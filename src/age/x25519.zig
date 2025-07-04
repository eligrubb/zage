const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const secureZero = std.crypto.secureZero;
const base64 = std.crypto.codecs.base64;

const AgeError = @import("errors.zig").AgeError;
const Allocator = std.mem.Allocator;
const ArrayListAlignedUnmanaged = std.ArrayListAlignedUnmanaged;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Curve25519 = std.crypto.ecc.Curve25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Identity = @import("Identity.zig");
const Recipient = @import("Recipient.zig");
const Stanza = @import("Stanza.zig");

const FILE_KEY_LEN = constants.FILE_KEY_BYTES;
const X25519_SCALAR_SIZE = constants.X25519_SCALAR_BYTES;
const X25519_LABEL = "age-encryption.org/v1/X25519";
const X25519_RECIPIENT_TAG = "X25519";
const CHACHA20POLY1305_KEY_SIZE = constants.ChaCha20Poly1305.key_length;
// const leftover = SCALAR_SIZE % 3; // 2
// const encoded_scalar_size = SCALAR_SIZE / 3 * 4 + (leftover * 4 + 2) / 3; // 43
const ENCODED_SCALAR_SIZE = 43;

pub const X25519Recipient = struct {
    their_public_key: [X25519_SCALAR_SIZE]u8 = undefined,

    pub fn initFromPoint(public_key: []u8) AgeError!X25519Recipient {
        assert(public_key.len == X25519_SCALAR_SIZE);

        return .{
            .their_public_key = .public_key,
        };
    }

    /// Call Stanza.deinit for each stanza in stanzas
    fn wrapFileKey(self: *X25519Recipient, allocator: Allocator, file_key: []const u8) AgeError![]Stanza {
        assert(file_key.len > 0);
        var arena = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        const rng = std.crypto.random;
        var ephemeral: [X25519_SCALAR_SIZE]u8 = undefined;
        rng.bytes(&ephemeral);

        const our_public_key = Curve25519.mul(Curve25519.basePoint, ephemeral) catch unreachable;
        const shared_secret = Curve25519.mul(Curve25519.fromBytes(self.their_public_key), ephemeral) catch unreachable;

        const salt: [X25519_SCALAR_SIZE * 2]u8 = our_public_key ++ self.their_public_key;
        const kdf = HkdfSha256;
        const prk = kdf.extract(&salt, &shared_secret);
        var wrapping_key: [CHACHA20POLY1305_KEY_SIZE]u8 = undefined;
        defer secureZero(wrapping_key);
        kdf.expand(&wrapping_key, &X25519_LABEL, prk);

        var encrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
        var tag: [constants.ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, wrapping_key);

        var buffer = arena_allocator.alignedAlloc(u8, .@"16", ENCODED_SCALAR_SIZE) catch return AgeError.OutOfMemory;
        const our_public_key_encoded = base64.encode(buffer[0..ENCODED_SCALAR_SIZE], our_public_key.toBytes(), base64.Variant.standard_nopad) catch unreachable;

        var stanzas = try std.ArrayListAlignedUnmanaged(Stanza, .@"8").initCapacity(arena_allocator, 1);
        try stanzas.append(arena_allocator, .{
            .tag = X25519_RECIPIENT_TAG,
            .args = .{our_public_key_encoded},
            .body = encrypted_file_key ++ tag,
            .arena = arena,
        });
        return stanzas.toOwnedSlice(arena_allocator);
    }

    fn wrap(ctx: *anyopaque, allocator: Allocator, file_key: []const u8) AgeError![]Stanza {
        const self: *X25519Recipient = @alignCast(@ptrCast(ctx));
        return self.wrapFileKey(allocator, file_key);
    }

    pub fn recipient(self: *X25519Recipient) Recipient {
        return .{
            .ptr = self,
            .vtable = &.{
                .wrap = wrap,
            },
        };
    }
};

pub const X25519Identity = struct {
    secret_key: [X25519_SCALAR_SIZE]u8 = undefined,
    our_public_key: [X25519_SCALAR_SIZE]u8 = undefined,

    /// Returns a X25519Identity from a Curve25519 scalar
    pub fn initFromScalar(secret_key: []u8) AgeError!X25519Identity {
        assert(secret_key.len == X25519_SCALAR_SIZE);

        return .{
            .secret_key = secret_key,
            .our_public_key = Curve25519.mul(Curve25519.basePoint, secret_key).toBytes(),
        };
    }

    /// Randomly generates a new X25519Identity
    pub fn generate() AgeError!X25519Identity {
        const rng = std.crypto.random;
        var secret_key: [X25519_SCALAR_SIZE]u8 = undefined;
        rng.bytes(&secret_key);

        return initFromScalar(&secret_key);
    }

    pub fn x25519Recipient(self: *X25519Identity) X25519Recipient {
        return .{
            .their_public_key = self.our_public_key,
        };
    }

    pub fn recipient(self: *X25519Identity) Recipient {
        return self.x25519Recipient().recipient();
    }
};

test "x25519 round trip og" {
    const allocator = std.testing.allocator;

    var identity = try X25519Identity.generate();
    var recipient = identity.recipient();

    const r2 = try X25519Recipient.parseX25519Recipient(recipient.toString());
    try std.testing.expectEqualSlices(u8, recipient.toString(), r2.toString());

    const i2 = try X25519Identity.parseX25519Identity(identity.toString());
    try std.testing.expectEqualSlices(u8, identity.toString(), i2.toString());

    const rng = std.crypto.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };

    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}

test "x25519 round trip interfaces" {
    const allocator = std.testing.allocator;

    var x25519_identity = try X25519Identity.generate();

    var identity = x25519_identity.identity();
    var recipient = x25519_identity.recipient();

    const rng = std.crypto.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };

    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
