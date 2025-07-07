const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const secureZero = std.crypto.secureZero;
const base64 = std.crypto.codecs.base64;
const bech32 = @import("internal/bech32.zig");

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
const BASE64_ENCODED_SCALAR_SIZE = 43;
const BECH32_PUBLIC_KEY_HRP_TAG = "age";
const BECH32_PRIVATE_KEY_HRP_TAG = "AGE-SECRET-KEY-";
// hrp.len + 1 + calcExpansion(X25519_SCALAR_SIZE) + 6
const BECH32_ENCODED_PUBLIC_KEY_SIZE = BECH32_PUBLIC_KEY_HRP_TAG.len + 1 + 52 + 6;
const BECH32_ENCODED_PRIVATE_KEY_SIZE = BECH32_PRIVATE_KEY_HRP_TAG.len + 1 + 52 + 6;

pub const X25519Recipient = struct {
    their_public_key: [X25519_SCALAR_SIZE]u8 = undefined,

    pub fn initFromPoint(public_key: []const u8) AgeError!X25519Recipient {
        assert(public_key.len == X25519_SCALAR_SIZE);
        var their_public_key: [X25519_SCALAR_SIZE]u8 = undefined;
        @memcpy(&their_public_key, public_key);

        return .{
            .their_public_key = their_public_key,
        };
    }

    /// Returns a new X25519Recipient from a bech32 public key encoding with the "age1" prefix
    pub fn initFromBech32String(bech32_string: []const u8) AgeError!X25519Recipient {
        assert(bech32_string.len == BECH32_ENCODED_PUBLIC_KEY_SIZE);
        var buf: [bech32.max_data_size]u8 = undefined;
        const decoded = bech32.standard.Decoder.decode(&buf, bech32_string) catch return AgeError.InvalidBech32String;
        if (!std.mem.eql(u8, decoded.hrp, BECH32_PUBLIC_KEY_HRP_TAG)) return AgeError.InvalidBech32String;
        if (decoded.data.len != X25519_SCALAR_SIZE) return AgeError.InvalidBech32String;
        if (decoded.encoding != bech32.Encoding.bech32) return AgeError.InvalidBech32String;

        var public_key: [X25519_SCALAR_SIZE]u8 = undefined;
        @memcpy(&public_key, decoded.data);

        return .{
            .their_public_key = public_key,
        };
    }

    /// Call Stanza.deinit for each stanza in []Stanza
    pub fn wrapFileKey(self: *X25519Recipient, allocator: Allocator, file_key: []const u8) AgeError![]Stanza {
        assert(file_key.len > 0);
        var arena = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        const rng = std.crypto.random;
        var ephemeral: [X25519_SCALAR_SIZE]u8 = undefined;
        rng.bytes(&ephemeral);

        const our_public_key = Curve25519.mul(Curve25519.basePoint, ephemeral) catch unreachable;
        const shared_secret = Curve25519.mul(Curve25519.fromBytes(self.their_public_key), ephemeral) catch unreachable;

        const salt: [X25519_SCALAR_SIZE * 2]u8 = our_public_key.toBytes() ++ self.their_public_key;
        const kdf = HkdfSha256;
        const prk = kdf.extract(&salt, &shared_secret.toBytes());
        var wrapping_key: [CHACHA20POLY1305_KEY_SIZE]u8 = undefined;
        defer secureZero(u8, &wrapping_key);
        kdf.expand(&wrapping_key, X25519_LABEL, prk);

        var encrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
        var tag: [constants.ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, wrapping_key);

        var buffer = arena_allocator.alignedAlloc(u8, .@"16", BASE64_ENCODED_SCALAR_SIZE) catch return AgeError.OutOfMemory;
        const our_public_key_encoded = base64.encode(buffer[0..BASE64_ENCODED_SCALAR_SIZE], &our_public_key.toBytes(), base64.Variant.standard_nopad) catch unreachable;

        var stanzas = try std.ArrayListAlignedUnmanaged(Stanza, .@"8").initCapacity(arena_allocator, 1);
        try stanzas.append(arena_allocator, .{
            .tag = X25519_RECIPIENT_TAG,
            .args = .{ our_public_key_encoded, null },
            .body = encrypted_file_key ++ tag,
            .arena = arena,
        });
        return stanzas.toOwnedSlice(arena_allocator);
    }

    /// Returns a bech32 public key encoding of the X25519Recipient with the "age1" prefix
    pub fn toBech32String(self: *const X25519Recipient) [BECH32_ENCODED_PUBLIC_KEY_SIZE]u8 {
        const data = self.their_public_key;
        const enc = bech32.Encoding.bech32;
        var buf: [bech32.max_string_size]u8 = undefined;
        var encoded_stack: [BECH32_ENCODED_PUBLIC_KEY_SIZE]u8 = undefined;
        const encoded = bech32.standard.Encoder.encode(&buf, BECH32_PUBLIC_KEY_HRP_TAG, &data, enc);
        assert(encoded.len == BECH32_ENCODED_PUBLIC_KEY_SIZE);
        @memcpy(&encoded_stack, encoded);
        return encoded_stack;
    }
};

pub const X25519Identity = struct {
    secret_key: [X25519_SCALAR_SIZE]u8 = undefined,
    our_public_key: [X25519_SCALAR_SIZE]u8 = undefined,

    /// Returns a X25519Identity from a Curve25519 scalar
    pub fn initFromScalar(secret_key: []const u8) AgeError!X25519Identity {
        assert(secret_key.len == X25519_SCALAR_SIZE);
        var our_secret_key: [X25519_SCALAR_SIZE]u8 = undefined;
        @memcpy(&our_secret_key, secret_key);

        const our_public_key = Curve25519.mul(Curve25519.basePoint, our_secret_key) catch return AgeError.IncorrectKeyLength;

        return .{
            .secret_key = our_secret_key,
            .our_public_key = our_public_key.toBytes(),
        };
    }

    /// Returns a new X25519Identity from a bech32 private key encoding
    /// with the "AGE-SECRET-KEY-1" prefix
    pub fn initFromBech32String(private_key: []const u8) AgeError!X25519Identity {
        assert(private_key.len == BECH32_ENCODED_PRIVATE_KEY_SIZE);
        var buf: [bech32.max_data_size]u8 = undefined;
        const decoded = bech32.standard_uppercase.Decoder.decode(&buf, private_key) catch return AgeError.InvalidBech32String;
        if (!std.mem.eql(u8, decoded.hrp, BECH32_PRIVATE_KEY_HRP_TAG)) return AgeError.InvalidBech32String;
        if (decoded.data.len != X25519_SCALAR_SIZE) return AgeError.InvalidBech32String;
        if (decoded.encoding != bech32.Encoding.bech32) return AgeError.InvalidBech32String;

        return initFromScalar(decoded.data);
    }

    /// Randomly generates a new X25519Identity
    pub fn generate() AgeError!X25519Identity {
        const rng = std.crypto.random;
        var secret_key: [X25519_SCALAR_SIZE]u8 = undefined;
        rng.bytes(&secret_key);

        return initFromScalar(&secret_key);
    }

    pub fn unwrapFileKey(self: *X25519Identity, allocator: Allocator, stanzas: []const Stanza) AgeError![FILE_KEY_LEN]u8 {
        assert(stanzas.len > 0);
        _ = allocator;
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.tag, X25519_RECIPIENT_TAG)) continue;

            assert(stanza.args.len == 2);
            if (stanza.body.len != ChaCha20Poly1305.key_length + ChaCha20Poly1305.tag_length) return AgeError.InvalidX25519RecpientBlock;

            const encoded_public_key = stanza.args[0] orelse return AgeError.InvalidX25519RecpientBlock;
            assert(stanza.args[1] == null);

            var their_public_key: [X25519_SCALAR_SIZE]u8 = undefined;
            const decoded_public_key_slice = base64.decode(&their_public_key, encoded_public_key, base64.Variant.standard_nopad) catch return AgeError.InvalidX25519RecpientBlock;
            assert(decoded_public_key_slice.len == X25519_SCALAR_SIZE);

            const shared_secret_point = Curve25519.mul(Curve25519.fromBytes(their_public_key), self.secret_key) catch return AgeError.InvalidX25519RecpientBlock;
            const shared_secret = shared_secret_point.toBytes();

            const salt: [X25519_SCALAR_SIZE * 2]u8 = their_public_key ++ self.our_public_key;
            const kdf = HkdfSha256;
            const prk = kdf.extract(&salt, &shared_secret);
            var wrapping_key: [CHACHA20POLY1305_KEY_SIZE]u8 = undefined;
            defer secureZero(u8, &wrapping_key);
            kdf.expand(&wrapping_key, X25519_LABEL, prk);

            var decrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
            defer secureZero(u8, &decrypted_file_key);
            ChaCha20Poly1305.decrypt(&decrypted_file_key, stanza.body[0..FILE_KEY_LEN], stanza.body[FILE_KEY_LEN..].*, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, wrapping_key) catch return AgeError.FileKeyDecryptionFailed;

            return decrypted_file_key;
        }
        return AgeError.IncorrectIdentity;
    }

    pub fn recipient(self: *X25519Identity) X25519Recipient {
        return .{
            .their_public_key = self.our_public_key,
        };
    }

    /// Returns the bech32 private key encoding of this identity
    pub fn toBech32String(self: *const X25519Identity) [BECH32_ENCODED_PRIVATE_KEY_SIZE]u8 {
        const data = self.secret_key;
        const enc = bech32.Encoding.bech32;
        var buf: [bech32.max_string_size]u8 = undefined;
        var encoded_stack: [BECH32_ENCODED_PRIVATE_KEY_SIZE]u8 = undefined;
        const encoded = bech32.standard_uppercase.Encoder.encode(&buf, BECH32_PRIVATE_KEY_HRP_TAG, &data, enc);
        assert(encoded.len == BECH32_ENCODED_PRIVATE_KEY_SIZE);
        @memcpy(&encoded_stack, encoded);
        return encoded_stack;
    }
};

test "x25519 round trip og" {
    const allocator = std.testing.allocator;

    var identity = try X25519Identity.generate();
    var recipient = identity.recipient();

    const recipient2 = try X25519Recipient.initFromBech32String(&recipient.toBech32String());
    try std.testing.expectEqualSlices(u8, &recipient.toBech32String(), &recipient2.toBech32String());

    const identity2 = try X25519Identity.initFromBech32String(&identity.toBech32String());
    try std.testing.expectEqualSlices(u8, &identity.toBech32String(), &identity2.toBech32String());

    const rng = std.crypto.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(&file_key);

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
    var x25519_recipient = x25519_identity.recipient();

    var identity = Identity.init(&x25519_identity);
    var recipient = Recipient.init(&x25519_recipient);

    const rng = std.crypto.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(&file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };

    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
