const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const base64 = std.crypto.codecs.base64;
const bech32 = @import("internal/bech32.zig");

const AgeError = @import("errors.zig").AgeError;
const ArrayListAlignedUnmanaged = std.ArrayListAlignedUnmanaged;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Identity = @import("Identity.zig").Identity;
const Recipient = @import("Recipient.zig").Recipient;
const Stanza = @import("Stanza.zig").Stanza;
const X25519 = std.crypto.dh.X25519;

/// x25519 scalar length in bytes
pub const scalar_length = 32;
const hkdf_label = "age-encryption.org/v1/X25519";

pub const X25519Recipient = struct {
    their_public_key: [scalar_length]u8 = undefined,

    const label = "X25519";
    const bech32_public_hrp = "age";
    // hrp.len + 1 + calcExpansion(scalar_length) + 6
    const bech32_encoded_key_length = bech32_public_hrp.len + 1 + 52 + 6;
    // const leftover = SCALAR_SIZE % 3; // 2
    // const encoded_scalar_size = SCALAR_SIZE / 3 * 4 + (leftover * 4 + 2) / 3; // 43
    const base64_encoded_scalar_length = 43;

    pub fn initFromPoint(public_key: []const u8) AgeError!X25519Recipient {
        assert(public_key.len == scalar_length);
        var their_public_key: [scalar_length]u8 = undefined;
        @memcpy(&their_public_key, public_key);

        return .{
            .their_public_key = their_public_key,
        };
    }

    /// Returns a new X25519Recipient from a bech32 public key encoding with the "age1" prefix
    pub fn initFromBech32String(bech32_string: []const u8) AgeError!X25519Recipient {
        assert(bech32_string.len == bech32_encoded_key_length);
        var buf: [bech32.max_data_size]u8 = undefined;
        const decoded = bech32.standard.Decoder.decode(&buf, bech32_string) catch return AgeError.InvalidBech32String;
        if (!std.mem.eql(u8, decoded.hrp, bech32_public_hrp)) return AgeError.InvalidBech32String;
        if (decoded.data.len != scalar_length) return AgeError.InvalidBech32String;
        if (decoded.encoding != bech32.Encoding.bech32) return AgeError.InvalidBech32String;

        var public_key: [scalar_length]u8 = undefined;
        @memcpy(&public_key, decoded.data);

        return .{
            .their_public_key = public_key,
        };
    }

    /// Call Stanza.deinit for each stanza in []Stanza
    pub fn wrapFileKey(self: *X25519Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
        assert(file_key.len > 0);
        var arena = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        const rng = std.crypto.random;
        var ephemeral: [scalar_length]u8 = undefined;
        rng.bytes(&ephemeral);

        const our_public_key = X25519.scalarmult(ephemeral, X25519.Curve.basePoint.toBytes()) catch unreachable;
        const shared_secret = X25519.scalarmult(ephemeral, self.their_public_key) catch unreachable;

        const salt: [scalar_length * 2]u8 = our_public_key ++ self.their_public_key;
        const kdf = HkdfSha256;
        const prk = kdf.extract(&salt, &shared_secret);
        var wrapping_key: [ChaCha20Poly1305.key_length]u8 = undefined;
        defer crypto.secureZero(u8, &wrapping_key);
        kdf.expand(&wrapping_key, hkdf_label, prk);

        var encrypted_file_key: [Identity.file_key_length]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, wrapping_key);

        var buffer = arena_allocator.alignedAlloc(u8, .@"16", base64_encoded_scalar_length) catch return AgeError.OutOfMemory;
        const our_public_key_encoded = base64.encode(buffer[0..base64_encoded_scalar_length], &our_public_key, base64.Variant.standard_nopad) catch unreachable;
        assert(our_public_key_encoded.len == base64_encoded_scalar_length);

        var encoded_file_key: [Stanza.body_length]u8 = undefined;
        const ciphertext: [Identity.file_key_length + ChaCha20Poly1305.tag_length]u8 = encrypted_file_key ++ tag;
        const our_encrypted_file_key_encoded = base64.encode(&encoded_file_key, &ciphertext, base64.Variant.standard_nopad) catch unreachable;
        assert(our_encrypted_file_key_encoded.len == Stanza.body_length);

        var stanzas = try std.ArrayListAlignedUnmanaged(Stanza, .@"8").initCapacity(arena_allocator, 1);
        try stanzas.append(arena_allocator, .{
            .tag = label,
            .args = .{ our_public_key_encoded, null },
            .body = encoded_file_key,
            .arena = arena,
        });
        return stanzas.toOwnedSlice(arena_allocator);
    }

    /// Returns a bech32 public key encoding of the X25519Recipient with the "age1" prefix
    pub fn toBech32String(self: *const X25519Recipient) [bech32_encoded_key_length]u8 {
        const data = self.their_public_key;
        const enc = bech32.Encoding.bech32;
        var buf: [bech32.max_string_size]u8 = undefined;
        var encoded_stack: [bech32_encoded_key_length]u8 = undefined;
        const encoded = bech32.standard.Encoder.encode(&buf, bech32_public_hrp, &data, enc);
        assert(encoded.len == bech32_encoded_key_length);
        @memcpy(&encoded_stack, encoded);
        return encoded_stack;
    }
};

pub const X25519Identity = struct {
    secret_key: [scalar_length]u8 = undefined,
    our_public_key: [scalar_length]u8 = undefined,

    const bech32_private_hrp = "AGE-SECRET-KEY-";
    // hrp.len + 1 + calcExpansion(scalar_length) + 6
    const bech32_encoded_key_length = bech32_private_hrp.len + 1 + 52 + 6;
    // const BECH32_ENCODED_KEY_LENGTH = bech32_private_hrp.len + 1 + 52 + 6;
    const file_key_length = Identity.file_key_length;

    /// Returns a X25519Identity from a Curve25519 scalar
    pub fn initFromScalar(secret_key: []const u8) AgeError!X25519Identity {
        assert(secret_key.len == scalar_length);
        var our_secret_key: [scalar_length]u8 = undefined;
        @memcpy(&our_secret_key, secret_key);
        const our_public_key = try X25519.recoverPublicKey(our_secret_key);

        return .{
            .secret_key = our_secret_key,
            .our_public_key = our_public_key,
        };
    }

    /// Returns a new X25519Identity from a bech32 private key encoding
    /// with the "AGE-SECRET-KEY-1" prefix
    pub fn initFromBech32String(private_key: []const u8) AgeError!X25519Identity {
        assert(private_key.len == bech32_encoded_key_length);
        var buf: [bech32.max_data_size]u8 = undefined;
        const decoded = bech32.standard_uppercase.Decoder.decode(&buf, private_key) catch return AgeError.InvalidBech32String;
        if (!std.mem.eql(u8, decoded.hrp, bech32_private_hrp)) return AgeError.InvalidBech32String;
        if (decoded.data.len != scalar_length) return AgeError.InvalidBech32String;
        if (decoded.encoding != bech32.Encoding.bech32) return AgeError.InvalidBech32String;

        return initFromScalar(decoded.data);
    }

    /// Randomly generates a new X25519Identity
    pub fn generate() AgeError!X25519Identity {
        const rng = std.crypto.random;
        var secret_key: [scalar_length]u8 = undefined;

        while (true) {
            rng.bytes(&secret_key);
            return initFromScalar(&secret_key) catch {
                @branchHint(.unlikely);
                continue;
            };
        }
    }

    pub fn unwrapFileKey(self: *X25519Identity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![file_key_length]u8 {
        assert(stanzas.len > 0);
        _ = allocator;
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.tag, X25519Recipient.label)) continue;

            assert(stanza.args.len == 2);
            const encoded_public_key = stanza.args[0] orelse return AgeError.InvalidX25519RecipientBlock;
            assert(encoded_public_key.len == X25519Recipient.base64_encoded_scalar_length);
            assert(stanza.args[1] == null);

            if (stanza.body.len != Stanza.body_length) return AgeError.InvalidX25519RecipientBlock;
            var ciphertext: [file_key_length + ChaCha20Poly1305.tag_length]u8 = undefined;
            const decoded_ciphertext = base64.decode(&ciphertext, &stanza.body, base64.Variant.standard_nopad) catch return AgeError.InvalidX25519RecipientBlock;
            assert(decoded_ciphertext.len == file_key_length + ChaCha20Poly1305.tag_length);

            var their_public_key: [scalar_length]u8 = undefined;
            const decoded_public_key_slice = base64.decode(&their_public_key, encoded_public_key, base64.Variant.standard_nopad) catch return AgeError.InvalidX25519RecipientBlock;
            assert(decoded_public_key_slice.len == scalar_length);

            const shared_secret = X25519.scalarmult(self.secret_key, their_public_key) catch return AgeError.InvalidX25519RecipientBlock;

            const salt: [scalar_length * 2]u8 = their_public_key ++ self.our_public_key;
            const kdf = HkdfSha256;
            const prk = kdf.extract(&salt, &shared_secret);
            var wrapping_key: [ChaCha20Poly1305.key_length]u8 = undefined;
            defer crypto.secureZero(u8, &wrapping_key);
            kdf.expand(&wrapping_key, hkdf_label, prk);

            var decrypted_file_key: [file_key_length]u8 = undefined;
            defer crypto.secureZero(u8, &decrypted_file_key);
            ChaCha20Poly1305.decrypt(&decrypted_file_key, ciphertext[0..file_key_length], ciphertext[file_key_length..].*, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, wrapping_key) catch return AgeError.FileKeyDecryptionFailed;

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
    pub fn toBech32String(self: *const X25519Identity) [bech32_encoded_key_length]u8 {
        const data = self.secret_key;
        var buf: [bech32.max_string_size]u8 = undefined;
        var encoded_stack: [bech32_encoded_key_length]u8 = undefined;
        const encoded = bech32.standard_uppercase.Encoder.encode(&buf, bech32_private_hrp, &data, bech32.Encoding.bech32);
        assert(encoded.len == bech32_encoded_key_length);
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
    var file_key: [Identity.file_key_length]u8 = undefined;
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
    var file_key: [Identity.file_key_length]u8 = undefined;
    rng.bytes(&file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };

    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}

test "x25519 basic decryption" {
    const allocator = std.testing.allocator;

    // from github.com/C2SP/CCTV/blog/main/age/testdata/x25519
    const identity_str = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    const stanza_arg = "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc";
    const stanza_body = "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U";
    var xIdentity = try X25519Identity.initFromBech32String(identity_str);
    const identity = Identity.init(&xIdentity);

    // var xRecipient = xIdentity.recipient();
    // var recipient = Recipient.init(&xRecipient);
    const file_key = [_]u8{ 0x59, 0x45, 0x4c, 0x4c, 0x4f, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4d, 0x41, 0x52, 0x49, 0x4e, 0x45 };
    // const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    // defer for (stanzas) |stanza| {
    //     stanza.deinit();
    // };

    var stanza_body_arr: [Stanza.body_length]u8 = undefined;
    for (stanza_body, 0..) |byte, i| {
        stanza_body_arr[i] = byte;
    }

    const stanzas = [_]Stanza{
        Stanza{
            .tag = "X25519",
            .args = [_]?[]const u8{ stanza_arg, null },
            .body = stanza_body_arr,
            .arena = null,
        },
    };

    const decrypted_file_key = try identity.unwrapFileKey(allocator, &stanzas);
    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
