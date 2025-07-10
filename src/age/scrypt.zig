const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const scrypt = std.crypto.pwhash.scrypt;
const base64 = std.crypto.codecs.base64;

const AgeError = @import("errors.zig").AgeError;
const ArrayListAlignedUnmanaged = std.ArrayListAlignedUnmanaged;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Identity = @import("Identity.zig").Identity;
const Recipient = @import("Recipient.zig").Recipient;
const Stanza = @import("Stanza.zig").Stanza;

const salt_length = 16;
const salt_label = "age-encryption.org/v1/scrypt";

pub const ScryptRecipient = struct {
    password: []const u8,
    log_n: u6 = 18, // TODO: configure work factor (log_n) based on work factor of 1s for the machine running our program, investigate potentially using std.crypto.scrypt.Params.fromLimits function

    const label = "scrypt";
    // const leftover = salt_length % 3;
    // const encoded_salt_len = salt_length / 3 * 4 + (leftover * 4 + 2) / 3;
    const encoded_salt_length = 22;
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1

    pub fn init(password: []const u8) ScryptRecipient {
        assert(password.len > 0);
        return ScryptRecipient{
            .password = password,
        };
    }

    pub fn setWorkFactor(self: *ScryptRecipient, work_factor: u8) void {
        assert(0 < work_factor and work_factor < 64);
        self.log_n = @truncate(work_factor);
    }

    fn getBufferSize(self: *const ScryptRecipient) usize {
        var buf: [10]u8 = undefined;
        const log_n_str = std.fmt.bufPrint(&buf, "{}", .{self.log_n}) catch unreachable;
        // return some padding so accessing log_n_str is 32 and 16 byte aligned
        return encoded_salt_length + (32 % encoded_salt_length) + log_n_str.len;
    }

    /// Call Stanza.deinit for each stanza in []Stanza
    fn wrapFileKey(self: *ScryptRecipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
        assert(file_key.len == Identity.file_key_length);
        var arena = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        const rng = crypto.random;
        var salt: [salt_length]u8 = undefined;
        rng.bytes(&salt);

        const inner_salt = salt_label.* ++ salt[0..];
        // const inner_salt: [salt_label.len + salt_length]u8 = salt_label.* ++ salt[0..];

        var key: [ChaCha20Poly1305.key_length]u8 = undefined;

        scrypt.kdf(allocator, &key, self.password, inner_salt, .{
            .ln = self.log_n,
            .r = owasp_r,
            .p = owasp_p,
        }) catch return AgeError.ScryptKeyGenerationFailed;

        var encrypted_file_key: [Identity.file_key_length]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key);

        var buffer = arena_allocator.alignedAlloc(u8, .@"16", self.getBufferSize()) catch return AgeError.OutOfMemory;
        errdefer arena_allocator.free(buffer);
        const encoded_salt = base64.encode(buffer[0..encoded_salt_length], salt[0..], base64.Variant.standard_nopad) catch unreachable;
        // start log_n_str at 32 so accesses are 16 and 32 byte aligned
        const log_n_str = std.fmt.bufPrint(buffer[32..], "{}", .{self.log_n}) catch unreachable;

        var encoded_file_key: [Stanza.body_length]u8 = undefined;
        const ciphertext = encrypted_file_key ++ tag;
        const our_encrypted_file_key_encoded = base64.encode(&encoded_file_key, &ciphertext, base64.Variant.standard_nopad) catch unreachable;
        assert(our_encrypted_file_key_encoded.len == Stanza.body_length);

        var stanzas = try ArrayListAlignedUnmanaged(Stanza, .@"8").initCapacity(arena_allocator, 1);
        try stanzas.append(arena_allocator, .{
            .tag = label,
            .args = .{ encoded_salt, log_n_str },
            .body = encoded_file_key,
            .arena = arena,
        });
        return stanzas.toOwnedSlice(arena_allocator);
    }

    pub fn recipient(self: *ScryptRecipient) Recipient {
        return .{
            .ptr = self,
            .wrap = wrap,
        };
    }

    fn wrap(ctx: *anyopaque, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
        const r: *ScryptRecipient = @ptrCast(@alignCast(ctx));
        return r.wrapFileKey(allocator, file_key);
    }

    fn wrapFileKeyWithLabels(self: *ScryptRecipient, allocator: mem.Allocator, file_key: []const u8) AgeError!.{ []Stanza, [][]const u8 } {
        const stanzas = try self.wrapFileKey(allocator, file_key);

        const rng = crypto.random;
        var random: [16]u8 = undefined;
        rng.bytes(&random);

        var buf: [16]u8 = undefined;
        const random_label = try std.fmt.bufPrint(&buf, "{}", .{random});

        return .{ stanzas, &[_][]const u8{random_label[0..]} };
    }
};

pub const ScryptIdentity = struct {
    password: []const u8,
    max_log_n: u6 = 18,
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1
    const file_key_length = Identity.file_key_length;

    pub fn init(password: []const u8) ScryptIdentity {
        assert(password.len > 0);
        return ScryptIdentity{
            .password = password,
        };
    }

    pub fn setMaxWorkFactor(self: *ScryptIdentity, max_work_factor: u8) void {
        assert(0 < max_work_factor and max_work_factor < 64);
        self.max_log_n = @truncate(max_work_factor);
    }

    fn unwrapFileKey(self: *ScryptIdentity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![file_key_length]u8 {
        assert(stanzas.len > 0);
        for (stanzas) |stanza| {
            if (!mem.eql(u8, stanza.tag, ScryptRecipient.label)) continue;

            assert(stanza.args.len == 2);
            if (stanza.body.len != Stanza.body_length) return AgeError.InvalidScryptRecipientBlock;
            var ciphertext: [file_key_length + ChaCha20Poly1305.tag_length]u8 = undefined;
            const decoded_ciphertext = base64.decode(&ciphertext, &stanza.body, base64.Variant.standard_nopad) catch return AgeError.InvalidX25519RecipientBlock;
            assert(decoded_ciphertext.len == file_key_length + ChaCha20Poly1305.tag_length);

            const encoded_salt = stanza.args[0] orelse return AgeError.InvalidScryptRecipientBlock;
            const encoded_log_n = stanza.args[1] orelse return AgeError.InvalidScryptRecipientBlock;

            var inner_salt: [salt_label.len + salt_length]u8 = salt_label.* ++ [_]u8{0} ** salt_length;
            const decoded_buf = inner_salt[salt_label.len..]; // or call base64.decodedLen(stanza.args[0].len, base64.Variant.standard_nopad)
            const decoded_salt = base64.decode(decoded_buf, encoded_salt, base64.Variant.standard_nopad) catch return AgeError.InvalidScryptRecipientBlock;
            assert(decoded_salt.len == salt_length);

            const log_n = std.fmt.parseInt(u6, encoded_log_n, 10) catch return AgeError.InvalidScryptRecipientBlock;
            if (log_n < 0 or self.max_log_n < log_n) return AgeError.InvalidScryptRecipientBlock;

            // const inner_salt = salt_label[0..salt_label.len] ++ decoded_salt[0..];

            var key: [ChaCha20Poly1305.key_length]u8 = undefined;
            defer crypto.secureZero(u8, &key);

            scrypt.kdf(allocator, &key, self.password, &inner_salt, .{
                .ln = log_n,
                .r = owasp_r,
                .p = owasp_p,
            }) catch return AgeError.ScryptKeyGenerationFailed;

            var decrypted_file_key: [file_key_length]u8 = undefined;
            ChaCha20Poly1305.decrypt(&decrypted_file_key, ciphertext[0..file_key_length], ciphertext[file_key_length..].*, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key) catch return AgeError.FileKeyDecryptionFailed;

            return decrypted_file_key;
        }
        return AgeError.IncorrectIdentity;
    }

    pub fn identity(self: *ScryptIdentity) Identity {
        return .{
            .ptr = self,
            .unwrap = unwrap,
        };
    }

    fn unwrap(ctx: *anyopaque, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![file_key_length]u8 {
        const i: *ScryptIdentity = @ptrCast(@alignCast(ctx));
        return i.unwrapFileKey(allocator, stanzas);
    }
};

test "scrypt round trip og" {
    const password = "twitch.tv/filosottile";
    const allocator = std.testing.allocator;
    // var arena = std.heap.ArenaAllocator.init(test_allocator);
    // defer arena.deinit();

    // const allocator = arena.allocator();

    var identity = ScryptIdentity.init(password);
    var recipient = ScryptRecipient.init(password);
    recipient.setWorkFactor(15);

    const rng = std.crypto.random;
    var file_key: [Identity.file_key_length]u8 = undefined;
    rng.bytes(&file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    // irrelevant because now I'm taking advantage of arena allocators! :D
    // defer allocator.free(stanzas);
    // TODO switch to this form, much nicer looking
    // but stanza is a const for some reason so i can't call deinit
    // so gotta figure out how to for each without producing constants
    // okay it was just because I was expecting a pointer at all in my Stanza deinit definition
    // instead of defining self as *Stanza I changed it to just Stanza and this now works
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };
    // old
    // TODO add to zig learning devlog
    // defer for (0..stanzas.len) |i| {
    //     stanzas[i].deinit(allocator);
    // };
    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}

test "scrypt round trip interfaces" {
    const password = "twitch.tv/filosottile";
    const allocator = std.testing.allocator;

    var scrypt_identity = ScryptIdentity.init(password);
    var scrypt_recipient = ScryptRecipient.init(password);
    scrypt_recipient.setWorkFactor(15);

    var identity = scrypt_identity.identity();
    var recipient = scrypt_recipient.recipient();

    //var identity = scrypt_identity.identity();
    //var recipient = scrypt_recipient.recipient();

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

test "scrypt basic unwrap" {
    const allocator = std.testing.allocator;

    // from https://github.com/C2SP/CCTV/blob/main/age/testdata/scrypt
    const password = "password";
    const stanza_arg_0 = "rF0/NwblUHHTpgQgRpe5CQ";
    const stanza_arg_1 = "10";
    const stanza_body = "gUjEymFKMVXQEKdMMHL24oYexjE3TIC0O0zGSqJ2aUY";

    var sIdentity = ScryptIdentity.init(password);
    const identity = sIdentity.identity();

    const file_key = [_]u8{ 0x59, 0x45, 0x4c, 0x4c, 0x4f, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4d, 0x41, 0x52, 0x49, 0x4e, 0x45 };

    const stanzas = [_]Stanza{
        Stanza{
            .tag = ScryptRecipient.label,
            .args = [_]?[]const u8{ stanza_arg_0, stanza_arg_1 },
            .body = stanza_body.*,
            .arena = null,
        },
    };

    const decrypted_file_key = try identity.unwrapFileKey(allocator, &stanzas);
    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
