const std = @import("std");
const assert = std.debug.assert;
const scrypt = std.crypto.pwhash.scrypt;
const constants = @import("constants.zig");
const base64 = std.crypto.codecs.base64;
const secureZero = std.crypto.secureZero;

const AgeError = @import("errors.zig").AgeError;
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Identity = @import("Identity.zig");
const Recipient = @import("Recipient.zig");
const Stanza = @import("Stanza.zig");

const SALT_SIZE = 16;
// const leftover = SALT_SIZE % 3;
// const encoded_salt_len = SALT_SIZE / 3 * 4 + (leftover * 4 + 2) / 3;
const ENCODED_SALT_SIZE = 22;
const SCRYPT_RECIPIENT_TAG = "scrypt";
const SCRYPT_SALT_LABEL = "age-encryption.org/v1/scrypt";
const FILE_KEY_LEN = constants.FILE_KEY_BYTES;
const MAX_USIZE = std.math.maxInt(usize);
const MAX_INT = MAX_USIZE >> 1;

pub const ScryptRecipient = struct {
    password: []const u8,
    log_n: u6 = 18, // TODO: configure work factor (log_n) based on work factor of 1s for the machine running our program, investigate potentially using std.crypto.scrypt.Params.fromLimits function
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1

    inline fn getMaxScryptAllocSize(ln: u6, r: u30, p: u30) usize {
        const n64 = @as(u64, 1) << ln;
        if (n64 > MAX_USIZE) return MAX_INT / 128 / @as(u64, r);
        const n = @as(usize, @intCast(n64));
        if (n > MAX_INT / 128 / @as(u64, r)) return MAX_INT / 128 / @as(u64, r);
        return (@sizeOf(u32) * (64 * r)) + (@sizeOf(u32) * (32 * n * r)) + (@sizeOf(u8) * (p * 128 * r));
    }

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

    inline fn getBufferSize(self: *const ScryptRecipient) usize {
        var buf: [10]u8 = undefined;
        const log_n_str = std.fmt.bufPrint(&buf, "{}", .{self.log_n}) catch unreachable;
        // return some padding so accessing log_n_str is 32 and 16 byte aligned
        return ENCODED_SALT_SIZE + (32 % ENCODED_SALT_SIZE) + log_n_str.len;
    }

    /// Call Stanza.deinit for each stanza in stanzas
    fn wrapFileKey(self: *ScryptRecipient, allocator: Allocator, file_key: []const u8) AgeError![]Stanza {
        assert(file_key.len > 0);
        var arena = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        const rng = std.crypto.random;
        var salt: [SALT_SIZE]u8 = undefined;
        rng.bytes(&salt);

        const inner_salt = SCRYPT_SALT_LABEL.* ++ salt[0..];
        // const inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ salt[0..];

        var key: [FILE_KEY_LEN]u8 = undefined;

        scrypt.kdf(allocator, &key, self.password, inner_salt, .{
            .ln = self.log_n,
            .r = owasp_r,
            .p = owasp_p,
        }) catch return AgeError.ScryptKeyGenerationFailed;

        var encrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
        var tag: [constants.ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key);

        var buffer = arena_allocator.alignedAlloc(u8, .@"16", self.getBufferSize()) catch return AgeError.OutOfMemory;
        const encoded_salt = base64.encode(buffer[0..ENCODED_SALT_SIZE], salt[0..], base64.Variant.standard_nopad) catch unreachable;
        // start log_n_str at 32 so accesses are 16 and 32 byte aligned
        const log_n_str = std.fmt.bufPrint(buffer[32..], "{}", .{self.log_n}) catch unreachable;

        var stanzas = try std.ArrayListAlignedUnmanaged(Stanza, .@"8").initCapacity(arena_allocator, 1);
        try stanzas.append(arena_allocator, .{
            .tag = SCRYPT_RECIPIENT_TAG,
            .args = .{ encoded_salt, log_n_str },
            .body = encrypted_file_key ++ tag,
            .arena = arena,
        });
        return stanzas.toOwnedSlice(arena_allocator);
    }

    fn wrapFileKeyWithLabels(self: *ScryptRecipient, allocator: Allocator, file_key: []const u8) AgeError!.{ []Stanza, [][]const u8 } {
        const stanzas = try self.wrapFileKey(allocator, file_key);

        const rng = std.crypto.random;
        var random: [16]u8 = undefined;
        rng.bytes(&random);

        var buf: [16]u8 = undefined;
        const random_label = try std.fmt.bufPrint(&buf, "{}", .{random});

        return .{ stanzas, &[_][]const u8{random_label[0..]} };
    }

    fn wrap(ctx: *anyopaque, allocator: Allocator, file_key: []const u8) AgeError![]Stanza {
        const self: *ScryptRecipient = @alignCast(@ptrCast(ctx));
        return self.wrapFileKey(allocator, file_key);
    }

    pub fn recipient(self: *ScryptRecipient) Recipient {
        return .{
            .ptr = self,
            .vtable = &.{
                .wrap = wrap,
            },
        };
    }
};

pub const ScryptIdentity = struct {
    password: []const u8,
    max_log_n: u6 = 18,
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1

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

    fn unwrapFileKey(self: *ScryptIdentity, allocator: Allocator, stanzas: []const Stanza) AgeError![FILE_KEY_LEN]u8 {
        assert(stanzas.len > 0);
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.tag, SCRYPT_RECIPIENT_TAG)) continue;

            assert(stanza.args.len == 2);
            if (stanza.body.len != constants.ChaCha20Poly1305.key_length + constants.ChaCha20Poly1305.tag_length) return AgeError.InvalidScryptRecipientBlock;

            const encoded_salt = stanza.args[0] orelse return AgeError.InvalidScryptRecipientBlock;
            const encoded_log_n = stanza.args[1] orelse return AgeError.InvalidScryptRecipientBlock;

            var inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ [_]u8{0} ** SALT_SIZE;
            const decoded_buf = inner_salt[SCRYPT_SALT_LABEL.len..]; // or call base64.decodedLen(stanza.args[0].len, base64.Variant.standard_nopad)
            const decoded_salt = base64.decode(decoded_buf, encoded_salt, base64.Variant.standard_nopad) catch return AgeError.InvalidScryptRecipientBlock;
            assert(decoded_salt.len == SALT_SIZE);

            const log_n = std.fmt.parseInt(u6, encoded_log_n, 10) catch return AgeError.InvalidScryptRecipientBlock;
            if (log_n < 0 or self.max_log_n < log_n) return AgeError.InvalidScryptRecipientBlock;

            // const inner_salt = SCRYPT_SALT_LABEL[0..SCRYPT_SALT_LABEL.len] ++ decoded_salt[0..];

            var key: [ChaCha20Poly1305.key_length]u8 = undefined;
            defer secureZero(u8, &key);

            scrypt.kdf(allocator, &key, self.password, &inner_salt, .{
                .ln = log_n,
                .r = owasp_r,
                .p = owasp_p,
            }) catch return AgeError.ScryptKeyGenerationFailed;

            var decrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
            ChaCha20Poly1305.decrypt(&decrypted_file_key, stanza.body[0..FILE_KEY_LEN], stanza.body[FILE_KEY_LEN .. FILE_KEY_LEN + ChaCha20Poly1305.tag_length].*, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key) catch return AgeError.FileKeyDecryptionFailed;

            return decrypted_file_key;
        }
        return AgeError.IncorrectIdentity;
    }

    fn unwrap(ctx: *anyopaque, allocator: Allocator, stanzas: []const Stanza) AgeError![FILE_KEY_LEN]u8 {
        const self: *ScryptIdentity = @alignCast(@ptrCast(ctx));
        return self.unwrapFileKey(allocator, stanzas);
    }

    pub fn identity(self: *ScryptIdentity) Identity {
        return .{
            .ptr = self,
            .vtable = &.{
                .unwrap = unwrap,
            },
        };
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
    var file_key: [FILE_KEY_LEN]u8 = undefined;
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
