const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const print = std.debug.print;

const AgeError = @import("errors.zig").AgeError;
const Stanza = @import("Stanza.zig");

const primitives = @import("primitives.zig");
const constants = @import("constants.zig");
const scrypt = primitives.scrypt;
const ChaCha20Poly1305 = primitives.ChaCha20Poly1305;
const base64 = primitives.base64;

const SALT_SIZE = 16;
const SCRYPT_RECIPIENT_TAG = "scrypt";
const SCRYPT_SALT_LABEL = "age-encryption.org/v1/scrypt";
const FILE_KEY_LEN = constants.FILE_KEY_BYTES;
const MAX_LOG_N: u8 = 63;
const MAX_USIZE = std.math.maxInt(usize);
const MAX_INT = MAX_USIZE >> 1;

pub const ScryptRecipient = struct {
    password: []const u8,
    allocator: Allocator,
    log_n: u6 = 18, // TODO: configure work factor (log_n) based on work factor of 1s for the machine running our program, investigate potentially using std.crypto.scrypt.Params.fromLimits function
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1

    inline fn getMaxBufferSize(ln: u6, r: u30, p: u30) usize {
        const n64 = @as(u64, 1) << ln;
        if (n64 > MAX_USIZE) return MAX_INT / 128 / @as(u64, r);
        const n = @as(usize, @intCast(n64));
        if (n > MAX_INT / 128 / @as(u64, r)) return MAX_INT / 128 / @as(u64, r);
        return (@sizeOf(u32) * (64 * r)) + (@sizeOf(u32) * (32 * n * r)) + (@sizeOf(u8) * (p * 128 * r));
    }

    pub fn init(allocator: Allocator, password: []const u8) ScryptRecipient {
        assert(password.len > 0);
        return ScryptRecipient{
            .password = password,
            .allocator = allocator,
        };
    }

    pub fn setWorkFactor(self: *ScryptRecipient, work_factor: u8) void {
        assert(0 < work_factor and work_factor < 64);
        self.log_n = @truncate(work_factor);
    }

    pub fn wrapFileKey(self: *const ScryptRecipient, file_key: []const u8) AgeError![1]Stanza {
        assert(file_key.len > 0);

        const rng = primitives.random;
        var salt: [SALT_SIZE]u8 = undefined;
        rng.bytes(&salt);

        const inner_salt = SCRYPT_SALT_LABEL.* ++ salt[0..];
        // const inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ salt[0..];

        var key: [FILE_KEY_LEN]u8 = undefined;

        scrypt.kdf(self.allocator, &key, self.password, inner_salt, .{
            .ln = self.log_n,
            .r = owasp_r,
            .p = owasp_p,
        }) catch return AgeError.ScryptKeyGenerationFailed;

        var encrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;

        print("encrypting file key {any}\n", .{file_key});
        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key);
        print("encrypted file key {any}\n", .{encrypted_file_key});
        print("tag {any}\n", .{tag});

        const leftover = SALT_SIZE % 3;
        const encoded_salt_len = SALT_SIZE / 3 * 4 + (leftover * 4 + 2) / 3;
        assert(encoded_salt_len == 22);
        var buf = self.allocator.alignedAlloc(u8, .@"32", 64) catch return AgeError.OutOfMemory;
        print("encoding salt {any}\n", .{inner_salt});
        const encoded_salt = base64.encode(buf[0..encoded_salt_len], salt[0..], base64.Variant.standard_nopad) catch unreachable;
        print("encoded salt {any}\n", .{encoded_salt});

        const log_n_str = std.fmt.bufPrint(buf[32..], "{}", .{self.log_n}) catch unreachable;

        const stanza = Stanza{
            .tag = SCRYPT_RECIPIENT_TAG,
            .args = .{ encoded_salt, log_n_str },
            .body = encrypted_file_key ++ tag,
            .buf = buf,
        };
        print("stanza {any}\n", .{stanza});

        return [_]Stanza{stanza};
    }

    pub fn wrapFileKeyWithLabels(self: *ScryptRecipient, file_key: []u8) AgeError!.{ []Stanza, [][]const u8 } {
        const stanzas = try self.wrapFileKey(file_key);

        const rng = primitives.random;
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
    allocator: Allocator,
    const owasp_r: u30 = 8; // scrypt.Params.owasp.r, // 8
    const owasp_p: u30 = 1; // scrypt.Params.owasp.p, // 1

    pub fn init(allocator: Allocator, password: []const u8) ScryptIdentity {
        assert(password.len > 0);
        return ScryptIdentity{
            .password = password,
            .allocator = allocator,
        };
    }

    pub fn setMaxWorkFactor(self: *ScryptIdentity, max_work_factor: u8) void {
        assert(0 < max_work_factor and max_work_factor < 64);
        self.max_log_n = @truncate(max_work_factor);
    }

    pub fn unwrapFileKey(self: *const ScryptIdentity, stanzas: []const Stanza) AgeError![FILE_KEY_LEN]u8 {
        assert(stanzas.len > 0);
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.tag, SCRYPT_RECIPIENT_TAG)) continue;
            if (stanza.args.len != 2) return AgeError.InvalidScryptRecipientBlock;
            if (stanza.body.len != constants.ChaCha20Poly1305.key_length + constants.ChaCha20Poly1305.tag_length) return AgeError.InvalidScryptRecipientBlock;

            var inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ [_]u8{0} ** SALT_SIZE;
            const decoded_buf = inner_salt[SCRYPT_SALT_LABEL.len..]; // or call base64.decodedLen(stanza.args[0].len, base64.Variant.standard_nopad)
            print("encoded salt {any}\n", .{stanza.args[0]});
            _ = base64.decode(decoded_buf, stanza.args[0], base64.Variant.standard_nopad) catch return AgeError.InvalidScryptRecipientBlock;
            print("decoded salt {any}\n", .{decoded_buf});

            if (decoded_buf.len != SALT_SIZE) return AgeError.InvalidScryptRecipientBlock;
            const log_n = std.fmt.parseInt(u6, stanza.args[1], 10) catch return AgeError.InvalidScryptRecipientBlock;
            if (log_n < 0 or self.max_log_n < log_n) return AgeError.InvalidScryptRecipientBlock;

            // const inner_salt = SCRYPT_SALT_LABEL[0..SCRYPT_SALT_LABEL.len] ++ decoded_salt[0..];

            var key: [ChaCha20Poly1305.key_length]u8 = undefined;
            defer primitives.secureZero(u8, &key);

            scrypt.kdf(self.allocator, &key, self.password, &inner_salt, .{
                .ln = log_n,
                .r = owasp_r,
                .p = owasp_p,
            }) catch return AgeError.ScryptKeyGenerationFailed;

            var decrypted_file_key: [FILE_KEY_LEN]u8 = undefined;
            ChaCha20Poly1305.decrypt(&decrypted_file_key, stanza.body[0..FILE_KEY_LEN], stanza.body[FILE_KEY_LEN .. FILE_KEY_LEN + SALT_SIZE].*, &[_]u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key) catch return AgeError.FileKeyDecryptionFailed;

            return decrypted_file_key;
        }
        return AgeError.IncorrectIdentity;
    }
};

test "scrypt round trip og" {
    const password = "twitch.tv/filosottile";
    const allocator = std.testing.allocator;

    const identity = ScryptIdentity.init(allocator, password);
    var recipient = ScryptRecipient.init(allocator, password);
    recipient.setWorkFactor(15);

    const rng = primitives.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(&file_key);

    var stanzas = try recipient.wrapFileKey(&file_key);
    for (stanzas) |stanza| {
        print("stanza {any}\n", .{stanza});
        // defer allocator.free(stanza.buf);
    }
    var decrypted_file_key = try identity.unwrapFileKey(&stanzas);
    for (stanzas) |stanza| {
        allocator.free(stanza.buf);
    }

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
