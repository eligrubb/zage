const std = @import("std");
const assert = std.debug.assert;

const age = @import("../age.zig");
const Error = age.Error;
const Stanza = age.Stanza;

const primitives = @import("primitives.zig");
const scrypt = primitives.scrypt;
const ChaCha20Poly1305 = primitives.ChaCha20Poly1305;
const base64 = primitives.base64;

const SALT_SIZE = 16;
const SCRYPT_RECIPIENT_TAG = "scrypt";
const SCRYPT_SALT_LABEL = "age-encryption.org/v1/scrypt";
const FILE_KEY_LEN = age.FILE_KEY_LEN;

const ScryptRecipient = struct {
    password: []u8,
    log_n: u6 = 18, // TODO: configure work factor (log_n) based on work factor of 1s for the machine running our program
    r: u30 = scrypt.Params.owasp.r, // 8
    p: u30 = scrypt.Params.owasp.p, // 1

    inline fn getBufferSize(self: *ScryptRecipient) usize {
        return (@sizeOf(u32) * (64 * self.r)) + (@sizeOf(u32) * (32 * @as(usize, @intCast(@as(u64, 1) << self.log_n)) * self.r)) + (@sizeOf(u8) * (self.p * 128 * self.r));
    }

    pub fn init(password: []const u8) ScryptRecipient {
        assert(password.len > 0);
        return ScryptRecipient{
            .password = password,
        };
    }

    pub fn setWorkFactor(self: *ScryptRecipient, work_factor: u8) void {
        assert(0 < work_factor and work_factor < 64);
        self.log_n = @as(u6, work_factor);
    }

    pub fn wrapFileKey(self: *ScryptRecipient, file_key: []u8) ![]Stanza {
        assert(file_key.len > 0);

        const rng = primitives.random;
        var salt: [SALT_SIZE]u8 = undefined;
        rng.bytes(&salt);

        const inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ salt[0..];

        const key: [FILE_KEY_LEN]u8 = undefined;
        var buffer: [self.getBufferSize()]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);
        const allocator = fba.allocator();

        try scrypt.kdf(allocator, &key, self.password, inner_salt, .{
            .ln = self.log_n,
            .r = self.r,
            .p = self.p,
        });

        var encrypted_file_key: [file_key.len]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;

        ChaCha20Poly1305.encrypt(&encrypted_file_key, &tag, file_key, []u8{}, [_]u8{0} ** ChaCha20Poly1305.nonce_length, key);

        const leftover = SALT_SIZE % 3;
        const encoded_salt_len = SALT_SIZE / 3 * 4 + (leftover * 4 + 2) / 3;
        var encoded_buf: [encoded_salt_len]u8 = undefined; // or call base64.encodedLen(SALT_SIZE, base64.Variant.standard_nopad)
        const encoded_salt = try base64.encode(&encoded_buf, salt[0..], base64.Variant.standard_nopad);

        var buf: [10]u8 = undefined;
        const log_n_str = try std.fmt.bufPrint(&buf, "{}", .{self.log_n});

        return Stanza{
            .tag = SCRYPT_RECIPIENT_TAG,
            .args = [_][]const u8{
                encoded_salt,
                log_n_str,
            },
            .body = encrypted_file_key ++ tag,
        };
    }

    pub fn wrapFileKeyWithLabels(self: *ScryptRecipient, file_key: []u8) !.{ []Stanza, [][]const u8 } {
        const stanzas = try self.wrapFileKey(file_key);

        const rng = primitives.random;
        var random: [16]u8 = undefined;
        rng.bytes(&random);

        var buf: [16]u8 = undefined;
        const random_label = try std.fmt.bufPrint(&buf, "{}", .{random});

        return .{ stanzas, &[_][]const u8{random_label[0..]} };
    }
};

const ScryptIdentity = struct {
    password: []u8,
    max_log_n: u6 = 18,
    r: u30 = scrypt.Params.owasp.r, // 8
    p: u30 = scrypt.Params.owasp.p, // 1

    pub fn init(password: []const u8) ScryptIdentity {
        assert(password.len > 0);
        return ScryptIdentity{
            .password = password,
        };
    }

    pub fn setMaxWorkFactor(self: *ScryptIdentity, max_work_factor: u8) void {
        assert(0 < max_work_factor and max_work_factor < 64);
        self.max_log_n = @as(u6, max_work_factor);
    }

    pub fn unwrapFileKey(self: *ScryptIdentity, stanzas: []Stanza) ![]u8 {
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.tag, SCRYPT_RECIPIENT_TAG)) return Error.IncorrectIdentity;
            if (stanza.args.len != 2 or stanza.body.len != ChaCha20Poly1305.key_length) return Error.InvalidScryptRecipientBlock;

            var result = SALT_SIZE / 4 * 3;
            const leftover = SALT_SIZE % 4;
            if (leftover % 4 == 1) return Error.InvalidPadding;
            result += leftover * 3 / 4;
            var decoded_buf: [result]u8 = undefined; // or call base64.decodedLen(stanza.args[0].len, base64.Variant.standard_nopad)
            const decoded_salt = try base64.decode(&decoded_buf, stanza.args[0], base64.Variant.standard_nopad);

            if (decoded_salt.len != SALT_SIZE) return Error.InvalidScryptRecipientBlock;
            const log_n = try std.fmt.parseInt(u8, stanza.args[1], 10);
            if (log_n < 0 or self.max_log_n < log_n) return Error.InvalidScryptRecipientBlock;

            const inner_salt: [SCRYPT_SALT_LABEL.len + SALT_SIZE]u8 = SCRYPT_SALT_LABEL.* ++ decoded_salt[0..];

            const key: [ChaCha20Poly1305.key_length]u8 = undefined;
            var buffer: [self.getBufferSize()]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buffer);
            const allocator = fba.allocator();

            try scrypt.kdf(allocator, &key, self.password, inner_salt, .{
                .ln = log_n,
                .r = self.r,
                .p = self.p,
            });
        }
    }
};
