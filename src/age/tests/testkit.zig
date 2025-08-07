const std = @import("std");
const Sha256 = std.crypto.sha2.Sha256;

const ExpectType = enum {
    Success,
    NoMatch,
    HMACFailure,
    HeaderFailure,
    PayloadFailure,
    ArmorFailure,
};

const TestFile = struct {
    expect: ExpectType,
    compressed: bool = false,
    payload: [Sha256.digest_length]u8,
    file_key: [16]u8,
    identity: ?[]u8,
    passphrase: ?[]u8,
    armored: bool,
    file_data: []u8,
};

fn runTest(expect: ExpectType, compressed: bool, payload: [Sha256.digest_length]u8) void {}
