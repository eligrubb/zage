const std = @import("std");
const primitives = @import("primitives.zig");
const constants = @import("constants.zig");

const FILE_KEY_LEN = constants.FILE_KEY_BYTES;

pub const X25519Recipient = struct {};

test "x25519 round trip og" {
    const allocator = std.testing.allocator;

    var identity = try X25519Identity.generate();
    var recipient = identity.recipient();

    const r2 = try X25519Recipient.parseX25519Recipient(recipient.toString());
    try std.testing.expectEqualSlices(u8, recipient.toString(), r2.toString());

    const i2 = try X25519Identity.parseX25519Identity(identity.toString());
    try std.testing.expectEqualSlices(u8, identity.toString(), i2.toString());

    const rng = primitives.random;
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

    const rng = primitives.random;
    var file_key: [FILE_KEY_LEN]u8 = undefined;
    rng.bytes(file_key);

    const stanzas = try recipient.wrapFileKey(allocator, &file_key);
    defer for (stanzas) |stanza| {
        stanza.deinit();
    };

    var decrypted_file_key = try identity.unwrapFileKey(allocator, stanzas);

    try std.testing.expectEqualSlices(u8, &file_key, &decrypted_file_key);
}
