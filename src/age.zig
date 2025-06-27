pub const errors = @import("age/errors.zig");
pub const primitives = @import("age/primitives.zig");

pub const ScryptRecipient = @import("age/scrypt.zig").ScryptRecipient;
pub const ScryptIdentity = @import("age/scrypt.zig").ScryptIdentity;

pub const FILE_KEY_BYTES: usize = 16;

pub const Stanza = struct {
    tag: []u8,
    args: [][]u8,
    body: []u8,
};
