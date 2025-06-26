pub const errors = @import("errors.zig");

pub const Stanza = struct {
    tag: []u8,
    args: [][]u8,
    body: []u8,
};
