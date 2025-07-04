const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const mem = @import("std").mem;
const constants = @import("constants.zig");

const Identity = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    unwrap: *const fn (*anyopaque, mem.Allocator, []const Stanza) AgeError![constants.FILE_KEY_BYTES]u8,
};

pub fn rawUnwrap(self: Identity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![constants.FILE_KEY_BYTES]u8 {
    return self.vtable.unwrap(self.ptr, allocator, stanzas);
}

pub fn unwrapFileKey(self: Identity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![constants.FILE_KEY_BYTES]u8 {
    return self.rawUnwrap(allocator, stanzas);
}
