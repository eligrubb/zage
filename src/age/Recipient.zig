const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const mem = @import("std").mem;

const Recipient = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    // TODO write interface docs lol
    wrap: *const fn (*anyopaque, mem.Allocator, []const u8) AgeError![]Stanza,
};

pub fn rawWrap(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.vtable.wrap(self.ptr, allocator, file_key);
}

pub fn wrapFileKey(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.rawWrap(allocator, file_key);
}
