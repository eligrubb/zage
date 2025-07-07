const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const mem = @import("std").mem;

pub const Recipient = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub fn init(recipient_ptr: anytype) Recipient {
    const T = @TypeOf(recipient_ptr);

    const gen = struct {
        fn wrap(ctx: *anyopaque, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
            const recipient: T = @ptrCast(@alignCast(ctx));
            return recipient.wrapFileKey(allocator, file_key);
        }
    };

    return .{
        .ptr = recipient_ptr,
        .vtable = &.{
            .wrap = gen.wrap,
        },
    };
}

pub const VTable = struct {
    // TODO write interface docs lol
    wrap: *const fn (*anyopaque, mem.Allocator, []const u8) AgeError![]Stanza,
};

pub fn rawWrap(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.vtable.wrap(self.ptr, allocator, file_key);
}

/// Call Stanza.deinit for each stanza in []Stanza
pub fn wrapFileKey(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.rawWrap(allocator, file_key);
}
