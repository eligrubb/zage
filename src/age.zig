pub const primitives = @import("age/primitives.zig");

pub const ScryptRecipient = @import("age/scrypt.zig").ScryptRecipient;
pub const ScryptIdentity = @import("age/scrypt.zig").ScryptIdentity;
pub const AgeError = @import("age/errors.zig").AgeError;

test {
    const std = @import("std");
    std.testing.refAllDeclsRecursive(@This());
}

test {
    _ = @import("age/scrypt.zig");
}
