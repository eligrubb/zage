pub const Recipient = @import("age/recipient.zig").Recipient;
pub const Identity = @import("age/identity.zig").Identity;
pub const ScryptRecipient = @import("age/scrypt.zig").ScryptRecipient;
pub const ScryptIdentity = @import("age/scrypt.zig").ScryptIdentity;
pub const X25519Recipient = @import("age/x25519.zig").X25519Recipient;
pub const X25519Identity = @import("age/x25519.zig").X25519Identity;
pub const AgeError = @import("age/errors.zig").AgeError;

test {
    const std = @import("std");
    _ = @import("age/scrypt.zig");
    _ = @import("age/x25519.zig");
    _ = @import("age/internal/bech32.zig");

    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("age/scrypt.zig"));
    std.testing.refAllDecls(@import("age/x25519.zig"));
    std.testing.refAllDecls(@import("age/internal/bech32.zig"));
}
