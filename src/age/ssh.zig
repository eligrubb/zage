const Identity = @import("Identity.zig");
const Recipient = @import("Recipient.zig");

pub const SshRecipient = struct {
    pub fn recipient() Recipient {}
};

pub const SshIdentity = struct {
    pub fn identity() Identity {}
};
