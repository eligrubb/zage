pub const FILE_KEY_BYTES: usize = 16;
pub const BASE64_ENCODED_FILE_KEY_BYTES: usize = 43;
pub const ChaCha20Poly1305 = struct {
    pub const key_length: usize = 32;
    pub const nonce_length: usize = 12;
    pub const tag_length: usize = 16;
};
pub const MAX_ARGS: usize = 2;
pub const X25519_SCALAR_BYTES: usize = 32;
