pub const AgeError = error{
    FileKeyDecryptionFailed,
    IncorrectIdentity,
    IncorrectKeyLength,
    InvalidScryptRecipientBlock,
    InvalidX25519RecpientBlock,
    OutOfMemory,
    ScryptKeyGenerationFailed,
};
