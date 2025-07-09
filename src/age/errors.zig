pub const AgeError = error{
    FileKeyDecryptionFailed,
    IncorrectIdentity,
    IncorrectKeyLength,
    InvalidBech32String,
    InvalidScryptRecipientBlock,
    InvalidX25519RecipientBlock,
    OutOfMemory,
    ScryptKeyGenerationFailed,
};
