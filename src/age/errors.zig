pub const AgeError = error{
    FileKeyDecryptionFailed,
    IdentityElement,
    IncorrectIdentity,
    IncorrectKeyLength,
    InvalidBech32String,
    InvalidScryptRecipientBlock,
    InvalidX25519RecipientBlock,
    OutOfMemory,
    ScryptKeyGenerationFailed,
};
