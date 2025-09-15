pub const AgeError = error{
    ReaderBufferTooSmall,
    FileKeyDecryptionFailed,
    IdentityElement,
    IncorrectIdentity,
    IncorrectKeyLength,
    InvalidBech32String,
    InvalidScryptRecipientBlock,
    InvalidX25519RecipientBlock,
    InvalidX25519Identity,
    OutOfMemory,
    ScryptKeyGenerationFailed,
    UnknownRecipient,
};
