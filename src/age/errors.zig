pub const AgeError = error{
    FileKeyDecryptionFailed,
    IncorrectIdentity,
    InvalidScryptRecipientBlock,
    OutOfMemory,
    ScryptKeyGenerationFailed,
};
