# CLAUDE.local.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Zig implementation of the [age file encryption standard](https://age-encryption.org/). The project provides both a library (`age` module) and command-line tool (`zage`) for file encryption and decryption.

## Build System & Commands

The project uses Zig's native build system. Key commands:

- `zig build` - Build the project
- `zig build test` - Run all tests (both zage and age module tests)
- `zig build install` - Install the zage executable

The minimum Zig version required is `0.15.0-dev.847+850655f06`.

## Architecture

The codebase is organized into two main modules:

### `age` Module (src/age.zig)
Core encryption library with the following components:
- **Identity.zig** - Interface for decryption keys using vtable pattern
- **Recipient.zig** - Interface for encryption recipients using vtable pattern
- **Stanza.zig** - Encrypted header stanzas containing file keys
- **x25519.zig** - X25519 key exchange implementation
- **scrypt.zig** - Password-based encryption using scrypt
- **internal/bech32.zig** - Bech32 encoding for key serialization
- **constants.zig** - Protocol constants (FILE_KEY_BYTES, etc.)
- **errors.zig** - Error definitions (AgeError)

### `zage` Module (src/zage.zig)
Command-line interface (currently minimal "Hello, World!" implementation)

## Key Design Patterns

- **Virtual Table Pattern**: Both Identity and Recipient use vtables for polymorphic behavior
- **Error Handling**: Uses custom `AgeError` type for library-specific errors
- **Memory Management**: Allocators passed explicitly to functions requiring memory allocation
- **Module System**: Clear separation between library (`age`) and CLI (`zage`) components

## Testing

Tests are automatically run during build (`b.getInstallStep().dependOn(tests_step)`). The test suite includes:
- Unit tests for individual modules
- Comprehensive testing via `std.testing.refAllDecls`
- Tests for both main modules (zage and age)

## Development Notes

The project follows Zig conventions for:
- Module imports and exports
- Error handling patterns
- Memory allocation patterns
- Test organization
