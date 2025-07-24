# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a pure Zig implementation of the [age file encryption standard](https://age-encryption.org/). The project provides both a library (`age` module) and a command-line tool (`zage`) for file encryption and decryption.

## Commands

### Build and Run
- `zig build` - Build the project
- `zig build -Doptimize=ReleaseSafe` - Build optimized release version
- `zig run src/zage.zig` - Run the main executable directly

### Testing
- `zig build test` - Run all tests (both zage and age module tests)
- `zig test src/age.zig` - Run only age module tests
- `zig test src/age/scrypt.zig` - Run only scrypt tests
- `zig test src/age/x25519.zig` - Run only x25519 tests
- `zig test src/age/stream.zig` - Run only stream tests
- `zig test src/zage.zig` - Run only zage executable tests

### Installation
- `zig build install` - Install the `zage` binary to `zig-out/bin/`

## Architecture

### Core Modules
- **`src/age.zig`** - Main library module that exports all public APIs
- **`src/zage.zig`** - CLI executable (currently basic, prints "Hello, World!")

### Age Library Structure
- **`src/age/`** - Core age encryption implementation
  - `Identity.zig` - Identity type for decryption
  - `Recipient.zig` - Recipient type for encryption
  - `Stanza.zig` - Stanza data structures for encrypted headers
  - `x25519.zig` - X25519 elliptic curve encryption implementation
  - `stream.zig` - Streaming encryption and decryption
  - `scrypt.zig` - Password-based encryption using scrypt
  - `errors.zig` - Age-specific error types
  - `internal/bech32.zig` - Bech32 encoding for key serialization

### Key Components
- **X25519 Implementation**: Asymmetric encryption using Curve25519
- **Scrypt Implementation**: Password-based encryption with configurable work factors
- **Bech32 Encoding**: For encoding public keys with `age` prefix
- **ChaCha20-Poly1305**: AEAD cipher for actual data encryption
- **HKDF-SHA256**: Key derivation function

### Build Configuration
- Minimum Zig version: `0.15.0-dev.847+850655f06`
- Project version: `0.1.0`
- Uses Zig's module system with `age` and `bech32` modules
- Tests are automatically run on build (`b.getInstallStep().dependOn(tests_step)`)

### Architecture Notes
- The library follows the age specification with separate Identity/Recipient abstractions
- X25519 and Scrypt are the two primary encryption schemes supported
- The codebase uses Zig's standard crypto primitives extensively
- Error handling uses custom `AgeError` types for age-specific errors
