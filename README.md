<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="./assets/img/zage-logo-white.png">
        <source media="(prefers-color-scheme: light)" srcset="./assets/img/zage-logo.png">
        <img alt="the zage logo: the age logo (a wireframe of St. Peters dome in Rome, with the text: age, file encryption) with the Ziglang Z spray painted on top." width="600" src="./assets/img/zage-logo.svg"
    </picture>
</p>

# zage: age File Encryption with Zig

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
![Zig_Version](https://img.shields.io/badge/Zig-nightly-color?logo=zig&color=%23f3ab20)
[![Go Reference](https://pkg.go.dev/badge/filippo.io/age.svg)](https://pkg.go.dev/filippo.io/age)
[![C2SP_specification](https://img.shields.io/badge/%C2%A7%23-specification-blueviolet)](https://age-encryption.org/v1)

A pure Zig implementation of the [`age` file encryption
standard](https://age-encryption.org/).

The specification can be found at
[age-encryption.org/v1](https://age-encryption.org/v1). `age` was designed by
[@Benjojo](https://benjojo.co.uk/) and
[@FiloSottile](https://bsky.app/profile/filippo.abyssdomain.expert).

example from the primary go library:

```
$ zage-keygen -o key.txt
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
$ tar cvz ~/data | zage -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age
$ zage --decrypt -i key.txt data.tar.gz.age > data.tar.gz
```

[Like
age](https://github.com/FiloSottile/age/blob/15153e699f5b7223b8fd573c3d869092b37749eb/README.md?plain=1#L34)
and GIF, `zage` is pronounced with a hard *g* sound:
[`/zɑːgeɪ/`](https://en.wikipedia.org/wiki/Help:IPA/English) or
[*ZAH-ghay*](https://en.wikipedia.org/wiki/Help:Pronunciation_respelling_key).
`zage` is always spelled entirely lowercase.

>[!ALERT]
>`zage` is currently alpha software and not considered ready for production use

# Quickstart

Generate a keypair:

```sh
$ zage-keygen -o key.txt
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

Encrypt a file:

```sh
tar cvz ~/data | zage -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age
```

Decrypt a file:

```sh
zage --decrypt -i key.txt data.tar.gz.age > data.tar.gz
```

# Installation

## Build from source with Zig

[Download Zig](https://ziglang.org/download/) and run the following commands:

```sh
git clone git@github.com:eligrubb/zage.git
cd zage
zig build
```

## Binary releases (TBD)

# Usage

## Basic encryption/decryption

## Multiple recipients

## Passphrase encryption

## Command-line options

```sh
zage --help
```

# age Zig library usage

## Zig module installation

```sh
zig fetch --save ...
```

## Basic API examples

### Generating a keypair

### Encrypting a file with X25519

### Encrypting a file with scrypt

# Features

## age specification compliance chart

## performance

# Testing

# Related projects

- [age](https://filippo.io/age): the original Go implementation
- [rage](https://github.com/str4d/rage): Rust reference implementation
- [typage](https://github.com/FiloSottile/typage): official TypeScrypt
implementation
- [awesome-age](https://github.com/FiloSottile/awesome-age): a curated list of
age resources, including plugins, tools, integrations, and libraries.

# License and Acknowledgements

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file
for details.

The Go implementation of age is licensed under the [BSD 3-Clause
License](https://github.com/FiloSottile/age/blob/master/LICENSE). The Rust
implementation of age is licensed under either [Apache License
2.0](https://github.com/str4d/rage/blob/main/LICENSE-APACHE) or [MIT
License](https://github.com/str4d/rage/blob/main/LICENSE-MIT) at your option.
The TypeScript implementation of age is licensed under the [BSD 3-Clause
License](https://github.com/FiloSottile/typage/blob/main/LICENSE)
