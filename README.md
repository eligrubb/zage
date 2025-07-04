<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="./assets/img/zage-logo-white.png">
        <source media="(prefers-color-scheme: light)" srcset="./assets/img/zage-logo.png">
        <img alt="the Zage logo: the age logo (a wireframe of St. Peters dome in Rome, with the text: age, file encryption) with the Ziglang Z spray painted on top." width="600" src="./assets/img/zage-logo.svg"
    </picture>
</p>


# zage: age File Encryption with Zig

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig Version](https://img.shields.io/badge/Zig-nightly-success.svg)](https://ziglang.org/)
[![Go Reference](https://pkg.go.dev/badge/filippo.io/age.svg)](https://pkg.go.dev/filippo.io/age)
[![C2SP specification](https://img.shields.io/badge/%C2%A7%23-specification-blueviolet)](https://age-encryption.org/v1)
<!-- [![man page](<https://img.shields.io/badge/age(1)-man%20page-lightgrey>)](https://filippo.io/age/age.1) -->

A pure Zig implementation of the [age file encryption standard](https://age-encryption.org/).

example from the primary go library:
```
$ zage-keygen -o key.txt
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
$ tar cvz ~/data | age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age
$ zage --decrypt -i key.txt data.tar.gz.age > data.tar.gz
```
