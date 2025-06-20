# Zage: age File Encryption with Zig

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig Version](https://img.shields.io/badge/Zig-0.14.1-success.svg)](https://ziglang.org/)

A pure Zig implementation of the [age file encryption standard](https://age-encryption.org/)

example from the primary go library:
```
$ zage-keygen -o key.txt
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
$ tar cvz ~/data | age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age
$ zage --decrypt -i key.txt data.tar.gz.age > data.tar.gz
```

