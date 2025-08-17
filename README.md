# ipcrypt

[![Pub Package](https://img.shields.io/pub/v/ipcrypt?style=for-the-badge)](https://pub.dev/packages/ipcrypt)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/ipcrypt?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/ipcrypt?branch=main)
[![LICENSE](https://img.shields.io/badge/LICENSE-ISC-GREEN?style=for-the-badge)](LICENSE)

A Dart implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Requirements

- **Dart SDK:** 3.9+

## Overview

IPCrypt provides three different methods for IP address encryption:

1. **Deterministic Encryption**: Uses AES-128 in a deterministic mode, where the same input always produces the same output for a given key. This is useful when you need to consistently map IP addresses to encrypted values.

2. **Non-Deterministic Encryption**: Uses KIASU-BC, a tweakable block cipher, to provide non-deterministic encryption. This means the same input can produce different outputs, providing better privacy protection.

3. **Extended Non-Deterministic Encryption**: An enhanced version of non-deterministic encryption that uses a larger key and tweak size for increased security.

## Usage

See [example/ipcrypt.dart](example/ipcrypt.dart).

```dart
import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';

enum Method { deterministic, nonDeterministic, extendedNonDeterministic }

void main() {
  final List<({Uint8List key, Uint8List tweak, Method method})> credentials = [
    (
      key: hexStringToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
      tweak: hexStringToBytes(''),
      method: Method.deterministic,
    ),
    (
      key: hexStringToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
      tweak: hexStringToBytes('b4ecbe30b70898d7'),
      method: Method.nonDeterministic,
    ),
    (
      key: hexStringToBytes(
        '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ),
      tweak: hexStringToBytes('21bd1834bc088cd2b4ecbe30b70898d7'),
      method: Method.extendedNonDeterministic,
    ),
  ];

  for (final String ip in ['192.0.2.1', '2001:db8::1']) {
    for (final c in credentials) {
      Uint8List encryptedBytes;
      String encryptedIp = '';
      String decryptedIp = '';
      if (c.method == Method.deterministic) {
        encryptedIp = ipCryptDeterministic.encrypt(ip, c.key);
        decryptedIp = ipCryptDeterministic.decrypt(encryptedIp, c.key);
      }
      if (c.method == Method.nonDeterministic) {
        encryptedBytes = ipCryptNonDeterministic.encrypt(ip, c.key, c.tweak);
        encryptedIp = bytesToIp(encryptedBytes.sublist(c.tweak.length));
        decryptedIp = ipCryptNonDeterministic.decrypt(encryptedBytes, c.key);
      }
      if (c.method == Method.extendedNonDeterministic) {
        encryptedBytes = ipCryptExtendedNonDeterministic.encrypt(
          ip,
          c.key,
          c.tweak,
        );
        encryptedIp = bytesToIp(encryptedBytes.sublist(c.tweak.length));
        decryptedIp = ipCryptExtendedNonDeterministic.decrypt(
          encryptedBytes,
          c.key,
        );
      }
      print('IP: $ip | IPCrypt Method: ${c.method.name}');
      print('  Key (as hex string): ${bytesToHexString(c.key)}');
      if (c.method != Method.deterministic) {
        print('Tweak (as hex string): ${bytesToHexString(c.tweak)}');
      }
      print('         Encrypted IP: $encryptedIp');
      print('         Decrypted IP: $decryptedIp');
      print('');
    }
  }
}
```

Output

```text
IP: 192.0.2.1 | IPCrypt Method: deterministic
  Key (as hex string): 2b7e151628aed2a6abf7158809cf4f3c
         Encrypted IP: 1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777
         Decrypted IP: 192.0.2.1

IP: 192.0.2.1 | IPCrypt Method: nonDeterministic
  Key (as hex string): 2b7e151628aed2a6abf7158809cf4f3c
Tweak (as hex string): b4ecbe30b70898d7
         Encrypted IP: d8c5:1602:14e3:86f:13fe:6861:c4a6:dd1d
         Decrypted IP: 192.0.2.1

IP: 192.0.2.1 | IPCrypt Method: extendedNonDeterministic
  Key (as hex string): 0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301
Tweak (as hex string): 21bd1834bc088cd2b4ecbe30b70898d7
         Encrypted IP: a300:9985:293a:436f:28aa:2d31:5e3c:7566
         Decrypted IP: 192.0.2.1

IP: 2001:db8::1 | IPCrypt Method: deterministic
  Key (as hex string): 2b7e151628aed2a6abf7158809cf4f3c
         Encrypted IP: 10ea:8047:d631:d47d:150d:53dc:6ff3:9302
         Decrypted IP: 2001:db8::1

IP: 2001:db8::1 | IPCrypt Method: nonDeterministic
  Key (as hex string): 2b7e151628aed2a6abf7158809cf4f3c
Tweak (as hex string): b4ecbe30b70898d7
         Encrypted IP: 553a:c897:4d1b:4250:eafc:4b0a:a1f8:c96
         Decrypted IP: 2001:db8::1

IP: 2001:db8::1 | IPCrypt Method: extendedNonDeterministic
  Key (as hex string): 0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301
Tweak (as hex string): 21bd1834bc088cd2b4ecbe30b70898d7
         Encrypted IP: 4158:7059:8424:8841:107e:8036:4aac:933b
         Decrypted IP: 2001:db8::1
```

## References

- IPCrypt in Go
  - <https://github.com/jedisct1/go-ipcrypt>

- IPCrypt in JavaScript
  - <https://github.com/jedisct1/ipcrypt-js>
