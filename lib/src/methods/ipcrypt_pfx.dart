import 'dart:typed_data';

import 'package:ipcrypt/src/core/pfx.dart';

class IpCryptPrefixPreserving {
  const new();

  static const int keySize = 32;

  /// Encrypts an IP address using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// The first half of the 32-byte key cannot be the same as the second half.
  /// Returns the encrypted IP address maintaining the
  /// original format (IPv4 or IPv6).
  String encrypt(String ip, Uint8List key) => pfx(ip, key, true);

  /// Decrypts an IP address that was encrypted using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// The first half of the 32-byte key cannot be the same as the second half.
  /// Returns the decrypted IP address.
  String decrypt(String encryptedData, Uint8List key) =>
      pfx(encryptedData, key, false);
}
