import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_ecb.dart';

class IpCryptPrefixPreserving {
  const IpCryptPrefixPreserving();

  static const int keySize = 32;

  /// Encrypts an IP address using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// Returns the encrypted IP address maintaining the
  /// original format (IPv4 or IPv6).
  String encrypt(final String ip, final Uint8List key) =>
      aesEcbPfx(ip, key, true);

  /// Decrypts an IP address that was encrypted using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// Returns the decrypted IP address.
  String decrypt(final String encryptedIp, final Uint8List key) =>
      aesEcbPfx(encryptedIp, key, false);
}
