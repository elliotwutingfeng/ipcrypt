import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_ecb.dart';
import 'package:ipcrypt/src/core/utils.dart';

class IpCryptDeterministic {
  const new();

  static const int keySize = 16;

  /// Encrypts an IP address using AES-128 in a deterministic mode.
  /// This mode ensures that the same input IP address and key will always
  /// produce the same output, making it suitable for scenarios where consistent
  /// mapping is required (e.g., database lookups, load balancing).
  ///
  /// The encryption process:
  /// 1. Convert IP address to a 16-byte block
  /// 2. Apply standard AES-128 encryption
  /// 3. Convert result back to IP address format
  ///
  /// Security note: Because this mode is deterministic, it may leak information
  /// about IP address patterns.
  /// Use non-deterministic modes for higher security.
  String encrypt(String ip, Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }
    final Uint8List plaintext = ipToBytes(ip);
    final Uint8List ciphertext = encryptBlockEcb(key, plaintext);
    return bytesToIp(ciphertext);
  }

  /// Decrypts an IP address that was encrypted using
  /// AES-128 deterministic mode.
  ///
  /// The decryption process is the inverse of encryption:
  /// 1. Convert encrypted IP address to a 16-byte block
  /// 2. Apply standard AES-128 decryption
  /// 3. Convert result back to IP address format
  String decrypt(String encryptedData, Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }
    final Uint8List ciphertext = ipToBytes(encryptedData);
    final Uint8List plaintext = decryptBlockEcb(key, ciphertext);
    return bytesToIp(plaintext);
  }
}
