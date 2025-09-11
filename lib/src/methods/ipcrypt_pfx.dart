import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_ecb.dart';
import 'package:ipcrypt/src/core/utils.dart';

class IpCryptPrefixPreserving {
  const IpCryptPrefixPreserving();

  static const int keySize = 32;

  /// Encrypts an IP address using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// Returns the encrypted IP address maintaining the
  /// original format (IPv4 or IPv6).
  String encrypt(final String ip, final Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }

    // Split the key into two AES-128 keys
    final Uint8List k1 = key.sublist(0, 16);
    final Uint8List k2 = key.sublist(16, 32);

    // Check that k1 and k2 are different
    if (equalBytes(k1, k2)) {
      throw ArgumentError('The two halves of the key must be different.');
    }

    // Convert IP to 16-byte representation
    final Uint8List bytes16 = ipToBytes(ip);

    // Initialize encrypted result with zeros
    final Uint8List encrypted = Uint8List(16);

    // Determine starting point
    final bool ipv4 = isIPv4(bytes16);
    final int prefixStart = ipv4 ? 96 : 0;

    // If IPv4, copy the IPv4-mapped prefix
    if (ipv4) {
      encrypted.setAll(0, bytes16.sublist(0, 12));
    }

    // Initialize padded_prefix for the starting prefix length
    Uint8List paddedPrefix = ipv4 ? padPrefix96() : padPrefix0();

    // Process each bit position
    for (
      int prefixLenBits = prefixStart;
      prefixLenBits < 128;
      prefixLenBits++
    ) {
      // Compute pseudorandom function with dual AES encryption
      final Uint8List e1 = encryptBlockEcb(k1, paddedPrefix);
      final Uint8List e2 = encryptBlockEcb(k2, paddedPrefix);

      // XOR the two encryptions
      final Uint8List e = xorBytes(e1, e2);

      // We only need the least significant bit of byte 15
      final int cipherBit = e[15] & 1;

      // Extract the current bit from the original IP
      final int currentBitPos = 127 - prefixLenBits;

      // Set the bit in the encrypted result
      final int originalBit = getBit(bytes16, currentBitPos);
      final int encryptedBit = cipherBit ^ originalBit;
      setBit(encrypted, currentBitPos, encryptedBit);

      // Prepare padded_prefix for next iteration
      // Shift left by 1 bit and insert the next bit from bytes16
      paddedPrefix = shiftLeftOneBit(paddedPrefix);
      setBit(paddedPrefix, 0, originalBit);
    }
    return bytesToIp(encrypted);
  }

  /// Decrypts an IP address that was encrypted using ipcrypt-pfx mode.
  /// The key must be exactly 32 bytes long (split into two AES-128 keys).
  /// Returns the decrypted IP address.
  String decrypt(final String encryptedIp, final Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }

    // Split the key into two AES-128 keys
    final Uint8List k1 = key.sublist(0, 16);
    final Uint8List k2 = key.sublist(16, 32);

    // Check that k1 and k2 are different
    if (equalBytes(k1, k2)) {
      throw ArgumentError('The two halves of the key must be different.');
    }

    // Convert encrypted IP to 16-byte representation
    final Uint8List encryptedBytes = ipToBytes(encryptedIp);

    // Initialize decrypted result with zeros
    final Uint8List decrypted = Uint8List(16);

    // Determine starting point
    final bool ipv4 = isIPv4(encryptedBytes);
    final int prefixStart = ipv4 ? 96 : 0;

    // If IPv4, copy the IPv4-mapped prefix
    if (ipv4) {
      decrypted.setAll(0, encryptedBytes.sublist(0, 12));
    }

    // Initialize padded_prefix for the starting prefix length
    Uint8List paddedPrefix;
    if (prefixStart == 0) {
      paddedPrefix = padPrefix0();
    } else {
      paddedPrefix = padPrefix96();
    }

    // Process each bit position
    for (
      int prefixLenBits = prefixStart;
      prefixLenBits < 128;
      prefixLenBits++
    ) {
      // Compute pseudorandom function with dual AES encryption
      final Uint8List e1 = encryptBlockEcb(k1, paddedPrefix);
      final Uint8List e2 = encryptBlockEcb(k2, paddedPrefix);

      // XOR the two encryptions
      final Uint8List e = xorBytes(e1, e2);

      // We only need the least significant bit of byte 15
      final int cipherBit = e[15] & 1;

      // Extract the current bit from the encrypted IP
      final int currentBitPos = 127 - prefixLenBits;

      // Set the bit in the decrypted result
      final int encryptedBit = getBit(encryptedBytes, currentBitPos);
      final int originalBit = cipherBit ^ encryptedBit;
      setBit(decrypted, currentBitPos, originalBit);

      // Prepare padded_prefix for next iteration
      // Shift left by 1 bit and insert the next bit from decrypted
      paddedPrefix = shiftLeftOneBit(paddedPrefix);
      setBit(paddedPrefix, 0, originalBit);
    }
    return bytesToIp(decrypted);
  }
}
