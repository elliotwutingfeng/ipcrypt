import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_ecb.dart';
import 'package:ipcrypt/src/core/utils.dart';
import 'package:ipcrypt/src/methods/ipcrypt_pfx.dart';

/// Encrypts or Decrypts an IP address using ipcrypt-pfx mode.
/// The key must be exactly 32 bytes long (split into two AES-128 keys).
/// The first half of the 32-byte key cannot be the same as the second half.
String pfx(final String ip, final Uint8List key, final bool encrypt) {
  if (key.length != IpCryptPrefixPreserving.keySize) {
    throw ArgumentError(
      'Key must be ${IpCryptPrefixPreserving.keySize} bytes.',
    );
  }

  // Split the key into two AES-128 keys
  final Uint8List k1 = key.sublist(0, IpCryptPrefixPreserving.keySize ~/ 2);
  final Uint8List k2 = key.sublist(IpCryptPrefixPreserving.keySize ~/ 2);

  // k1 and k2 must be different
  if (equalBytes(k1, k2)) {
    throw ArgumentError('The two halves of the key must be different.');
  }

  // Convert IP to 16-byte representation
  final Uint8List ipBytes = ipToBytes(ip);

  // Initialize encrypted/decrypted result with zeros
  final Uint8List result = Uint8List(16);

  // Determine starting point
  final bool ipv4 = isIPv4(ipBytes);
  final int prefixStart = ipv4 ? 96 : 0;

  // If IPv4, copy the IPv4-mapped prefix
  if (ipv4) {
    result.setAll(0, ipBytes.sublist(0, 12));
  }

  // Initialize padded_prefix for the starting prefix length
  Uint8List paddedPrefix = ipv4 ? padPrefix96() : padPrefix0();

  // Process each bit position
  for (int prefixLenBits = prefixStart; prefixLenBits < 128; prefixLenBits++) {
    // Compute pseudorandom function with dual AES encryption
    final Uint8List e1 = encryptBlockEcb(k1, paddedPrefix);
    final Uint8List e2 = encryptBlockEcb(k2, paddedPrefix);

    // XOR the two encryptions
    final Uint8List e = xorBytes(e1, e2);

    // We only need the least significant bit of byte 15
    final int cipherBit = e[15] & 1;

    // Extract the current bit from the original IP
    final int currentBitPos = 127 - prefixLenBits;

    // Set the bit in the encrypted/decrypted result
    final int originalBit = getBit(ipBytes, currentBitPos);
    final int xoredBit = cipherBit ^ originalBit;
    setBit(result, currentBitPos, xoredBit);

    // Prepare padded_prefix for next iteration
    // Shift left by 1 bit and insert the next bit from unencrypted ip bytes
    paddedPrefix = shiftLeftOneBit(paddedPrefix);
    setBit(paddedPrefix, 0, encrypt ? originalBit : xoredBit);
  }
  return bytesToIp(result);
}
