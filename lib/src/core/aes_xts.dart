import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_ecb.dart';
import 'package:ipcrypt/src/core/utils.dart';
import 'package:ipcrypt/src/methods/ipcrypt_ndx.dart';

/// Encrypt a single block using AES-XTS
/// mode (XEX Tweakable Block Cipher with Ciphertext Stealing).
/// AES-XTS uses two keys: K1 for the main encryption
/// and K2 for tweak processing.
/// The tweak is first encrypted with K2, then the result is used in both
/// pre- and post-whitening of the main encryption with K1.
/// This provides strong security for IP address encryption.
///
/// Process:
/// 1. Split the 32-byte key into K1 and K2 (16 bytes each).
/// 2. Encrypt the tweak with AES using K2.
/// 3. XOR plaintext with encrypted tweak.
/// 4. Encrypt the result with AES using K1.
/// 5. XOR the result with encrypted tweak again.
Uint8List encryptBlockXts(
  final Uint8List key,
  final Uint8List tweak,
  final Uint8List plaintext,
) {
  final Uint8List k1 = key.sublist(
    0,
    IpCryptExtendedNonDeterministic.keySize ~/ 2,
  );
  final Uint8List k2 = key.sublist(
    IpCryptExtendedNonDeterministic.keySize ~/ 2,
  );
  final Uint8List firstEncrypt = encryptBlockEcb(k2, tweak);
  final Uint8List firstXor = xorBytes(plaintext, firstEncrypt);
  final Uint8List secondEncrypt = encryptBlockEcb(k1, firstXor);
  return xorBytes(secondEncrypt, firstEncrypt);
}

/// Decrypt a single block using AES-XTS mode.
/// The decryption process is the inverse of encryption.
///
/// Process:
/// 1. Split the 32-byte key into K1 and K2 (16 bytes each).
/// 2. Encrypt the tweak with AES using K2 (same as encryption).
/// 3. XOR ciphertext with encrypted tweak.
/// 4. Decrypt the result with AES using K1.
/// 5. XOR the result with encrypted tweak again.
Uint8List decryptBlockXts(
  final Uint8List key,
  final Uint8List tweak,
  final Uint8List ciphertext,
) {
  final Uint8List k1 = key.sublist(
    0,
    IpCryptExtendedNonDeterministic.keySize ~/ 2,
  );
  final Uint8List k2 = key.sublist(
    IpCryptExtendedNonDeterministic.keySize ~/ 2,
  );
  final Uint8List firstEncrypt = encryptBlockEcb(k2, tweak);
  final Uint8List firstXor = xorBytes(ciphertext, firstEncrypt);
  final Uint8List firstDecrypt = decryptBlockEcb(k1, firstXor);
  return xorBytes(firstDecrypt, firstEncrypt);
}
