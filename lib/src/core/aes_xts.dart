import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

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
  Uint8List key,
  Uint8List tweak,
  Uint8List plaintext,
) => AESInXTSMode(key, tweak).encrypt(plaintext);

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
  Uint8List key,
  Uint8List tweak,
  Uint8List ciphertext,
) => AESInXTSMode(key, tweak).decrypt(ciphertext);
