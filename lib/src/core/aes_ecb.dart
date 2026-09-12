import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

/// Encrypt a single block using AES-ECB mode.
Uint8List encryptBlockEcb(Uint8List key, Uint8List plaintext) =>
    AESInECBMode(key, Padding.none).encrypt(plaintext);

/// Decrypt a single block using AES-ECB mode.
/// The decryption process is the inverse of encryption.
Uint8List decryptBlockEcb(Uint8List key, Uint8List ciphertext) =>
    AESInECBMode(key, Padding.none).decrypt(ciphertext);
