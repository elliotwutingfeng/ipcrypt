import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/ecb.dart';

/// Encrypt a single block using AES-ECB mode.
Uint8List encryptBlockEcb(final Uint8List key, final Uint8List plaintext) {
  final ECBBlockCipher ecb = ECBBlockCipher(AESEngine())
    ..init(true, KeyParameter(key));
  return ecb.process(plaintext);
}

/// Decrypt a single block using AES-ECB mode.
/// The decryption process is the inverse of encryption.
Uint8List decryptBlockEcb(final Uint8List key, final Uint8List ciphertext) {
  final ECBBlockCipher ecb = ECBBlockCipher(AESEngine())
    ..init(false, KeyParameter(key));
  return ecb.process(ciphertext);
}
