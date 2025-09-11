import 'dart:typed_data';

import 'package:ipcrypt/src/core/aes_xts.dart';
import 'package:ipcrypt/src/core/utils.dart';

class IpCryptExtendedNonDeterministic {
  const IpCryptExtendedNonDeterministic();

  static const int keySize = 32;
  static const int tweakSize = 16;

  /// Encrypts an IP address using AES-XTS mode.
  /// This function provides non-deterministic encryption with
  /// strong security guarantees.
  /// If no tweak is provided, a random one is generated, making the
  /// encryption non-deterministic.
  /// The tweak is included in the output to allow for decryption.
  Uint8List encrypt(
    final String ip,
    final Uint8List key, [
    final Uint8List? tweak,
  ]) {
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }
    final Uint8List tweak_ = tweak ?? randomBytes(tweakSize);
    if (tweak_.length != tweakSize) {
      throw ArgumentError('Tweak must be $tweakSize bytes.');
    }
    final Uint8List plaintext = ipToBytes(ip);
    final Uint8List ciphertext = encryptBlockXts(key, tweak_, plaintext);
    return (BytesBuilder()
          ..add(tweak_)
          ..add(ciphertext))
        .toBytes();
  }

  /// Decrypts an IP address using AES-XTS mode.
  /// The input must include both the tweak and
  /// ciphertext used during encryption.
  /// The first 16 bytes are the tweak,
  /// and the last 16 bytes are the ciphertext.
  String decrypt(final Uint8List encryptedData, final Uint8List key) {
    if (encryptedData.length != tweakSize + keySize ~/ 2) {
      throw ArgumentError(
        'Encrypted data must be ${tweakSize + keySize ~/ 2} bytes.',
      );
    }
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }
    final Uint8List tweak = encryptedData.sublist(0, tweakSize);
    final Uint8List ciphertext = encryptedData.sublist(tweakSize);
    final Uint8List plaintext = decryptBlockXts(key, tweak, ciphertext);
    return bytesToIp(plaintext);
  }
}
