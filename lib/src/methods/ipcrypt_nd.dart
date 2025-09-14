import 'dart:typed_data';

import 'package:ipcrypt/src/core/kiasu_bc.dart';
import 'package:ipcrypt/src/core/utils.dart';

class IpCryptNonDeterministic {
  const IpCryptNonDeterministic();

  static const int keySize = 16;
  static const int tweakSize = 8;

  /// Encrypts an IP address using KIASU-BC with an optional tweak.
  /// If no tweak is provided, a random 8-byte tweak is generated.
  /// Returns a 24-byte array containing the tweak followed by the ciphertext.
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
    final Uint8List ciphertext = encryptBlockKiasuBc(key, tweak_, plaintext);
    return (BytesBuilder(copy: false)
          ..add(tweak_)
          ..add(ciphertext))
        .toBytes();
  }

  /// Decrypts an IP address that was encrypted with KIASU-BC.
  /// Input must be a 24-byte array containing the tweak
  /// followed by the ciphertext.
  String decrypt(final Uint8List encryptedData, final Uint8List key) {
    if (encryptedData.length != tweakSize + keySize) {
      throw ArgumentError(
        'Encrypted data must be ${tweakSize + keySize} bytes.',
      );
    }
    if (key.length != keySize) {
      throw ArgumentError('Key must be $keySize bytes.');
    }
    final Uint8List tweak = encryptedData.sublist(0, tweakSize);
    final Uint8List ciphertext = encryptedData.sublist(tweakSize);
    final Uint8List plaintext = decryptBlockKiasuBc(key, tweak, ciphertext);
    return bytesToIp(plaintext);
  }
}
