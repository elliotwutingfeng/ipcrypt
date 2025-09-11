import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';

enum Method {
  deterministic,
  nonDeterministic,
  extendedNonDeterministic,
  prefixPreserving,
}

void main() {
  final List<({Uint8List key, Uint8List tweak, Method method})> credentials = [
    (
      key: hexStringToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
      tweak: hexStringToBytes(''),
      method: Method.deterministic,
    ),
    (
      key: hexStringToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
      tweak: hexStringToBytes('b4ecbe30b70898d7'),
      method: Method.nonDeterministic,
    ),
    (
      key: hexStringToBytes(
        '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ),
      tweak: hexStringToBytes('21bd1834bc088cd2b4ecbe30b70898d7'),
      method: Method.extendedNonDeterministic,
    ),
    (
      key: hexStringToBytes(
        '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ),
      tweak: hexStringToBytes(''),
      method: Method.prefixPreserving,
    ),
  ];

  for (final String ip in ['192.0.2.1', '2001:db8::1']) {
    for (final c in credentials) {
      Uint8List encryptedBytes;
      String encryptedIp = '';
      String decryptedIp = '';
      if (c.method == Method.deterministic) {
        encryptedIp = ipCryptDeterministic.encrypt(ip, c.key);
        decryptedIp = ipCryptDeterministic.decrypt(encryptedIp, c.key);
      }
      if (c.method == Method.nonDeterministic) {
        encryptedBytes = ipCryptNonDeterministic.encrypt(ip, c.key, c.tweak);
        encryptedIp = bytesToIp(encryptedBytes.sublist(c.tweak.length));
        decryptedIp = ipCryptNonDeterministic.decrypt(encryptedBytes, c.key);
      }
      if (c.method == Method.extendedNonDeterministic) {
        encryptedBytes = ipCryptExtendedNonDeterministic.encrypt(
          ip,
          c.key,
          c.tweak,
        );
        encryptedIp = bytesToIp(encryptedBytes.sublist(c.tweak.length));
        decryptedIp = ipCryptExtendedNonDeterministic.decrypt(
          encryptedBytes,
          c.key,
        );
      }
      if (c.method == Method.prefixPreserving) {
        encryptedIp = ipCryptPrefixPreserving.encrypt(ip, c.key);
        decryptedIp = ipCryptPrefixPreserving.decrypt(encryptedIp, c.key);
      }
      print('IP: $ip | IPCrypt Method: ${c.method.name}');
      print('  Key (as hex string): ${bytesToHexString(c.key)}');
      if (![Method.deterministic, Method.prefixPreserving].contains(c.method)) {
        print('Tweak (as hex string): ${bytesToHexString(c.tweak)}');
      }
      print('         Encrypted IP: $encryptedIp');
      print('         Decrypted IP: $decryptedIp');
      print('');
    }
  }
}
