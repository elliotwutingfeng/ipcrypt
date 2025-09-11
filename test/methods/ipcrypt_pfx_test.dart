import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';
import 'package:ipcrypt/src/methods/ipcrypt_pfx.dart';
import 'package:test/test.dart';
import 'test_vectors.dart';

void main() {
  group('IpCryptPrefixPreserving', () {
    test('IpCryptPrefixPreserving() | returnsNormally', () {
      expect(IpCryptPrefixPreserving.new, returnsNormally);
    });

    for (final TestVector testVector in TestVectors.pfx) {
      test('encrypt | ${testVector.ip} -> ${testVector.output}', () {
        expect(
          ipCryptPrefixPreserving.encrypt(
            testVector.ip,
            hexStringToBytes(testVector.key),
          ),
          testVector.output,
        );
      });
      test('decrypt | ${testVector.output} -> ${testVector.ip}', () {
        expect(
          ipCryptPrefixPreserving.decrypt(
            testVector.output,
            hexStringToBytes(testVector.key),
          ),
          testVector.ip,
        );
      });
    }

    test('encrypt | Invalid input', () {
      expect(
        () => ipCryptPrefixPreserving.encrypt(
          'invalid',
          Uint8List.fromList(
            List.generate(32, (final int i) => i, growable: false),
          ),
        ),
        throwsFormatException,
      );
      expect(
        () => ipCryptPrefixPreserving.encrypt('1.1.1.1', Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => ipCryptPrefixPreserving.encrypt(
          '1.1.1.1',
          Uint8List.fromList(
            List.generate(42, (final int i) => i, growable: false),
          ),
        ),
        throwsArgumentError,
      );
    });
    test('decrypt | Invalid input', () {
      expect(
        () => ipCryptPrefixPreserving.decrypt(
          'invalid',
          Uint8List.fromList(
            List.generate(32, (final int i) => i, growable: false),
          ),
        ),
        throwsFormatException,
      );
      expect(
        () => ipCryptPrefixPreserving.decrypt('1.1.1.1', Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => ipCryptPrefixPreserving.decrypt(
          '1.1.1.1',
          Uint8List.fromList(
            List.generate(42, (final int i) => i, growable: false),
          ),
        ),
        throwsArgumentError,
      );
    });
  });
}
