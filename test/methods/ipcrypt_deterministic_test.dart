import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';
import 'package:ipcrypt/src/methods/ipcrypt_deterministic.dart';
import 'package:test/test.dart';
import 'test_vectors.dart';

void main() {
  group('IpCryptDeterministic', () {
    test('IpCryptDeterministic() | returnsNormally', () {
      expect(IpCryptDeterministic.new, returnsNormally);
    });

    for (final TestVector testVector in TestVectors.deterministic) {
      test('encrypt | ${testVector.ip} -> ${testVector.output}', () {
        expect(
          ipCryptDeterministic.encrypt(
            testVector.ip,
            hexStringToBytes(testVector.key),
          ),
          testVector.output,
        );
      });
      test('decrypt | ${testVector.output} -> ${testVector.ip}', () {
        expect(
          ipCryptDeterministic.decrypt(
            testVector.output,
            hexStringToBytes(testVector.key),
          ),
          testVector.ip,
        );
      });
    }

    test('encrypt | Invalid input', () {
      expect(
        () => ipCryptDeterministic.encrypt('invalid', Uint8List(16)),
        throwsFormatException,
      );
      expect(
        () => ipCryptDeterministic.encrypt('1.1.1.1', Uint8List(42)),
        throwsArgumentError,
      );
    });
    test('decrypt | Invalid input', () {
      expect(
        () => ipCryptDeterministic.decrypt('invalid', Uint8List(16)),
        throwsFormatException,
      );
      expect(
        () => ipCryptDeterministic.decrypt('1.1.1.1', Uint8List(42)),
        throwsArgumentError,
      );
    });
  });
}
