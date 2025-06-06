import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';
import 'package:ipcrypt/src/methods/ipcrypt_ndx.dart';
import 'package:test/test.dart';
import 'test_vectors.dart';

void main() {
  group('IpCryptExtendedNonDeterministic', () {
    test('IpCryptExtendedNonDeterministic() | returnsNormally', () {
      expect(IpCryptExtendedNonDeterministic.new, returnsNormally);
    });

    for (final TestVector testVector in TestVectors.ndx) {
      test('encrypt | ${testVector.ip} -> ${testVector.output}', () {
        testVector.tweak.isEmpty
            ? expect(
                () => bytesToIp(
                  ipCryptExtendedNonDeterministic
                      .encrypt(testVector.ip, hexStringToBytes(testVector.key))
                      .sublist(IpCryptExtendedNonDeterministic.tweakSize),
                ),
                returnsNormally,
              )
            : expect(
                ipCryptExtendedNonDeterministic.encrypt(
                  testVector.ip,
                  hexStringToBytes(testVector.key),
                  hexStringToBytes(testVector.tweak),
                ),
                hexStringToBytes(testVector.output),
              );
      });
      if (testVector.tweak.isEmpty) {
        continue;
      }
      test('decrypt | ${testVector.output} -> ${testVector.ip}', () {
        expect(
          ipCryptExtendedNonDeterministic.decrypt(
            hexStringToBytes(testVector.output),
            hexStringToBytes(testVector.key),
          ),
          testVector.ip,
        );
      });
    }

    test('encrypt | Invalid input', () {
      expect(
        () => ipCryptExtendedNonDeterministic.encrypt('invalid', Uint8List(32)),
        throwsFormatException,
      );
      expect(
        () => ipCryptExtendedNonDeterministic.encrypt('1.1.1.1', Uint8List(42)),
        throwsArgumentError,
      );
      expect(
        () => ipCryptExtendedNonDeterministic.encrypt(
          '1.1.1.1',
          Uint8List(32),
          Uint8List(42),
        ),
        throwsArgumentError,
      );
    });
    test('decrypt | Invalid input', () {
      expect(
        () => ipCryptExtendedNonDeterministic.decrypt(
          Uint8List(42),
          Uint8List(32),
        ),
        throwsArgumentError,
      );
      expect(
        () => ipCryptExtendedNonDeterministic.decrypt(
          Uint8List(32),
          Uint8List(42),
        ),
        throwsArgumentError,
      );
    });
  });
}
