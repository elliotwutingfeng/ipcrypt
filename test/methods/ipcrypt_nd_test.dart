import 'dart:typed_data';

import 'package:ipcrypt/ipcrypt.dart';
import 'package:ipcrypt/src/methods/ipcrypt_nd.dart';
import 'package:test/test.dart';
import 'test_vectors.dart';

void main() {
  group('IpCryptNonDeterministic', () {
    test('IpCryptNonDeterministic() | returnsNormally', () {
      expect(IpCryptNonDeterministic.new, returnsNormally);
    });

    for (final TestVector testVector in TestVectors.nd) {
      test('encrypt | ${testVector.ip} -> ${testVector.output}', () {
        testVector.tweak.isEmpty
            ? expect(
                () => bytesToIp(
                  ipCryptNonDeterministic
                      .encrypt(testVector.ip, hexStringToBytes(testVector.key))
                      .sublist(IpCryptNonDeterministic.tweakSize),
                ),
                returnsNormally,
              )
            : expect(
                ipCryptNonDeterministic.encrypt(
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
          ipCryptNonDeterministic.decrypt(
            hexStringToBytes(testVector.output),
            hexStringToBytes(testVector.key),
          ),
          testVector.ip,
        );
      });
    }

    test('encrypt | Invalid input', () {
      expect(
        () => ipCryptNonDeterministic.encrypt('invalid', Uint8List(16)),
        throwsFormatException,
      );
      expect(
        () => ipCryptNonDeterministic.encrypt('1.1.1.1', Uint8List(42)),
        throwsArgumentError,
      );
      expect(
        () => ipCryptNonDeterministic.encrypt(
          '1.1.1.1',
          Uint8List(16),
          Uint8List(42),
        ),
        throwsArgumentError,
      );
    });
    test('decrypt | Invalid input', () {
      expect(
        () => ipCryptNonDeterministic.decrypt(Uint8List(42), Uint8List(16)),
        throwsArgumentError,
      );
      expect(
        () => ipCryptNonDeterministic.decrypt(Uint8List(24), Uint8List(42)),
        throwsArgumentError,
      );
    });
  });
}
