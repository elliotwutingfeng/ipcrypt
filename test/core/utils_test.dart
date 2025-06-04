import 'dart:typed_data';

import 'package:ipcrypt/src/core/utils.dart';
import 'package:test/test.dart';

void main() {
  group('ipToBytes', () {
    test('Valid input', () {
      expect(
        ipToBytes('1.1.1.1'),
        Uint8List.fromList([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 1,
          //
        ]),
      );
      expect(
        ipToBytes('2001:db8::1'),
        Uint8List.fromList([
          0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
          //
        ]),
      );
    });
    test('Invalid input', () {
      expect(() => ipToBytes('invalid'), throwsFormatException);
    });
  });
  group('bytesToIp', () {
    test('Valid input', () {
      expect(
        bytesToIp(
          Uint8List.fromList([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 1,
            //
          ]),
        ),
        '1.1.1.1',
      );
      expect(
        bytesToIp(
          Uint8List.fromList([
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            //
          ]),
        ),
        '2001:db8::1',
      );
      expect(bytesToIp(Uint8List(16)), '::');
      expect(
        bytesToIp(
          Uint8List.fromList([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            //
          ]),
        ),
        '::abcd:1234:5678:9abc',
      );
      expect(
        bytesToIp(
          Uint8List.fromList([
            0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //
          ]),
        ),
        'fd00:1234:5678:9abc::',
      );
    });
    test('Invalid input', () {
      expect(
        () => bytesToIp(Uint8List.fromList([6, 23, 64, 183])),
        throwsArgumentError,
      );
    });
  });
  group('randomBytes', () {
    test('Valid input', () {
      expect(randomBytes(42).length, 42);
    });
    test('Invalid input', () {
      expect(() => randomBytes(-1), throwsRangeError);
    });
  });
  group('xorBytes', () {
    test('Valid input', () {
      expect(
        xorBytes(Uint8List.fromList([]), Uint8List.fromList([])),
        Uint8List.fromList([]),
      );
      expect(
        xorBytes(
          Uint8List.fromList([6, 23, 64, 183]),
          Uint8List.fromList([92, 23, 87, 183]),
        ),
        Uint8List.fromList([90, 0, 23, 0]),
      );
    });
    test('Invalid input', () {
      expect(
        () => xorBytes(
          Uint8List.fromList([6, 23, 64, 183]),
          Uint8List.fromList([92, 23, 87]),
        ),
        throwsArgumentError,
      );
    });
  });
  group('hexStringToBytes', () {
    test('Valid input', () {
      expect(hexStringToBytes(''), Uint8List.fromList([]));
      expect(
        hexStringToBytes('061740b7'),
        Uint8List.fromList([6, 23, 64, 183]),
      );
    });
    test('Invalid input', () {
      expect(() => hexStringToBytes('061740b'), throwsArgumentError);
    });
  });
  group('bytesToHexString', () {
    test('Valid input', () {
      expect(bytesToHexString(Uint8List.fromList([])), '');
      expect(
        bytesToHexString(Uint8List.fromList([6, 23, 64, 183])),
        '061740b7',
      );
    });
  });
}
