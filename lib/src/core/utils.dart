import 'dart:math';
import 'dart:typed_data';

/// Convert an IP address string to its 16-byte representation.
/// Handles both IPv4 and IPv6 addresses, with IPv4 being mapped to IPv6.
Uint8List ipToBytes(final String ip) {
  // Try parsing as IPv4.
  try {
    final List<int> maybeIPv4 = Uri.parseIPv4Address(ip);
    return (BytesBuilder(copy: false)
          ..add(Uint8List(10))
          ..addByte(0xff)
          ..addByte(0xff)
          ..add(maybeIPv4))
        .toBytes();
  } on FormatException {
    //
  }
  // Try parsing as IPv6.
  try {
    return Uint8List.fromList(Uri.parseIPv6Address(ip));
  } on FormatException {
    //
  }
  throw FormatException('$ip is not a valid IP address.');
}

/// Convert a 16-byte representation back to an IP address string.
/// Automatically detects and handles both IPv4-mapped and IPv6 addresses.
String bytesToIp(final Uint8List bytes) {
  if (bytes.length != 16) {
    throw ArgumentError('Input must be 16 bytes.');
  }

  // Check if first 12 bytes match IPv4-mapped IPv6 format (::ffff:x.x.x.x).
  if (isIPv4(bytes)) {
    return bytes.skip(12).join('.');
  }

  // Handle IPv6.
  final List<String> parts = List.generate(
    8,
    (final int i) => ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toRadixString(16),
    growable: false,
  );

  // Find best zero compression opportunity.
  ({int start, int length}) findLongestZeroRun(final List<String> parts) {
    int longestStart = -1, longestLength = 0;
    int currentStart = -1, currentLength = 0;

    for (int i = 0; i < parts.length; i++) {
      if (parts[i] == '0') {
        if (currentLength == 0) {
          currentStart = i;
        }
        currentLength++;
        continue;
      }
      if (currentLength > longestLength) {
        longestStart = currentStart;
        longestLength = currentLength;
      }
      currentStart = -1;
      currentLength = 0;
    }

    if (currentLength > longestLength) {
      longestStart = currentStart;
      longestLength = currentLength;
    }

    return (start: longestStart, length: longestLength);
  }

  final ({int start, int length}) zeroRun = findLongestZeroRun(parts);

  if (zeroRun.length >= 2) {
    final Iterable<String> before = parts.take(zeroRun.start);
    final Iterable<String> after = parts.skip(zeroRun.start + zeroRun.length);

    return '${before.join(':')}::${after.join(':')}';
  }

  return parts.join(':');
}

/// Generate cryptographically secure random bytes.
Uint8List randomBytes(final int length) {
  if (length <= 0) {
    throw RangeError('Number of bytes to generate must be positive.');
  }
  final Uint8List bytes = Uint8List(length);
  final Random random = Random.secure();
  for (int i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

/// XOR two byte arrays of equal length.
Uint8List xorBytes(final Uint8List a, final Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError('Both byte arrays must have the same length.');
  }
  final Uint8List bytes = Uint8List(a.length);
  for (int i = 0; i < a.length; i++) {
    bytes[i] = a[i] ^ b[i];
  }
  return bytes;
}

/// Convert hex string to bytes in big-endian order.
Uint8List hexStringToBytes(final String hexString) {
  if (hexString.length.isOdd) {
    throw ArgumentError('Length of hex string must be even.');
  }
  final Uint8List result = Uint8List(hexString.length ~/ 2);
  for (int i = 0; i < hexString.length; i += 2) {
    for (int j = i; j < i + 2; j++) {
      final int code = hexString.codeUnitAt(j);
      if (!(code >= 48 && code <= 57) && // '0'-'9'
          !(code >= 65 && code <= 70) && // 'A'-'F'
          !(code >= 97 && code <= 102)) //  'a'-'f'
      {
        throw ArgumentError(
          "Only characters ('0'-'9'), ('A'-'F'), and ('a'-'f')"
          ' are allowed in hex string.',
        );
      }
    }
    result[i ~/ 2] = int.parse(hexString.substring(i, i + 2), radix: 16);
  }
  return result;
}

/// Convert bytes in big-endian order to hex string.
String bytesToHexString(final Uint8List bytes) => bytes
    .map((final int byte) => byte.toRadixString(16).padLeft(2, '0'))
    .join();

/// Check if the IP address is IPv4 based on its byte length.
/// IPv4 addresses are 4 bytes, IPv6 addresses are 16 bytes.
bool isIPv4(final Uint8List bytes16) =>
    bytes16[10] == 0xff &&
    bytes16[11] == 0xff &&
    Iterable.generate(
      10,
      (final int i) => bytes16[i],
    ).every((final int b) => b == 0);

/// Pad prefix for prefix_len_bits=96 (IPv4).
/// Result: 00000001 00...00 0000ffff (separator at pos 96, then 96 bits).
Uint8List padPrefix96() {
  final Uint8List padded = Uint8List(16);
  padded[3] = 0x01; // Set bit at position 96 (bit 0 of byte 3)
  padded[14] = 0xFF;
  padded[15] = 0xFF;
  return padded;
}

/// Pad prefix for prefix_len_bits=0 (IPv6).
/// Sets separator bit at position 0 (LSB of byte 15).
Uint8List padPrefix0() {
  final Uint8List padded = Uint8List(16);
  padded[15] = 0x01; // Set bit at position 0 (LSB of byte 15)
  return padded;
}

/// Extract bit at position from N-byte array.
/// Position: 0 = LSB of last byte, n = (N * 8) - 1 = MSB of first byte.
int getBit(final Uint8List data, final int position) {
  final int byteIndex = data.length - 1 - position ~/ 8;
  final int bitIndex = position % 8;
  return (data[byteIndex] >> bitIndex) & 1;
}

/// Set bit at position in N-byte array.
/// Position: 0 = LSB of last byte, n = (N * 8) - 1 = MSB of first byte.
void setBit(final Uint8List data, final int position, final int value) {
  final int byteIndex = data.length - 1 - position ~/ 8;
  final int bitIndex = position % 8;

  if (value != 0) {
    data[byteIndex] |= 1 << bitIndex;
  } else {
    data[byteIndex] &= ~(1 << bitIndex);
  }
}

/// Shift a N-byte array one bit to the left.
/// The most significant bit is lost, and a zero bit is shifted in
/// from the right.
Uint8List shiftLeftOneBit(final Uint8List data) {
  final Uint8List result = Uint8List(data.length);
  int carry = 0;

  // Process from least significant byte (byte N) to most significant (byte 0)
  for (int i = data.length - 1; i >= 0; i--) {
    // Current byte shifted left by 1, with carry from previous byte
    result[i] = ((data[i] << 1) | carry) & 0xFF;
    // Extract the bit that will be carried to the next byte
    carry = (data[i] >> 7) & 1;
  }

  return result;
}

/// Check if 2 Uint8Lists are equal by comparing them element-by-element.
bool equalBytes(final Uint8List a, final Uint8List b) =>
    a.length == b.length &&
    Iterable.generate(
      a.length,
      (final int i) => a[i] == b[i],
    ).every((final bool isEqual) => isEqual);
