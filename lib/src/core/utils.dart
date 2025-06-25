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
  bool isIPv4Mapped = true;
  for (int index = 0; index < 12; index++) {
    if (bytes[index] != (index < 10 ? 0x00 : 0xff)) {
      isIPv4Mapped = false;
      break;
    }
  }
  if (isIPv4Mapped) {
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
  final Random random = Random.secure();
  return Uint8List.fromList(
    List.generate(length, (_) => random.nextInt(256), growable: false),
  );
}

/// XOR two byte arrays of equal length.
Uint8List xorBytes(final Uint8List a, final Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError('Both byte arrays must have the same length.');
  }
  return Uint8List.fromList(
    List.generate(a.length, (final int i) => a[i] ^ b[i], growable: false),
  );
}

/// Convert hex string to bytes in big-endian order.
Uint8List hexStringToBytes(final String hexString) {
  if (hexString.length.isOdd) {
    throw ArgumentError('Length of hex string must be even.');
  }
  return Uint8List.fromList([
    for (int i = 0; i < hexString.length; i += 2)
      int.parse(hexString.substring(i, i + 2), radix: 16),
  ]);
}

/// Convert bytes in big-endian order to hex string.
String bytesToHexString(final Uint8List bytes) => bytes
    .map((final int byte) => byte.toRadixString(16).padLeft(2, '0'))
    .join();
