import 'dart:typed_data';

const int stateSize = 16; // Size of the state array in bytes (4x4 matrix).
const int wordSize = 4; // Size of a word in bytes.
const int expandedKeySize =
    176; // Size of the expanded key (11 round keys * 16 bytes).

/// Galois Field (GF(2^8)) constants for MixColumns operation.
const int gfModulus = 0x1b; // Irreducible polynomial: x^8 + x^4 + x^3 + x + 1.
const int gfHighBit = 0x80; // Used for carry detection in GF multiplication.

/// MixColumns transformation matrix.
abstract class MixCols {
  abstract final int m00;
  abstract final int m01;
  abstract final int m02;
  abstract final int m03;
  abstract final int m10;
  abstract final int m11;
  abstract final int m12;
  abstract final int m13;
  abstract final int m20;
  abstract final int m21;
  abstract final int m22;
  abstract final int m23;
  abstract final int m30;
  abstract final int m31;
  abstract final int m32;
  abstract final int m33;
}

/// Forward MixColumns matrix coefficients.
class MixColsForward implements MixCols {
  const MixColsForward();

  @override
  final int m00 = 0x02;
  @override
  final int m01 = 0x03;
  @override
  final int m02 = 0x01;
  @override
  final int m03 = 0x01;
  @override
  final int m10 = 0x01;
  @override
  final int m11 = 0x02;
  @override
  final int m12 = 0x03;
  @override
  final int m13 = 0x01;
  @override
  final int m20 = 0x01;
  @override
  final int m21 = 0x01;
  @override
  final int m22 = 0x02;
  @override
  final int m23 = 0x03;
  @override
  final int m30 = 0x03;
  @override
  final int m31 = 0x01;
  @override
  final int m32 = 0x01;
  @override
  final int m33 = 0x02;
}

/// Inverse MixColumns matrix coefficients.
class MixColsInverse implements MixCols {
  const MixColsInverse();

  @override
  final int m00 = 0x0e;
  @override
  final int m01 = 0x0b;
  @override
  final int m02 = 0x0d;
  @override
  final int m03 = 0x09;
  @override
  final int m10 = 0x09;
  @override
  final int m11 = 0x0e;
  @override
  final int m12 = 0x0b;
  @override
  final int m13 = 0x0d;
  @override
  final int m20 = 0x0d;
  @override
  final int m21 = 0x09;
  @override
  final int m22 = 0x0e;
  @override
  final int m23 = 0x0b;
  @override
  final int m30 = 0x0b;
  @override
  final int m31 = 0x0d;
  @override
  final int m32 = 0x09;
  @override
  final int m33 = 0x0e;
}

final MixCols mixColsForward = MixColsForward();
final MixCols mixColsInverse = MixColsInverse();

/// AES S-box.
final List<int> sbox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
  //
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  //
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  //
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  //
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  //
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  //
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  //
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  //
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  //
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  //
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  //
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  //
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  //
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  //
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  //
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  //
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  //
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  //
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  //
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  //
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  //
  0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box.
final List<int> invSbox = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
  //
  0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  //
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
  //
  0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  //
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
  //
  0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  //
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  //
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  //
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
  //
  0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  //
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
  //
  0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  //
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
  //
  0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  //
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
  //
  0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  //
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
  //
  0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  //
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
  //
  0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  //
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  //
  0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constants.
final List<int> rcon = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  //
];

/// Performs the SubBytes operation on the state array.
/// Applies the S-box substitution to each byte in the state.
void subBytes(final Uint8List state, [final bool inverse = false]) {
  final List<int> sbox_ = inverse ? invSbox : sbox;
  for (int i = 0; i < stateSize; i++) {
    state[i] = sbox_[state[i]];
  }
}

/// Performs the ShiftRows operation on the state array.
/// Each row is cyclically shifted by a different offset.
void shiftRows(final Uint8List state, [final bool inverse = false]) {
  final Uint8List temp = Uint8List(stateSize);
  final List<int> shifts = inverse ? [0, 3, 2, 1] : [0, 1, 2, 3];

  // Row 0: no shift
  temp[0] = state[0];
  temp[4] = state[4];
  temp[8] = state[8];
  temp[12] = state[12];

  // Row 1: shift by 1
  final int row1Shift = shifts[1];
  temp[1] = state[(1 + 4 * row1Shift) % 16];
  temp[5] = state[(5 + 4 * row1Shift) % 16];
  temp[9] = state[(9 + 4 * row1Shift) % 16];
  temp[13] = state[(13 + 4 * row1Shift) % 16];

  // Row 2: shift by 2
  final int row2Shift = shifts[2];
  temp[2] = state[(2 + 4 * row2Shift) % 16];
  temp[6] = state[(6 + 4 * row2Shift) % 16];
  temp[10] = state[(10 + 4 * row2Shift) % 16];
  temp[14] = state[(14 + 4 * row2Shift) % 16];

  // Row 3: shift by 3
  final int row3Shift = shifts[3];
  temp[3] = state[(3 + 4 * row3Shift) % 16];
  temp[7] = state[(7 + 4 * row3Shift) % 16];
  temp[11] = state[(11 + 4 * row3Shift) % 16];
  temp[15] = state[(15 + 4 * row3Shift) % 16];

  state.setAll(0, temp);
}

/// Performs Galois Field multiplication in GF(2^8).
/// Uses the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
int gmul(final int a, final int b) {
  int p = 0;
  int a_ = a;
  int b_ = b;
  for (int i = 0; i < 8; i++) {
    if ((b_ & 1) != 0) p ^= a_;
    final bool highBitSet = (a_ & gfHighBit) != 0;
    a_ = (a_ << 1) & 0xff;
    if (highBitSet) a_ ^= gfModulus;
    b_ >>= 1;
  }
  return p;
}

/// Performs the MixColumns operation on the state array.
/// Each column is treated as a polynomial over GF(2^8) and multiplied
/// by a fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}.
void mixColumns(final Uint8List state, [final bool inverse = false]) {
  final Uint8List temp = Uint8List(stateSize);
  final MixCols coef = inverse ? mixColsInverse : mixColsForward;

  for (int i = 0; i < 4; i++) {
    final int col = i * 4;
    temp[col] =
        gmul(coef.m00, state[col]) ^
        gmul(coef.m01, state[col + 1]) ^
        gmul(coef.m02, state[col + 2]) ^
        gmul(coef.m03, state[col + 3]);

    temp[col + 1] =
        gmul(coef.m10, state[col]) ^
        gmul(coef.m11, state[col + 1]) ^
        gmul(coef.m12, state[col + 2]) ^
        gmul(coef.m13, state[col + 3]);

    temp[col + 2] =
        gmul(coef.m20, state[col]) ^
        gmul(coef.m21, state[col + 1]) ^
        gmul(coef.m22, state[col + 2]) ^
        gmul(coef.m23, state[col + 3]);

    temp[col + 3] =
        gmul(coef.m30, state[col]) ^
        gmul(coef.m31, state[col + 1]) ^
        gmul(coef.m32, state[col + 2]) ^
        gmul(coef.m33, state[col + 3]);
  }

  state.setAll(0, temp);
}

/// Expands a 16-byte key into round keys for AES encryption/decryption.
/// Implements the AES key schedule algorithm.
Uint8List expandKey(final Uint8List key) {
  final Uint8List expandedKey = Uint8List(expandedKeySize)..setAll(0, key);

  int rconIndex = 0;
  for (int i = stateSize; i < expandedKeySize; i += wordSize) {
    // Copy previous word
    final Uint8List temp = expandedKey.sublist(i - wordSize, i);

    // Key schedule core for first word of each round.
    if (i % stateSize == 0) {
      // Rotate word.
      final int t = temp[0];
      temp.setAll(0, temp.sublist(1));
      temp[3] = t;

      // Apply S-box and XOR with round constant.
      for (int j = 0; j < temp.length; j++) {
        temp[j] = sbox[temp[j]];
      }
      temp[0] ^= rcon[rconIndex++];
    }

    // XOR with word 4 positions back.
    for (int j = 0; j < wordSize; j++) {
      expandedKey[i + j] = expandedKey[i - stateSize + j] ^ temp[j];
    }
  }

  return expandedKey;
}

/// Pads an 8-byte tweak to 16 bytes according to KIASU-BC specification.
/// The tweak is padded by placing each 2-byte pair at the start of a
/// 4-byte group, effectively creating a sparse representation where
/// every other byte is zero. This padding scheme is specific to KIASU-BC
/// and helps prevent certain cryptographic attacks.
///
/// Example:
/// Input tweak:  [t0,t1,t2,t3,t4,t5,t6,t7]
/// Padded tweak: [t0,t1,0,0,t2,t3,0,0,t4,t5,0,0,t6,t7,0,0]
Uint8List padTweak(final Uint8List tweak) {
  final Uint8List padded = Uint8List(16);
  for (int i = 0; i < 8; i += 2) {
    padded[i * 2] = tweak[i];
    padded[i * 2 + 1] = tweak[i + 1];
  }
  return padded;
}

/// Encrypts a 16-byte block using KIASU-BC with the given key and tweak.
Uint8List encryptBlockKiasuBc(
  final Uint8List key,
  final Uint8List tweak,
  final Uint8List block,
) {
  // Pad tweak and expand key.
  final Uint8List paddedTweak = padTweak(tweak);
  final Uint8List expandedKey = expandKey(key);
  final Uint8List state = Uint8List.fromList(block); // make a copy.

  // Initial round.
  for (int i = 0; i < 16; i++) {
    state[i] ^= expandedKey[i] ^ paddedTweak[i];
  }

  // Main rounds.
  for (int round = 1; round < 10; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    for (int i = 0; i < 16; i++) {
      state[i] ^= expandedKey[round * 16 + i] ^ paddedTweak[i];
    }
  }

  // Final round.
  subBytes(state);
  shiftRows(state);
  for (int i = 0; i < 16; i++) {
    state[i] ^= expandedKey[160 + i] ^ paddedTweak[i];
  }

  return state;
}

/// Decrypts a 16-byte block using KIASU-BC with the given key and tweak.
Uint8List decryptBlockKiasuBc(
  final Uint8List key,
  final Uint8List tweak,
  final Uint8List block,
) {
  // Pad tweak and expand key.
  final Uint8List paddedTweak = padTweak(tweak);
  final Uint8List expandedKey = expandKey(key);
  final Uint8List state = Uint8List.fromList(block); // make a copy.

  // Initial round.
  for (int i = 0; i < 16; i++) {
    state[i] ^= expandedKey[160 + i] ^ paddedTweak[i];
  }
  shiftRows(state, true);
  subBytes(state, true);

  // Main rounds.
  for (int round = 9; round > 0; round--) {
    for (int i = 0; i < 16; i++) {
      state[i] ^= expandedKey[round * 16 + i] ^ paddedTweak[i];
    }
    mixColumns(state, true);
    shiftRows(state, true);
    subBytes(state, true);
  }

  // Final round.
  for (int i = 0; i < 16; i++) {
    state[i] ^= expandedKey[i] ^ paddedTweak[i];
  }

  return state;
}
