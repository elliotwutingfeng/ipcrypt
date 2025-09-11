/// A Dart library for IP address encryption and obfuscation.
///
/// IPCrypt provides four different methods for IP address encryption:
///
/// **Deterministic Encryption**: Uses AES-128 in a deterministic mode, where
/// the same input always produces the same output for a given key. This is
/// useful when you need to consistently map IP addresses to encrypted values.
///
/// **Non-Deterministic Encryption**: Uses KIASU-BC, a tweakable block cipher,
/// to provide non-deterministic encryption. This means the same input can
/// produce different outputs, providing better privacy protection.
///
/// **Extended Non-Deterministic Encryption**: An enhanced version of
/// non-deterministic encryption that uses a larger key and tweak size
/// for increased security.
///
/// **Prefix-Preserving Encryption**: Uses a dual AES-128 construction to
/// encrypt IP addresses while preserving their prefix structure. This is
/// useful for maintaining network topology information while protecting
/// individual addresses.
library;

export 'src/core/utils.dart';
export 'src/ipcrypt_base.dart';
