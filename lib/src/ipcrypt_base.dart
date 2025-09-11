import 'package:ipcrypt/src/methods/ipcrypt_deterministic.dart';
import 'package:ipcrypt/src/methods/ipcrypt_nd.dart';
import 'package:ipcrypt/src/methods/ipcrypt_ndx.dart';
import 'package:ipcrypt/src/methods/ipcrypt_pfx.dart';

/// **Deterministic Encryption**: Uses AES-128 in a deterministic mode, where
/// the same input always produces the same output for a given key. This is
/// useful when you need to consistently map IP addresses to encrypted values.
const IpCryptDeterministic ipCryptDeterministic = IpCryptDeterministic();

/// **Non-Deterministic Encryption**: Uses KIASU-BC, a tweakable block cipher,
/// to provide non-deterministic encryption. This means the same input can
/// produce different outputs, providing better privacy protection.
const IpCryptNonDeterministic ipCryptNonDeterministic =
    IpCryptNonDeterministic();

/// **Extended Non-Deterministic Encryption**: An enhanced version of
/// non-deterministic encryption that uses a larger key and tweak size
/// for increased security.
const IpCryptExtendedNonDeterministic ipCryptExtendedNonDeterministic =
    IpCryptExtendedNonDeterministic();

/// **Prefix-Preserving Encryption**: Uses a dual AES-128 construction to
/// encrypt IP addresses while preserving their prefix structure. This is
/// useful for maintaining network topology information while protecting
/// individual addresses.
const IpCryptPrefixPreserving ipCryptPrefixPreserving =
    IpCryptPrefixPreserving();
