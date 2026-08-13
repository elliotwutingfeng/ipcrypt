import 'dart:js_interop';
import 'dart:typed_data';

import 'package:ipcrypt/src/core/random_bytes_vm.dart' as vm;

const bool isDart2JS = bool.fromEnvironment('dart.tool.dart2js');

@JS()
@staticInterop
class Process;

@JS()
@staticInterop
class Versions;

@JS('process')
external Process? get _process;

extension on Process {
  external Versions? get versions;
}

extension on Versions {
  external JSAny get node;
}

bool get isNodeDart2JS => _process?.versions?.node != null && isDart2JS;

@JS()
external NodeCrypto require(String id);

extension type NodeCrypto._(JSObject _) implements JSObject {
  external JSUint8Array randomBytes(int size);
}

/// Generate [size] cryptographically secure random bytes.
Uint8List randomBytes(int size) => isNodeDart2JS
    ? require('crypto').randomBytes(size).toDart
    : vm.randomBytes(size);
