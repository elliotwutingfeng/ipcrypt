final class TestVector {
  const TestVector({
    required this.key,
    required this.ip,
    required this.tweak,
    required this.output,
  });

  final String key, ip, tweak, output;
}

final class TestVectors {
  static const List<TestVector> deterministic = [
    TestVector(
      key: '0123456789abcdeffedcba9876543210',
      ip: '0.0.0.0',
      tweak: '', // not used.
      output: 'bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb',
    ),
    TestVector(
      key: '1032547698badcfeefcdab8967452301',
      ip: '255.255.255.255',
      tweak: '', // not used.
      output: 'aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3c',
      ip: '192.0.2.1',
      tweak: '', // not used.
      output: '1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777',
    ),
  ];
  static const List<TestVector> nd = [
    TestVector(
      key: '0123456789abcdeffedcba9876543210',
      ip: '0.0.0.0',
      tweak: '08e0c289bff23b7c',
      output: '08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16',
    ),
    TestVector(
      key: '1032547698badcfeefcdab8967452301',
      ip: '192.0.2.1',
      tweak: '21bd1834bc088cd2',
      output: '21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3c',
      ip: '2001:db8::1',
      tweak: 'b4ecbe30b70898d7',
      output: 'b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3c',
      ip: '2001:db8::1',
      tweak: '', // tweak not provided.
      output: '', // not used.
    ),
  ];
  static const List<TestVector> ndx = [
    TestVector(
      key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ip: '0.0.0.0',
      tweak: '21bd1834bc088cd2b4ecbe30b70898d7',
      output:
          '21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5',
    ),
    TestVector(
      key: '1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210',
      ip: '192.0.2.1',
      tweak: '08e0c289bff23b7cb4ecbe30b70898d7',
      output:
          '08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b',
      ip: '2001:db8::1',
      tweak: '21bd1834bc088cd2b4ecbe30b70898d7',
      output:
          '21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b',
      ip: '2001:db8::1',
      tweak: '', // tweak not provided.
      output: '', // not used.
    ),
  ];
  static const List<TestVector> pfx = [
    // IPv4
    TestVector(
      key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ip: '0.0.0.0',
      tweak: '', // not used.
      output: '151.82.155.134',
    ),
    TestVector(
      key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ip: '255.255.255.255',
      tweak: '', // not used.
      output: '94.185.169.89',
    ),
    TestVector(
      key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ip: '192.0.2.1',
      tweak: '', // not used.
      output: '100.115.72.131',
    ),
    // IPv6
    TestVector(
      key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
      ip: '2001:db8::1',
      tweak: '', // not used.
      output: 'c180:5dd4:2587:3524:30ab:fa65:6ab6:f88',
    ),
    // IPv4 with second key
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '10.0.0.47',
      tweak: '', // not used.
      output: '19.214.210.244',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '10.0.0.129',
      tweak: '', // not used.
      output: '19.214.210.80',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '10.0.0.234',
      tweak: '', // not used.
      output: '19.214.210.30',
    ),
    // IPv4 /16 vs /24
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '172.16.5.193',
      tweak: '', // not used.
      output: '210.78.229.136',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '172.16.97.42',
      tweak: '', // not used.
      output: '210.78.179.241',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '172.16.248.177',
      tweak: '', // not used.
      output: '210.78.121.215',
    ),
    // IPv6 /64
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8::a5c9:4e2f:bb91:5a7d',
      tweak: '', // not used.
      output: '7cec:702c:1243:f70:1956:125:b9bd:1aba',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8::7234:d8f1:3c6e:9a52',
      tweak: '', // not used.
      output: '7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8::f1e0:937b:26d4:8c1a',
      tweak: '', // not used.
      output: '7cec:702c:1243:f70:443c:c8e:6a62:b64d',
    ),
    // IPv6 /32 vs /48
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8:3a5c:0:e7d1:4b9f:2c8a:f673',
      tweak: '', // not used.
      output: '7cec:702c:3503:bef:e616:96bd:be33:a9b9',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8:9f27:0:b4e2:7a3d:5f91:c8e6',
      tweak: '', // not used.
      output: '7cec:702c:a504:b74e:194a:3d90:b047:2d1a',
    ),
    TestVector(
      key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
      ip: '2001:db8:d8b4:0:193c:a5e7:8b2f:46d1',
      tweak: '', // not used.
      output: '7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb',
    ),
  ];
}
