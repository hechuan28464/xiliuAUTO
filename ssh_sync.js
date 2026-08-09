const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');
const os = require('os');

const vsContent = fs.readFileSync(path.join(__dirname, 'app', 'knowledge', 'vector_store.py'), 'utf-8');
const reqContent = fs.readFileSync(path.join(__dirname, 'requirements.txt'), 'utf-8');
const authContent = fs.readFileSync(path.join(__dirname, 'app', 'auth', '__init__.py'), 'utf-8');

const vsB64 = Buffer.from(vsContent).toString('base64');
const reqB64 = Buffer.from(reqContent).toString('base64');
const authB64 = Buffer.from(authContent).toString('base64');

const cmd = [
  `echo '${vsB64}' | base64 -d > /root/xiliuauto/app/knowledge/vector_store.py`,
  `echo '${reqB64}' | base64 -d > /root/xiliuauto/requirements.txt`,
  `echo '${authB64}' | base64 -d > /root/xiliuauto/app/auth/__init__.py`,
  `echo FILES-SYNCED`,
  `cd /root/xiliuauto && docker compose up -d --build 2>&1 | tail -10`,
  `echo BUILD-DONE`,
  `sleep 12`,
  `curl -s -o /dev/null -w '%{http_code}' http://localhost:18800/`,
  `echo ""`,
  `docker logs xiliuauto 2>&1 | tail -8`,
  `echo ALL-DONE`,
].join(' && ');

const conn = new Client();
conn.on('ready', () => {
  conn.exec(cmd, (err, stream) => {
    if (err) { console.error(err); conn.end(); process.exit(1); }
    stream.on('close', () => { conn.end(); });
    stream.on('data', (d) => process.stdout.write(d));
    stream.stderr.on('data', (d) => process.stderr.write(d));
  });
});
conn.on('error', (err) => { console.error('SSH error:', err.message); process.exit(1); });
conn.on('close', () => process.exit(0));
conn.connect({
  host: '154.37.215.195', port: 22, username: 'root',
  privateKey: fs.readFileSync(path.join(os.homedir(), '.ssh', 'xiliu_rsa2'), 'utf-8'),
  passphrase: 'xiliu', readyTimeout: 30000,
});
