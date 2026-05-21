// Test signing via WASM under Node.js
//   node web/node-sign-test.js <input.apk> <key.pem> <cert.pem>
const fs = require('fs');
const path = require('path');

require(path.join(__dirname, 'wasm_exec.js'));
const go = new Go();

(async () => {
  const wasm = fs.readFileSync(path.join(__dirname, 'apksig.wasm'));
  const inst = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(inst.instance);

  const apkPath = process.argv[2];
  const keyPath = process.argv[3];
  const certPath = process.argv[4];
  if (!apkPath || !keyPath || !certPath) {
    console.error('usage: node node-sign-test.js <apk> <key.pem> <cert.pem>');
    process.exit(2);
  }

  const apk = new Uint8Array(fs.readFileSync(apkPath));
  const keyPEM = new TextEncoder().encode(fs.readFileSync(keyPath, 'utf8'));
  const certPEM = new TextEncoder().encode(fs.readFileSync(certPath, 'utf8'));

  console.log(`version: ${apksigVersion}`);
  console.log(`input: ${apkPath} (${apk.length} bytes)`);

  const opts = { v1: true, v3: true, v31: true, v4: false, align: false,
                 v3MinSdk: 28, v3MaxSdk: 2147483647, v31MinSdk: 33, v31MaxSdk: 2147483647 };
  const r = apksigSign(apk, keyPEM, certPEM, opts);

  if (r.error) { console.error('SIGN ERROR:', r.error); process.exit(1); }

  const outPath = '/tmp/wasm-signed-test.apk';
  fs.writeFileSync(outPath, Buffer.from(r.signedApk));
  console.log(`signed: ${outPath} (${r.signedApk.length} bytes)`);

  // Verify the signed APK
  const vr = apksigVerify(r.signedApk, { minSdk: 24, maxSdk: 35 });
  console.log(`verify: v1=${vr.v1Verified} v2=${vr.v2Verified} v3=${vr.v3Verified} v3.1=${vr.v31Verified} align4kb=${vr.aligned4KB}`);

  // Compare first .so offset with original
  const origBuf = fs.readFileSync(apkPath);
  const signedBuf = Buffer.from(r.signedApk);
  const soName = Buffer.from('lib/arm64-v8a/lib');
  function findSO(buf) {
    const idx = buf.indexOf(soName);
    if (idx < 0) return -1;
    // Walk back to find LFH signature
    for (let off = Math.max(0, idx - 40); off < idx; off++) {
      if (buf[off] === 0x50 && buf[off+1] === 0x4b && buf[off+2] === 0x03 && buf[off+3] === 0x04) {
        return off;
      }
    }
    return -1;
  }
  const origOff = findSO(origBuf);
  const signedOff = findSO(signedBuf);
  console.log(`first .so LFH: orig=${origOff} signed=${signedOff} match=${origOff === signedOff}`);

  // Check MANIFEST.MF offset
  const mfName = Buffer.from('META-INF/MANIFEST.MF');
  function findMF(buf) {
    const idx = buf.indexOf(mfName);
    if (idx < 0) return -1;
    for (let off = Math.max(0, idx - 40); off < idx; off++) {
      if (buf[off] === 0x50 && buf[off+1] === 0x4b && buf[off+2] === 0x03 && buf[off+3] === 0x04) {
        return off;
      }
    }
    return -1;
  }
  const mfOff = findMF(signedBuf);
  console.log(`MANIFEST.MF LFH at: ${mfOff}`);

  process.exit(vr.verified ? 0 : 1);
})();
