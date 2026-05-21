// Test signing via WASM with a JKS or PKCS#12 keystore under Node.js.
//   node web/node-keystore-test.js <input.apk> <keystore> <storepass> [alias]
const fs = require('fs');
const path = require('path');

require(path.join(__dirname, 'wasm_exec.js'));
const go = new Go();

(async () => {
  const wasm = fs.readFileSync(path.join(__dirname, 'apksig.wasm'));
  const inst = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(inst.instance);

  const apkPath = process.argv[2];
  const ksPath = process.argv[3];
  const storePass = process.argv[4];
  const alias = process.argv[5] || '';
  if (!apkPath || !ksPath || storePass === undefined) {
    console.error('usage: node node-keystore-test.js <apk> <keystore> <storepass> [alias]');
    process.exit(2);
  }

  const apk = new Uint8Array(fs.readFileSync(apkPath));
  const ks = new Uint8Array(fs.readFileSync(ksPath));

  console.log(`version: ${apksigVersion}`);
  console.log(`input: ${apkPath} (${apk.length} bytes)`);
  console.log(`keystore: ${ksPath} (${ks.length} bytes)`);

  const opts = { storePass, alias, v1: true, v3: true, v31: true, v4: false, align: true,
                 v3MinSdk: 28, v3MaxSdk: 2147483647, v31MinSdk: 33, v31MaxSdk: 2147483647 };
  const r = apksigSignKeystore(apk, ks, opts);
  if (r.error) { console.error('SIGN ERROR:', r.error); process.exit(1); }

  const outPath = '/tmp/wasm-keystore-signed.apk';
  fs.writeFileSync(outPath, Buffer.from(r.signedApk));
  console.log(`signed: ${outPath} (${r.signedApk.length} bytes)`);

  const vr = apksigVerify(r.signedApk, { minSdk: 24, maxSdk: 35 });
  console.log(`verify: v1=${vr.v1Verified} v2=${vr.v2Verified} v3=${vr.v3Verified} v3.1=${vr.v31Verified} align4kb=${vr.aligned4KB}`);

  process.exit(vr.verified ? 0 : 1);
})();
