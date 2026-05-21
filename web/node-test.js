// node-test.js — runs the WASM module under Node to verify it works headless.
//   node web/node-test.js path/to/file.apk
const fs = require('fs');
const path = require('path');

require(path.join(__dirname, 'wasm_exec.js'));
const go = new Go();

(async () => {
  const wasm = fs.readFileSync(path.join(__dirname, 'apksig.wasm'));
  const apkPath = process.argv[2];
  if (!apkPath) { console.error('usage: node node-test.js <apk>'); process.exit(2); }
  const apk = fs.readFileSync(apkPath);

  const inst = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(inst.instance);

  const t0 = process.hrtime.bigint();
  const result = apksigVerify(new Uint8Array(apk), { minSdk: 24, maxSdk: 35 });
  const dt = Number(process.hrtime.bigint() - t0) / 1e6;

  console.log(JSON.stringify(result, null, 2));
  console.log(`# verified=${result.verified} in ${dt.toFixed(0)} ms`);
  process.exit(result.verified ? 0 : 1);
})();
