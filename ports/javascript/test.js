// Smoke test for the Node port. Run: node ports/javascript/test.js
// Uses only the Node stdlib assert module — no test runner / deps required.
import assert from "assert";
import { detect } from "./index.js";

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log("ok - " + name);
}

check("detects okhttp with version + purl", () => {
  const comps = detect(["libs/okhttp-4.9.0.jar", "okhttp3/OkHttpClient.class"]);
  const ok = comps.find((c) => c.name === "okhttp");
  assert(ok, "okhttp detected");
  assert.strictEqual(ok.version, "4.9.0");
  assert.strictEqual(ok.purl, "pkg:maven/com.squareup.okhttp3/okhttp@4.9.0");
});

check("detects native openssl", () => {
  const comps = detect(["lib/arm64-v8a/libssl.so.1.1.1k"]);
  assert(comps.some((c) => c.name === "openssl"));
});

check("no false positives on benign paths", () => {
  const comps = detect(["AndroidManifest.xml", "classes.dex"]);
  assert.strictEqual(comps.length, 0);
});

check("components sorted by name", () => {
  const comps = detect(["okhttp3/X.class", "com/google/gson/Gson.class"]);
  assert(comps.length >= 2);
  assert(comps[0].name <= comps[1].name);
});

console.log(`\n${passed} test(s) passed`);
