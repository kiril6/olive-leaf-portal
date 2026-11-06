// node test.mjs — checks the standalone tool AND the exact script the page serves against a vector made by the app.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { decryptArchive } from "./decrypt-cli.mjs";

// key = 32 x 0x09, salt = 32 x 0x03, plaintext "hello olive leaf" (made by the app's archiveCrypto.js)
const vec = new Uint8Array(Buffer.from("T0xBMQEDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4PZkyZU/lO7UoQe36KXDz+mAPTFdBcYNI9/CgNZvF1S", "base64"));
const key = new Uint8Array(32).fill(9);
const page = readFileSync(new URL("./page.js", import.meta.url), "utf8");
const pageFn = new Function(`${page.split("\ndocument.getElementById")[0]}\nreturn decryptArchive;`)();

for (const [name, fn] of [["decrypt-cli.mjs", decryptArchive], ["page.js", pageFn]]) {
  assert.equal(new TextDecoder().decode(await fn(key, vec)), "hello olive leaf", name);
  await assert.rejects(fn(new Uint8Array(32).fill(8), vec), name + " wrong key");
  const bad = vec.slice(); bad[bad.length - 1] ^= 1;
  await assert.rejects(fn(key, bad), name + " tampered");
  await assert.rejects(fn(key, vec.subarray(0, vec.length - 1)), name + " truncated");
  console.log("  ok  " + name);
}
const want = readFileSync(new URL("./page.js.sha256", import.meta.url), "utf8").split(/\s+/)[0];
assert.equal(createHash("sha256").update(page).digest("hex"), want, "page.js.sha256 matches page.js");
console.log("  ok  page.js hash file");
