#!/usr/bin/env node
// Standalone decrypt tool for an Olive Leaf delivery archive. No dependencies, no network: Node 20+.
//   node decrypt-cli.mjs <archive.enc> <key> [out.zip]
// <key> is the key from the SECOND email (base64url). The output is the ZIP the owner left for you.
import { readFileSync, writeFileSync } from "node:fs";

// Same algorithm as page.js (the script the download page serves). Format: see README.
export async function decryptArchive(keyBytes, data) {
  const CHUNK = 1048576, TAG = 16, HEADER = 37;
  if (keyBytes.length !== 32 || data.length < HEADER + TAG || data[0] !== 0x4f || data[1] !== 0x4c || data[2] !== 0x41 || data[3] !== 0x31 || data[4] !== 1) throw new Error("bad");
  const header = data.subarray(0, HEADER);
  const base = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: header.subarray(5), info: new TextEncoder().encode("olive-leaf delivery v1") }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const parts = [];
  let total = 0;
  for (let at = HEADER, i = 0; at < data.length; i++) {
    const end = Math.min(at + CHUNK + TAG, data.length);
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setUint32(7, i);
    iv[11] = end === data.length ? 1 : 0; // last-chunk flag: a cut-off or extended file fails to authenticate
    const p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: header }, key, data.subarray(at, end)));
    parts.push(p); total += p.length; at = end;
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const [file, keyText, out = "olive-leaf.zip"] = process.argv.slice(2);
  if (!file || !keyText) { console.error("usage: node decrypt-cli.mjs <archive.enc> <key> [out.zip]"); process.exit(2); }
  try {
    const key = new Uint8Array(Buffer.from(keyText.trim(), "base64url"));
    writeFileSync(out, await decryptArchive(key, new Uint8Array(readFileSync(file))));
    console.log(`Saved ${out}`);
  } catch {
    console.error("Could not decrypt: wrong key, or the file is damaged or incomplete.");
    process.exit(1);
  }
}
