async function decryptArchive(keyBytes, data) {
	const CHUNK = 1048576, TAG = 16, HEADER = 37;
	if (keyBytes.length !== 32 || data.length < HEADER + TAG || data[0] !== 79 || data[1] !== 76 || data[2] !== 65 || data[3] !== 49 || data[4] !== 1) throw new Error("bad");
	const header = data.subarray(0, HEADER);
	const base = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveKey"]);
	const key = await crypto.subtle.deriveKey({
		name: "HKDF",
		hash: "SHA-256",
		salt: header.subarray(5),
		info: new TextEncoder().encode("olive-leaf delivery v1")
	}, base, {
		name: "AES-GCM",
		length: 256
	}, false, ["decrypt"]);
	const parts = [];
	let total = 0;
	for (let at = HEADER, i = 0; at < data.length; i++) {
		const end = Math.min(at + CHUNK + TAG, data.length);
		const iv = new Uint8Array(12);
		new DataView(iv.buffer).setUint32(7, i);
		iv[11] = end === data.length ? 1 : 0;
		const p = new Uint8Array(await crypto.subtle.decrypt({
			name: "AES-GCM",
			iv,
			additionalData: header
		}, key, data.subarray(at, end)));
		parts.push(p);
		total += p.length;
		at = end;
	};
	const out = new Uint8Array(total);
	let o = 0;
	for (let k = 0; k < parts.length; k++) {
		out.set(parts[k], o);
		o += parts[k].length;
	};
	return out;
}
document.getElementById("go").onclick = async () => {
  const msg = document.getElementById("msg"), raw = document.getElementById("key").value.trim();
  msg.textContent = "Working…";
  try {
    const s = raw.replace(/-/g, "+").replace(/_/g, "/"), bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
    const res = await fetch(location.pathname + "/archive");
    if (!res.ok) throw new Error("fetch");
    const zip = await decryptArchive(Uint8Array.from(bin, (c) => c.charCodeAt(0)), new Uint8Array(await res.arrayBuffer()));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([zip], { type: "application/zip" }));
    a.download = "olive-leaf.zip";
    a.click();
    msg.textContent = "Done. The file was saved as olive-leaf.zip.";
  } catch (e) {
    msg.textContent = "That password did not work, or the file could not be downloaded. Check the second email and try again.";
  }
};