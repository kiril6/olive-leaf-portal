# Olive Leaf delivery portal: decrypt code

When someone leaves you a message through Olive Leaf, you get two emails: one with a download link, one with a key. The link's page decrypts the file **in your browser**. This repository is that code, so you can read it, check that the page you were served is the page published here, or skip the page and decrypt on your own computer.

It is only the decrypt side. The app and the server are not in this repository.

## What the page does

1. You paste the key from the second email.
2. The browser downloads the encrypted file from the same site (`.../archive`).
3. It decrypts the file with the key, in memory, and saves `olive-leaf.zip`.

The key and the decrypted data are never sent anywhere. The page's `Content-Security-Policy` allows requests to its own site only, and pins its one script by hash. The script is [`page.js`](page.js).

## Check the page you were served

The hash of `page.js` is in [`page.js.sha256`](page.js.sha256):

```
1b83fe0cc561ac1fc741bdea064368664d7a6ac087d0bffb050a7c87ed3e8872
```

The page's `Content-Security-Policy` header carries the same hash in base64: `script-src 'sha256-G4P+DMVhrB/HQb3qBkNoZk16asCH0L/7BQp8h+0+iHI='`. To hash the script in a link you received:

```bash
curl -s "<your link>" | python3 -c "import sys,re,hashlib;s=re.search(r'<script>(.*?)</script>',sys.stdin.read(),re.S).group(1);print(hashlib.sha256(s.encode()).hexdigest())"
```

If it differs from the line above, do not enter your key on that page. Use the tool below instead.

## Decrypt on your own computer (no page involved)

Needs Node 20 or newer. Download the encrypted file from the link (add `/archive` to the link's address), then:

```bash
node decrypt-cli.mjs olive-leaf.enc "<key from the second email>" olive-leaf.zip
```

It reads the file, writes the ZIP, and does not touch the network. A wrong key, a damaged file or an incomplete file all fail the same way and write nothing.

## File format

| Part | Bytes |
| --- | --- |
| Magic `OLA1` | 4 |
| Version (`1`) | 1 |
| Salt | 32 |
| Chunks: up to 1 MiB of data each, then a 16-byte tag | |

- Key: HKDF-SHA256 over the 32-byte delivery key, with the salt above and the info string `olive-leaf delivery v1`, giving an AES-256-GCM key.
- Each chunk is AES-GCM with the whole 37-byte header as associated data. The 12-byte nonce is an 11-byte big-endian chunk counter plus one byte that is `1` only on the last chunk.
- So a changed header, a reordered, removed or added chunk, or a cut-off or extended file does not authenticate.

`node test.mjs` checks both the tool and `page.js` against a file made by the app's own encryption code.

## What this does not prove

It shows what the page does with your key. It does not show that the server will always serve this page. A server could be changed to serve a different one, which is why the hash check and the standalone tool exist. Using the tool on a copy of the file is the strongest option.

## License

MIT, see [LICENSE](LICENSE).
