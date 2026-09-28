# Vendored source provenance

Everything under `vendor/` belongs to its original authors and is redistributed
here under the licence shown, with the upstream `LICENSE` file preserved alongside it.
Nothing has been relicensed, and no copyright headers were removed.

| Repository | Commit | Licence | Files | Size | What was taken |
|---|---|---|---|---|---|
| [jvdsn/crypto-attacks](https://github.com/jvdsn/crypto-attacks) | `d42a3df980bf` | MIT | 100 | 0.3 MB | attacks, shared, README.md, LICENSE |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | `c332c7be1b27` | MIT | 126 | 2.8 MB | ctf-ai-ml, ctf-crypto, ctf-forensics, ctf-misc, ctf-osint, ctf-pwn, ctf-reverse, ctf-web, ctf-blockchain, ctf-mobile, ctf-hardware, ctf-cloud, ctf-stego, README.md, LICENSE |
| [GTFOBins/GTFOBins.github.io](https://github.com/GTFOBins/GTFOBins.github.io) | `acd524623f9c` | GPL-3.0 | 479 | 0.2 MB | _gtfobins, LICENSE, README.md |
| [shellphish/how2heap](https://github.com/shellphish/how2heap) | `02da6aa26a44` | MIT | 189 | 0.9 MB | glibc_2.39, glibc_2.38, glibc_2.36, glibc_2.35, glibc_2.34, glibc_2.31, glibc_2.27, glibc_2.26, glibc_2.23, README.md, LICENSE |
| [RsaCtfTool/RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) | `8c9a9ecb85ca` | MIT | 97 | 0.4 MB | src/RsaCtfTool/attacks, src/RsaCtfTool/lib, src/RsaCtfTool/sage, README.md, LICENSE.txt |

## Not vendored (no upstream licence)

These are referenced by link and attribution only — no code is copied:

- [defund/coppersmith](https://github.com/defund/coppersmith) — Coppersmith's method for multivariate polynomials in SageMath — the standard drop-in `small_roots` used across CTF crypto.
- [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts) — A collection of Frida instrumentation scripts for Android and iOS.

## Removing something

If you are an author and want your work out of this mirror, delete the directory under
`vendor/` and the matching `content/scripts/**/vendor-*.md` wrappers, then re-run
`ctfbrain index`.
