---
title: "Docker forensics (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "docker", "forensics"]
summary: "Personal note: Docker forensics (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Docker forensics.md"
---

```bash
~/ctf/hackropole/forensics/Layer-Cake/part2 » docker-layer-extract --imagefile image.tar list
Layer 0:
  Command: `/bin/sh -c #(nop) ADD file:37a76ec18f9887751cd8473744917d08b7431fc4085097bb6a09d81b41775473 in / `
  ID: d4fc045c9e3a848011de66f34b81f052d4f2c15a17bb196d637e526349601820
  ImageLayerPath: blobs/sha256/d4fc045c9e3a848011de66f34b81f052d4f2c15a17bb196d637e526349601820
  Pax Headers: false
Layer 1:
  Command: `/bin/sh -c #(nop)  CMD ["/bin/sh"]`
  ID: eebed19322aaa0082058596cc4cff6c33253f1ce4327e9ae4399edb2f657242e
  ImageLayerPath: blobs/sha256/eebed19322aaa0082058596cc4cff6c33253f1ce4327e9ae4399edb2f657242e
  Pax Headers: false
Layer 2:
  Command: `COPY secret /tmp # buildkit`
  ID: fe62c480fd0c4bba858571806e7474fa5aa061ce78292de1988db0cd54d494b6
  ImageLayerPath: blobs/sha256/fe62c480fd0c4bba858571806e7474fa5aa061ce78292de1988db0cd54d494b6
  Pax Headers: false
```

```bash
~/ctf/hackropole/forensics/Layer-Cake/part2 » docker-layer-extract --imagefile image.tar extract --layerid eebed19322aaa0082058596cc4cff6c33253f1ce4327e9ae4399edb2f657242e --layerfile secret3.tar
```

```bash
~/ctf/hackropole/forensics/Layer-Cake/part2 » cd extracted
~/ctf/hackropole/forensics/Layer-Cake/part2/extracted » tar xvf ../secret3.tar
tmp/
tmp/secret
~/ctf/hackropole/forensics/Layer-Cake/part2/extracted »
~/ctf/hackropole/forensics/Layer-Cake/part2/extracted » cat tmp/secret
FCSC{b38095916b2b578109cbf35b8be713b04a64b2b2df6d7325934be63b7566be3b}
```

---

*From your own notes: `Forensics/Docker forensics.md`*
