---
title: "convert hex - Midnight Sun CTF 2018"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "nodejs", "convert", "hex", "cryptography", "convert-hex"]
summary: "JavaScript component to convert to/from hex strings and byte arrays."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2018/Midnight_Sun_CTF_2018/isoar/node_modules/convert-hex/README.md"
ctf:
  name: "Midnight Sun CTF"
  year: 2018
  challenge: "convert hex"
---

## Source

- **CTF:** Midnight Sun CTF 2018
- **Challenge:** convert hex
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2018/Midnight_Sun_CTF_2018/isoar/node_modules/convert-hex/README.md>

---
convert-hex
===========

JavaScript component to convert to/from hex strings and byte arrays.

AMD/CommonJS compatible.


Install
-------

### Node.js/Browserify

    npm install --save cryptocoin-convert-hex


### Component

    component install cryptocoin/convert-hex


### Bower

    bower install cryptocoin/convert-hex


### Script

```html
<script src="/path/to/convert-hex.js"></script>
```


Usage
-----

(if using script, the global is `convertHex`)

### bytesToHex(bytes)

```js
var convertHex = require('convert-hex')

var bytes = [0x34, 0x55, 0x1, 0xDF]
console.log(convertHex.bytesToHex(bytes)) //"345501df"
```


### hexToBytes(hexStr)

```js
var hex = "34550122DF" //"0x" prefix is optional
console.dir(conv.hexToBytes(hex).join(',')) //'[52,85,1,34,223]'
```

Credits
-------

Loosely inspired by code from here: https://github.com/vbuterin/bitcoinjs-lib & CryptoJS


License
-------

(MIT License)

Copyright 2013, JP Richardson  <jprichardson@gmail.com>
