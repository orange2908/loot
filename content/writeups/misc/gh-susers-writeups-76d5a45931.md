---
title: "心仪的公司 - 世安杯 2017"
category: "misc"
subcategory: "network"
type: "writeup"
tags: ["misc", "tshark", "network", "miscellaneous", "susers", "writeups"]
summary: "misc writeup for \"心仪的公司\" from 世安杯 - techniques: tshark, network, miscellaneous, susers, writeups."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2017/%E4%B8%96%E5%AE%89%E6%9D%AF/Misc/%E5%BF%83%E4%BB%AA%E7%9A%84%E5%85%AC%E5%8F%B8/Write-up.md"
ctf:
  name: "世安杯"
  year: 2017
  challenge: "心仪的公司"
---

## Source

- **CTF:** 世安杯 2017
- **Challenge:** 心仪的公司
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2017/%E4%B8%96%E5%AE%89%E6%9D%AF/Misc/%E5%BF%83%E4%BB%AA%E7%9A%84%E5%85%AC%E5%8F%B8/Write-up.md>

---
##  Title

##  Tools

##  Steps

- Step 1

`tshark`发现疑似webshell的可以文件`conf1g`

- Step 2

`tcp contains conf1g`过滤很快发现可疑请求`action=file&thefile=E%3A%2Fwamp%2Fwww%2Fwebshell.jpg&doing=downfile&dir=E%3A%2Fwamp%2Fwww%2F&zip_file=E%3A%2Fwamp%2Fwww%2F192.168.1.108.zip&exclude=`

得到flag

```shell
s@.(.N`k.UuUI.D.......o.....c...i.H.m..j...x....t....
?.].b......9.;.....n5...f]$.6..r....0.b.......D,.*.WMa.B.....+a<....bh.............&..<.~8.hgvq;.N..w.....q;.N.v...L.;.6i.*.N..Ls.....q;.N.......i....c...fl4g:{ftop_Is_Waiting_4_y}
```
