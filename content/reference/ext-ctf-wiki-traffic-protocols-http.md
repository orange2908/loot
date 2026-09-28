---
title: "HTTP (CTF Wiki)"
category: "forensics"
subcategory: "protocols"
type: "reference"
tags: ["ctf-wiki", "forensics", "pcap", "tshark", "http", "protocols", "chinese", "zh"]
summary: "HTTP ( Hyper Text Transfer Protocol ，也称为超文本传输协议)是一种用于分布式、协作式和超媒体信息系统的应用层协议。 HTTP 是万维网的数据通信的基础。"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/misc/traffic/protocols/http.md"
license: "CC BY-NC-SA 4.0"
---

# HTTP

`HTTP` ( `Hyper Text Transfer Protocol` ，也称为超文本传输协议)是一种用于分布式、协作式和超媒体信息系统的应用层协议。 `HTTP` 是万维网的数据通信的基础。

## 例题

> 题目：江苏省领航杯-2017：hack

总体观察可以得出:

- `HTTP`为主
- `192.168.173.134`为主
- 不存在附件

![linghang_hack](https://raw.githubusercontent.com/ctf-wiki/ctf-wiki/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/misc/traffic/protocols/figure/linghang_hack.png)

从这张图,基本可以判断初这是一个在`sql注入-盲注时产生的流量包`

到此为止,基本可以判断flag的方向,提取出所有的url后,用`python`辅助即可得到flag

- 提取url: `tshark -r hack.pcap -T fields  -e http.request.full_uri|tr -s '\n'|grep flag > log`
- 得到盲注结果
```python
import re

with open('log') as f:
    tmp = f.read()
    flag = ''
    data = re.findall(r'=(\d*)%23',tmp)
    data = [int(i) for i in data]
    for i,num in enumerate(data):
        try:
            if num > data[i+1]:
                flag += chr(num)
        except Exception:
            pass
    print flag
```

---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/misc/traffic/protocols/http.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
