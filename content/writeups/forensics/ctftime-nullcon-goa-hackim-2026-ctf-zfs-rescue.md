---
title: "ZFS rescue - Nullcon Goa HackIM 2026 CTF"
category: "forensics"
subcategory: "aes"
type: "writeup"
tags: ["forensics", "recovery", "zfs", "aes", "gcm", "canary", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: misc/ZFSrescue"
source:
  name: "CTFtime writeup #40565"
  url: "https://ctftime.org/writeup/40565"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "ZFS rescue"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** ZFS rescue
- **Author team:** 正规子群.AI
- **CTFtime tags:** forensics, recovery, zfs
- **CTFtime:** <https://ctftime.org/writeup/40565>

---
## 131 ZFS rescue

\- Category: `misc`  
\- Value: `470`  
\- Solves: `11`  
\- Solved by me: `True`  
\- Local directory: `misc/ZFSrescue`

### 题目描述  
> We had all our flags on this super old thumb drive. My friend said the data would be safe due to ZFS, but here we are... Something got corrupted and we can only remember that the password was from the rockyou.txt file...   
>  
> Can you recover the flag.txt?  
>  
> Author: @gehaxelt

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/e93dfd212bdf30e4c2fb2c8b6ac4e38f/nullcongoa_rescued.img?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjoxMDB9.aYqlRw.2SAOP1ilc43wdOBHI-lQNprraM0>`

### 内存布局  
\- Binary path: `misc/ZFSrescue/tmp_check`  
\- File type: `Mach-O 64-bit executable arm64`  
\- arch: `arm`  
\- bits: `64`  
\- class: `MACH064`  
\- bintype: `mach0`  
\- machine: `all`  
\- endian: `little`  
\- os: `macos`  
\- pic: `true`  
\- nx: `false`  
\- canary: `true`  
\- stripped: `false`  
\- baddr: `0x100000000`

```text  
nth paddr size vaddr vsize perm flags type name  
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――  
0 0x00003b9c 0x2a4 0x100003b9c 0x2a4 -r-x 0x0 REGULAR 0.__TEXT.__text  
1 0x00003e40 0xa8 0x100003e40 0xa8 -r-x 0x0 SYMBOL_STUBS 1.__TEXT.__stubs  
2 0x00003ee8 0x22 0x100003ee8 0x22 -r-x 0x0 CSTRINGS 2.__TEXT.__cstring  
3 0x00003f0a 0x9c 0x100003f0a 0x9c -r-x 0x0 REGULAR 3.__TEXT.__const  
4 0x00003fa8 0x58 0x100003fa8 0x58 -r-x 0x0 REGULAR 4.__TEXT.__unwind_info  
5 0x00004000 0x88 0x100004000 0x88 -rw- 0x0 NONLAZY_POINTERS 5.__DATA_CONST.__got  
```

### WP  
# ZFS rescue Writeup 完整版

\---

## 0. 题目与目标

题目给了一个损坏的 ZFS 镜像，描述为：

\- 曾经把所有 flag 放在一个老 U 盘（ZFS）里  
\- 现在有损坏  
\- 只记得口令来自 `rockyou.txt`  
\- 要求恢复 `flag.txt`

我的最终目标拆成两个层次：

1\. 拿到可提交的 flag 字符串。  
2\. 给出可复现、可验证的完整恢复流程（脚本 + 说明文档）。

\---

## 1. 最终目录结构

```text  
ZFSrescue/  
├── [README.md](http://README.md)  
├── solution/  
│ └── [solution.py](http://solution.py)  
├── task/  
│ └── nullcongoa_rescued.img  
└── flag.txt  
```

说明：

\- `task/nullcongoa_rescued.img` 是题目镜像。  
\- `solution/[solution.py](http://solution.py)` 是完整离线恢复脚本。  
\- `flag.txt` 由脚本运行后生成。

\---

## 2. 一句话总思路

**不能 import 池，就从 uberblock 的 rootbp 直接离线读 MOS，恢复到目标数据集对象树；先解包数据集密钥，再按 ZFS 真实规则解密目标文件数据块。**

\---

## 3. 初始侦察与失败路径

### 3.1 常规导入失败

尝试：

```bash  
zpool import -d /path/to/img_dir  
zpool import -d /path/to/img_dir -f -F -X  
```

结果：

\- `no pools available to import`

结论：

\- 标签配置（label nvlist）坏到不能用于 import。  
\- 不能走 `zfs load-key -> mount -> cat` 常规路径。

### 3.2 仍有可用 uberblock

使用 `zdb -luvvvv` 能看到有效 uberblock/rootbp（例如 txg=43）。

这一步意义：

\- label 不能导入 != 元数据全毁。  
\- 仍可以从 rootbp 逆向走对象树。

\---

## 4. 关键 ZFS 背景本题实际用到

### 4.1 DVA 偏移不是镜像绝对偏移

本题最先踩的坑就是这个。

ZFS vdev 前部有 label/boot 保留区，`DVA.offset` 是分配区内偏移。读取镜像文件时需要：

\- `physical_offset = VDEV_LABEL_START_SIZE + DVA.offset`  
\- 本题里 `VDEV_LABEL_START_SIZE = 0x400000`

不加这段，读取到的往往是全零，后续全部跑偏。

### 4.2 目录项编码

目录 ZAP 的 value 不是纯对象号，而是 `dirent` 打包值：

\- 高 4 bit: 类型  
\- 低 48 bit: 对象号

即：

\- `obj = de & ((1<<48)-1)`  
\- `type = (de >> 60) & 0xF`

本题 `flag.txt` 的 dirent 是：

\- `0x8000000000000002`  
\- 对象号是 `2`。

### 4.3 ZFS LZ4 不是裸流

ZFS 的 LZ4 块格式：

\- 前 4 字节是大端压缩长度 `BE32(clen)`  
\- 后面才是 LZ4 payload

直接把整个块喂裸 LZ4 解压会出错。

\---

## 5. 数据集密钥恢复口令确认

### 5.1 从 DSL crypto key 对象提取参数

恢复到的关键字段（object `272`）如下：

\- `DSL_CRYPTO_SUITE = 8` (`aes-256-gcm`)  
\- `DSL_CRYPTO_GUID = 7527707299918618326`  
\- `DSL_CRYPTO_VERSION = 1`  
\- `DSL_CRYPTO_IV = 1dd41ddc27e486efe756baae`  
\- `DSL_CRYPTO_MAC = 233648b5de813aa6544241fa9110076b`  
\- `DSL_CRYPTO_MASTER_KEY_1 = d7da54...84d7`（32B 密文）  
\- `DSL_CRYPTO_HMAC_KEY_1 = 2e2ff1...4272`（64B 密文）  
\- `keyformat = passphrase`  
\- `pbkdf2salt = d0b4a8ede9e60026`  
\- `pbkdf2iters = 100000`

### 5.2 派生与解包公式

OpenZFS 逻辑（对齐 `libzfs_crypto.c` / `zio_crypt_key_unwrap`）可写成：

\- 包装密钥：  
$K_w = \mathrm{PBKDF2\\_HMAC\\_SHA1}(P, \mathrm{bytes}(\mathrm{LE64}(salt)), iters, 32)$  
\- AAD：  
$AAD = \mathrm{LE64}(guid)\|\mathrm{LE64}(crypt)\|\mathrm{LE64}(version)$  
\- 解包：  
$(K_{master}\|K_{hmac}) = \mathrm{AES\\_GCM\\_DEC}(K_w, iv, ct, mac, AAD)$

### 5.3 口令结果

对 `rockyou.txt` 进行校验匹配后得到：

\- `reba12345`

这一步不是猜测，是能通过 GCM 验证标签（MAC）的一致性证明。

\---

## 6. 离线对象树恢复路径精确对象号

从 `rootbp -> MOS` 之后，路径如下：

1\. MOS object directory（obj 1）得到：  
\- `root_dataset = 32`  
2\. `dsl_dir(32)` 的 child map（obj 34）得到：  
\- `$MOS -> 35`  
\- `$FREE -> 38`  
\- `$ORIGIN -> 42`  
\- `flag -> 265`  
3\. 读取 `dsl_dir(265)` bonus，得到：  
\- `dd_head_dataset_obj = 268`  
4\. 读取 `dsl_dataset(268)` bonus 中 `ds_bp`，进入 `flag` 数据集 head fs objset  
5\. 读该 fs 的 master node（obj 1）得到：  
\- `ROOT = 34`  
6\. 读根目录 ZAP（obj 34）得到：  
\- `flag.txt -> 0x8000000000000002`  
7\. 取对象号低 48 bit：  
\- `2`  
8\. 读文件 dnode（obj 2）与其数据 bp，解密后得到明文。

\---

## 7. 块读取、认证、解密细节

### 7.1 通用块读取

对普通 BP：

1\. 取 DVA  
2\. 计算文件偏移 `0x400000 + offset`  
3\. 读取 `psize`  
4\. 若受压缩则解压到 `lsize`  
5\. 若受保护则按对象类型做认证/解密

### 7.2 加密块的 per-block key

对加密数据块，使用：

\- $K_b = \mathrm{HKDF\\_SHA512}(IKM=K_{master}, salt=\emptyset, info=salt_{block}, L=32)$

然后用 `AES-GCM(K_b, iv, aad)` 解密。

### 7.3 `DMU_OT_DNODE` 特殊处理

`DMU_OT_DNODE` 不能把整块直接当密文解：

\- dnode core 与部分字段进入 AAD（`dn_flags` 仅保留可移植位，`dn_used` 清零）  
\- 子 blkptr 变换为 auth buffer（`blk_prop` 掩码 + MAC）后入 AAD  
\- bonus 区只加密“需要加密”的那部分，其他仍为 AAD

脚本中已按这个逻辑实现最小可用流程。

\---

## 8. 我踩过的坑与修正

### 坑 1：`zpool import` 思路执念

\- 现象：一直 `no pools available to import`  
\- 修正：转为离线解析，不再依赖 import 成功

### 坑 2：DVA 直读

\- 现象：读到全零，MOS/dnode 全错  
\- 修正：统一加 `0x400000` 基址

### 坑 3：LZ4 直接解

\- 现象：解压崩溃或输出错  
\- 修正：先剥 `BE32(clen)` 头，再解 payload

### 坑 4：把目录项值当对象号

\- 现象：对象号巨大（例如 `0x8000...0002`）  
\- 修正：低 48 bit 才是对象号

### 坑 5：fatzap 数值端序

\- 现象：少数值按 LE 解析异常大  
\- 修正：在本样本中做 LE/BE 兼容判断

\---

## 9. 镜像内文件枚举结果

对目标数据集 `flag` 递归遍历，只有：

\- `/flag.txt`

没有其他普通文件与子目录。

（系统内部数据集 `$MOS/$FREE/$ORIGIN` 不算题目“用户文件”。）

\---

## 10. 运行与验证

### 10.1 运行

```bash  
python3 solution/[solution.py](http://solution.py)  
```

### 10.2 预期输出要点

\- 选中有效 uberblock txg  
\- 解析到 `root_dataset`、`flag`、`ROOT`  
\- 打印 `FLAG: ...`

### 10.3 结果文件

\- 生成 `flag.txt`

\---

## 11. 关键伪代码与脚本一致

```text  
load image  
unwrap (master_key, hmac_key) using passphrase + pbkdf2 + aes-gcm

rootbp = best uberblock rootbp  
mos = read_bp(rootbp)

root_dataset = mos_objdir["root_dataset"]  
flag_dd = child_map(root_dataset)["flag"]  
head_ds = dsl_dir(flag_dd).head_dataset  
fs_bp = dsl_dataset(head_ds).ds_bp  
fs = read_bp(fs_bp)

root_obj = fs_master_node["ROOT"]  
dirent = fs_dir(root_obj)["flag.txt"]  
file_obj = dirent & ((1<<48)-1)  
file_data = read_file_object(file_obj)

extract token like ENO{...}  
```

\---

## 12. 最终 Flag

```text  
ENO{you_4r3_Truly_An_ZFS_3xp3rt}  
```

补充：题面提到格式 `flag{}`，但镜像中 `flag.txt` 实际内容为 `ENO{...}`，按实际恢复结果提交。

\---

## 13. 附录：核心常量便于复现比对

\- `CRYPT = 8`  
\- `GUID = 7527707299918618326`  
\- `KEY_VERSION = 1`  
\- `PBKDF2_ITERS = 100000`  
\- `PBKDF2_SALT_RAW = d0b4a8ede9e60026`  
\- `WRAP_IV = 1dd41ddc27e486efe756baae`  
\- `WRAP_MAC = 233648b5de813aa6544241fa9110076b`  
\- `VDEV_LABEL_START_SIZE = 0x400000`

这些值与 `solution/[solution.py](http://solution.py)` 一一对应。

### Exploit  
#### misc/ZFSrescue/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import struct  
import hashlib  
import hmac  
from pathlib import Path  
from dataclasses import dataclass  
from typing import List, Tuple, Optional, Dict

# ---- constants ----  
BASE_DIR = Path(__file__).resolve().parents[1]  
IMG = BASE_DIR / 'task' / 'nullcongoa_rescued.img'  
PASS = b'reba12345'

# from recovered DSL crypto key object (272)  
CRYPT = 8 # aes-256-gcm  
KEY_VERSION = 1  
KEY_GUID = 7527707299918618326  
WRAP_IV = bytes.fromhex('1dd41ddc27e486efe756baae')  
WRAP_MAC = bytes.fromhex('233648b5de813aa6544241fa9110076b')  
WRAP_MASTER_CT = bytes.fromhex('d7da54dac4d6b6eab0450efef2bd602357007ac5f5dc9ed65d4892c5a99484d7')  
WRAP_HMAC_CT = bytes.fromhex('2e2ff1a74e1d88735ecec7559f084dceb7bcb083fb506fc6060b68e86afb5595c3067fe06d86d99ca77537c43bc81c1d79c432ec897d0c00d472b8f30cc84272')  
PBKDF2_ITERS = 100000  
PBKDF2_SALT_RAW = bytes.fromhex('d0b4a8ede9e60026')

SPA_MINBLOCKSHIFT = 9  
VDEV_LABEL_START_SIZE = 0x400000 # 2 labels + 3.5MB boot area  
DNODE_SHIFT = 9  
DNODE_SIZE = 1 << DNODE_SHIFT  
DNODES_PER_BLOCK_SHIFT = 14 - 9  
DNODES_PER_BLOCK = 1 << DNODES_PER_BLOCK_SHIFT

# legacy dmu_ot[ot].ot_encrypt == TRUE (from openzfs dmu.c)  
ENC_OT_LEGACY = {9, 10, 18, 19, 20, 22, 23, 25, 26, 33, 34, 35, 39, 40, 44, 45, 46, 47, 49}

def bget(word: int, low: int, length: int) -> int:  
return (word >> low) & ((1 << length) - 1)

def bget_sb(word: int, low: int, length: int, shift: int, bias: int) -> int:  
return (bget(word, low, length) + bias) << shift

def le64(x: int) -> bytes:  
return struct.pack('<Q', x & 0xFFFFFFFFFFFFFFFF)

def is_ot_encrypted(ot: int) -> bool:  
if ot & 0x80: # DMU_OT_NEWTYPE  
return (ot & 0x20) != 0 # DMU_OT_ENCRYPTED  
return ot in ENC_OT_LEGACY

@dataclass  
class DVA:  
w0: int  
w1: int

@property  
def asize(self) -> int:  
return bget_sb(self.w0, 0, 24, SPA_MINBLOCKSHIFT, 0)

@property  
def vdev(self) -> int:  
return bget(self.w0, 32, 24)

@property  
def offset(self) -> int:  
return bget_sb(self.w1, 0, 63, SPA_MINBLOCKSHIFT, 0)

@property  
def gang(self) -> int:  
return bget(self.w1, 63, 1)

@dataclass  
class BP:  
raw: bytes  
dva: List[DVA]  
prop: int  
prop2: int  
pad: int  
birth0: int  
birth1: int  
fill: int  
cksum: Tuple[int, int, int, int]

@staticmethod  
def parse(buf: bytes) -> 'BP':  
w = struct.unpack('<16Q', buf)  
d0 = DVA(w[0], w[1])  
d1 = DVA(w[2], w[3])  
d2 = DVA(w[4], w[5])  
return BP(buf, [d0, d1, d2], w[6], w[7], w[8], w[9], w[10], w[11], (w[12], w[13], w[14], w[15]))

@property  
def embedded(self) -> bool:  
return bget(self.prop, 39, 1) == 1

@property  
def lsize(self) -> int:  
if self.embedded:  
return bget_sb(self.prop, 0, 25, 0, 1)  
return bget_sb(self.prop, 0, 16, SPA_MINBLOCKSHIFT, 1)

@property  
def psize(self) -> int:  
if self.embedded:  
return bget_sb(self.prop, 25, 7, 0, 1)  
return bget_sb(self.prop, 16, 16, SPA_MINBLOCKSHIFT, 1)

@property  
def comp(self) -> int:  
return bget(self.prop, 32, 7)

@property  
def cksum_type(self) -> int:  
return bget(self.prop, 40, 8)

@property  
def ot(self) -> int:  
return bget(self.prop, 48, 8)

@property  
def level(self) -> int:  
return bget(self.prop, 56, 5)

@property  
def uses_crypt(self) -> bool:  
return bget(self.prop, 61, 1) == 1

@property  
def dedup(self) -> int:  
return bget(self.prop, 62, 1)

@property  
def byteorder(self) -> int:  
return bget(self.prop, 63, 1)

@property  
def host_le(self) -> bool:  
# host is LE => ZFS_HOST_BYTEORDER == 1  
return self.byteorder == 1

@property  
def encrypted(self) -> bool:  
return self.uses_crypt and self.level <= 0 and is_ot_encrypted(self.ot)

@property  
def authenticated(self) -> bool:  
return self.uses_crypt and self.level <= 0 and (not is_ot_encrypted(self.ot))

@property  
def iv2(self) -> int:  
return bget(self.fill, 32, 32)

def parse_dnode(d: bytes):  
# first 64 bytes core  
dn_type = d[0]  
dn_indblkshift = d[1]  
dn_nlevels = d[2]  
dn_nblkptr = d[3]  
dn_bonustype = d[4]  
dn_checksum = d[5]  
dn_compress = d[6]  
dn_flags = d[7]  
dn_datablkszsec = struct.unpack_from('<H', d, 8)[0]  
dn_bonuslen = struct.unpack_from('<H', d, 10)[0]  
dn_extra_slots = d[12]  
dn_maxblkid = struct.unpack_from('<Q', d, 16)[0]  
dn_used = struct.unpack_from('<Q', d, 24)[0]

size = (dn_extra_slots + 1) << DNODE_SHIFT  
blkptrs = []  
off = 64  
for _ in range(dn_nblkptr):  
blkptrs.append(BP.parse(d[off:off+128]))  
off += 128

bonus_off = 64 + dn_nblkptr * 128  
if dn_flags & (1 << 2):  
spill_off = size - 128  
bonus_len_max = spill_off - bonus_off  
spill_bp = BP.parse(d[spill_off:spill_off+128])  
else:  
bonus_len_max = size - bonus_off  
spill_bp = None

bonus = d[bonus_off:bonus_off+bonus_len_max]

return {  
'type': dn_type,  
'indblkshift': dn_indblkshift,  
'nlevels': dn_nlevels,  
'nblkptr': dn_nblkptr,  
'bonustype': dn_bonustype,  
'flags': dn_flags,  
'datablkszsec': dn_datablkszsec,  
'bonuslen': dn_bonuslen,  
'extra_slots': dn_extra_slots,  
'maxblkid': dn_maxblkid,  
'used': dn_used,  
'blkptrs': blkptrs,  
'bonus_off': bonus_off,  
'bonus_len_max': bonus_len_max,  
'bonus': bonus,  
'spill_bp': spill_bp,  
'size': size,  
'raw': d,  
}

def byteswap_u64_arr(data: bytes) -> bytes:  
assert len(data) % 8 == 0  
vals = struct.unpack('<' + 'Q' * (len(data)//8), data)  
vals = [int.from_bytes(struct.pack('<Q', v), 'big') for v in vals]  
return struct.pack('<' + 'Q' * len(vals), *vals)

def bp_decode_mac(bp: BP, should_bswap: bool) -> bytes:  
if bp.ot == 11: # DMU_OT_OBJSET  
return b'\x00' * 16  
w2, w3 = bp.cksum[2], bp.cksum[3]  
if not should_bswap:  
return struct.pack('<QQ', w2, w3)  
return struct.pack('<QQ', int.from_bytes(struct.pack('<Q', w2), 'big'), int.from_bytes(struct.pack('<Q', w3), 'big'))

def bp_auth_bab(bp: BP, version: int) -> bytes:  
# little-endian only path; should_bswap=False for this image  
tmp_prop = bp.prop

# hole check by DVA words all zero  
is_hole = all(x.w0 == 0 and x.w1 == 0 for x in bp.dva)  
if is_hole:  
tmp_prop = 0  
else:  
lvl = bget(tmp_prop, 56, 5)  
if lvl != 0:  
# byteorder=0, compress=0, psize=512  
tmp_prop &= ~(1 << 63)  
tmp_prop &= ~(((1 << 7) - 1) << 32)  
# psize field stores ((x >> shift) - bias), shift=9,bias=1 => 512=>0  
tmp_prop &= ~(((1 << 16) - 1) << 16)  
# dedup=0 checksum=0  
tmp_prop &= ~(1 << 62)  
tmp_prop &= ~(((1 << 8) - 1) << 40)

bab_prop = le64(tmp_prop)  
bab_mac = bp_decode_mac(bp, should_bswap=False)  
bab_pad = b'\x00' * 8  
if version == 0:  
return bab_prop + bab_mac  
return bab_prop + bab_mac + bab_pad

def hkdf_sha512(ikm: bytes, info: bytes, out_len: int) -> bytes:  
# HKDF with salt = empty  
prk = hmac.new(b'', ikm, hashlib.sha512).digest()  
out = b''  
t = b''  
counter = 1  
while len(out) < out_len:  
t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()  
out += t  
counter += 1  
return out[:out_len]

def aes_gcm_decrypt(key: bytes, iv: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  
return AESGCM(key).decrypt(iv, ct + tag, aad)

class ZFSImage:  
def __init__(self, path: Path):  
self.b = path.read_bytes()  
self.master_key = None  
self.hmac_key = None

def unwrap_dataset_keys(self):  
# derive wrapping key from passphrase  
salt_lebytes = PBKDF2_SALT_RAW[::-1]  
wrapping_key = hashlib.pbkdf2_hmac('sha1', PASS, salt_lebytes, PBKDF2_ITERS, 32)  
aad = struct.pack('<QQQ', KEY_GUID, CRYPT, KEY_VERSION)  
pt = aes_gcm_decrypt(wrapping_key, WRAP_IV, WRAP_MASTER_CT + WRAP_HMAC_CT, WRAP_MAC, aad)  
assert len(pt) == 96  
self.master_key = pt[:32]  
self.hmac_key = pt[32:]

def read_at(self, off: int, size: int) -> bytes:  
return self.b[off:off+size]

def read_bp_raw(self, bp: BP) -> bytes:  
if bp.embedded:  
# payload is stored in all blkptr words except blk_prop (word 6)  
# and blk_birth_word[1] (word 10)  
w = struct.unpack('<16Q', bp.raw)  
payload_words = [0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15]  
payload = b''.join(struct.pack('<Q', w[i]) for i in payload_words)  
return payload[:bp.psize]

dva = bp.dva[0]  
assert dva.vdev == 0  
assert dva.gang == 0  
# DVA offsets are in allocatable vdev space (after start labels/boot).  
off = VDEV_LABEL_START_SIZE + dva.offset  
return self.read_at(off, bp.psize)

def decode_bp_crypto(self, bp: BP, raw: bytes) -> bytes:  
if not bp.uses_crypt:  
return raw

# authenticated-only blocks are plaintext on disk  
if not bp.encrypted:  
return raw

assert self.master_key is not None

# decode salt + iv from blkptr (little-endian path)  
salt = struct.pack('<Q', bp.dva[2].w0)  
iv_lo = struct.pack('<Q', bp.dva[2].w1)  
iv_hi = struct.pack('<I', bp.iv2)  
iv = iv_lo + iv_hi  
mac = struct.pack('<QQ', bp.cksum[2], bp.cksum[3])

# per-block key  
ekey = hkdf_sha512(self.master_key, salt, 32)

if bp.ot != 10: # non-DNODE encrypted => normal path (no AAD)  
return aes_gcm_decrypt(ekey, iv, raw, mac, b'')

# DNODE special case: only encrypted bonuses are in ciphertext stream.  
plain = bytearray(raw)  
aad = bytearray()  
ct_stream = bytearray()  
enc_segments = []

max_dnp = len(raw) >> DNODE_SHIFT  
i = 0  
while i < max_dnp:  
base = i * DNODE_SIZE  
if base + DNODE_SIZE > len(raw):  
break  
d = raw[base:base+DNODE_SIZE]  
dn = parse_dnode(d)  
slots = dn['extra_slots'] + 1  
if slots <= 0:  
break  
if base + slots * DNODE_SIZE > len(raw):  
# malformed tail, stop building AAD/cipher stream  
break  
dfull = raw[base:base + slots * DNODE_SIZE]  
dn = parse_dnode(dfull)

# core 64 bytes with portable mask on flags and zero dn_used  
core = bytearray(dfull[:64])  
core[7] &= (1 << 2)  
core[24:32] = b'\x00' * 8  
aad += core

for child in dn['blkptrs']:  
aad += bp_auth_bab(child, KEY_VERSION)

if dn['spill_bp'] is not None:  
aad += bp_auth_bab(dn['spill_bp'], KEY_VERSION)

if dn['type'] != 0 and is_ot_encrypted(dn['bonustype']) and dn['bonuslen'] != 0:  
boff = base + dn['bonus_off']  
blen = dn['bonus_len_max']  
ct_stream += raw[boff:boff+blen]  
enc_segments.append((boff, blen))  
else:  
boff = base + dn['bonus_off']  
blen = dn['bonus_len_max']  
aad += raw[boff:boff+blen]

i += slots

if ct_stream:  
dec_stream = aes_gcm_decrypt(ekey, iv, bytes(ct_stream), mac, bytes(aad))  
p = 0  
for boff, blen in enc_segments:  
plain[boff:boff+blen] = dec_stream[p:p+blen]  
p += blen  
assert p == len(dec_stream)  
else:  
# no encrypted bonuses, but still authenticate  
_ = aes_gcm_decrypt(ekey, iv, b'', mac, bytes(aad))

return bytes(plain)

def lz4_decompress_block(self, src: bytes, out_len: int) -> bytes:  
# ZFS LZ4 stores a 4-byte big-endian compressed payload length prefix.  
if len(src) < 4:  
raise ValueError('lz4 src too short')  
clen = struct.unpack_from('>I', src, 0)[0]  
if clen + 4 > len(src):  
raise ValueError(f'lz4 bad length {clen} > {len(src)-4}')  
src = src[4:4+clen]

# raw LZ4 block decompressor (no frame)  
i = 0  
out = bytearray()  
n = len(src)  
while i < n:  
token = src[i]  
i += 1  
lit_len = token >> 4  
if lit_len == 15:  
while True:  
b = src[i]  
i += 1  
lit_len += b  
if b != 255:  
break  
out += src[i:i+lit_len]  
i += lit_len  
if i >= n:  
break  
off = src[i] | (src[i+1] << 8)  
i += 2  
match_len = token & 0xF  
if match_len == 15:  
while True:  
b = src[i]  
i += 1  
match_len += b  
if b != 255:  
break  
match_len += 4  
pos = len(out) - off  
for _ in range(match_len):  
out.append(out[pos])  
pos += 1  
if len(out) != out_len:  
raise ValueError(f'lz4 size mismatch {len(out)} != {out_len}')  
return bytes(out)

def read_bp_data(self, bp: BP) -> bytes:  
raw = self.read_bp_raw(bp)  
data = self.decode_bp_crypto(bp, raw)  
comp = bp.comp  
if comp in (0, 2, 4):  
# inherit/off/empty treated as no compression here  
return data  
if comp == 15:  
return self.lz4_decompress_block(data, bp.lsize)  
raise NotImplementedError(f'compression={comp}')

# --- object access ---

def get_indirect_entry(block: bytes, idx: int) -> BP:  
off = idx * 128  
return BP.parse(block[off:off+128])

def dnode_get_block(z: ZFSImage, dnode: dict, blkid: int) -> Optional[BP]:  
if dnode['nlevels'] == 0:  
return None  
epb = 1 << (dnode['indblkshift'] - 7)  
nlevels = dnode['nlevels']

# top-level selection from dnode blkptr[]  
if nlevels == 1:  
if blkid >= len(dnode['blkptrs']):  
return None  
bp = dnode['blkptrs'][blkid]  
if all(x.w0 == 0 and x.w1 == 0 for x in bp.dva):  
return None  
return bp

# nlevels >=2  
rem = blkid  
bp = None  
for lvl in range(nlevels, 0, -1):  
span = epb ** (lvl - 1)  
idx = rem // span  
rem = rem % span

if lvl == nlevels:  
if idx >= len(dnode['blkptrs']):  
return None  
bp = dnode['blkptrs'][idx]  
else:  
if bp is None:  
return None  
if all(x.w0 == 0 and x.w1 == 0 for x in bp.dva):  
return None  
iblk = z.read_bp_data(bp)  
bp = get_indirect_entry(iblk, idx)

if all(x.w0 == 0 and x.w1 == 0 for x in bp.dva):  
return None

return bp

def dnode_read_block(z: ZFSImage, dnode: dict, blkid: int) -> bytes:  
bp = dnode_get_block(z, dnode, blkid)  
if bp is None:  
return b''  
return z.read_bp_data(bp)

def objset_get_dnode(z: ZFSImage, os_meta_dnode: dict, objid: int) -> Optional[dict]:  
blkid = objid >> DNODES_PER_BLOCK_SHIFT  
slot = objid & (DNODES_PER_BLOCK - 1)  
block = dnode_read_block(z, os_meta_dnode, blkid)  
if not block:  
return None  
off = slot * (1 << DNODE_SHIFT)  
d = parse_dnode(block[off:off + (1 << DNODE_SHIFT)])  
# if large dnode, re-read full slots  
full = block[off:off + d['size']]  
return parse_dnode(full)

def parse_microzap(block: bytes) -> Dict[str, int]:  
out = {}  
# mzap header 64 bytes, then entries of 64 bytes  
off = 64  
while off + 64 <= len(block):  
val, cd, pad = struct.unpack_from('<QIH', block, off)  
name = block[off+14:off+64].split(b'\x00', 1)[0]  
if name:  
out[name.decode('utf-8', 'ignore')] = val  
off += 64  
return out

def parse_fatzap(z: ZFSImage, dnode: dict) -> Dict[str, bytes]:  
# minimal parser for current challenge  
hdr = dnode_read_block(z, dnode, 0)  
if len(hdr) < 128:  
return {}  
zap_magic = struct.unpack_from('<Q', hdr, 8)[0]  
if zap_magic != 0x2F52AB2AB:  
return {}

# embedded ptrtbl?  
zt_blk, zt_numblks, zt_shift = struct.unpack_from('<QQQ', hdr, 16)  
block_shift = dnode['datablkszsec'].bit_length() + 8 - 1 # rough; for 8 sectors -> 12  
if (1 << block_shift) != dnode['datablkszsec'] * 512:  
block_shift = (dnode['datablkszsec'] * 512).bit_length() - 1

# read ptrtbl entries  
ptrs = []  
if zt_blk == 0:  
ent_shift = block_shift - 3 - 1  
nent = 1 << ent_shift  
base = (1 << ent_shift) * 8  
for i in range(nent):  
ptrs.append(struct.unpack_from('<Q', hdr, base + i*8)[0])  
else:  
# external ptrtbl  
pblk = dnode_read_block(z, dnode, zt_blk)  
nent = len(pblk) // 8  
for i in range(nent):  
ptrs.append(struct.unpack_from('<Q', pblk, i*8)[0])

out: Dict[str, bytes] = {}

# iterate leaf blocks referenced by ptrtbl  
seen = set()  
for lb in ptrs:  
if lb in seen or lb == 0:  
continue  
seen.add(lb)  
leaf = dnode_read_block(z, dnode, lb)  
if len(leaf) < 96:  
continue  
l_block_type = struct.unpack_from('<Q', leaf, 0)[0]  
l_magic = struct.unpack_from('<I', leaf, 24)[0]  
if l_block_type != (1 << 63) or l_magic != 0x2AB1EAF:  
continue

# parse leaf chunks  
hshift = block_shift - 5  
hnent = 1 << hshift  
chunks_off = 48 + hnent * 2  
nchunks = ((1 << block_shift) - 2 * hnent) // 24 - 2

def read_array(chain_idx: int, nbytes: int) -> bytes:  
buf = bytearray()  
idx = chain_idx  
while idx != 0xFFFF and len(buf) < nbytes:  
co = chunks_off + idx * 24  
ctype = leaf[co]  
if ctype != 251: # ZAP_CHUNK_ARRAY  
break  
buf += leaf[co+1:co+22]  
idx = struct.unpack_from('<H', leaf, co+22)[0]  
return bytes(buf[:nbytes])

for ci in range(nchunks):  
co = chunks_off + ci * 24  
ctype = leaf[co]  
if ctype != 252:  
continue  
v_intlen = leaf[co+1]  
name_chunk = struct.unpack_from('<H', leaf, co+4)[0]  
name_numints = struct.unpack_from('<H', leaf, co+6)[0]  
val_chunk = struct.unpack_from('<H', leaf, co+8)[0]  
val_numints = struct.unpack_from('<H', leaf, co+10)[0]  
name_raw = read_array(name_chunk, name_numints).split(b'\x00', 1)[0]  
if not name_raw:  
continue  
key = name_raw.decode('utf-8', 'ignore')  
val_raw = read_array(val_chunk, v_intlen * val_numints)  
out[key] = val_raw

return out

def parse_zap_object(z: ZFSImage, os_meta_dnode: dict, objid: int) -> Dict[str, bytes]:  
dn = objset_get_dnode(z, os_meta_dnode, objid)  
if dn is None:  
return {}  
b0 = dnode_read_block(z, dn, 0)  
if len(b0) < 16:  
return {}  
bt = struct.unpack_from('<Q', b0, 0)[0]  
if bt == (1 << 63) + 3: # microzap  
mz = parse_microzap(b0)  
return {k: struct.pack('<Q', v) for k, v in mz.items()}  
if bt == (1 << 63) + 1: # fatzap  
return parse_fatzap(z, dn)  
return {}

def u64(v: bytes) -> int:  
le = struct.unpack('<Q', v[:8])[0]  
be = struct.unpack('>Q', v[:8])[0]  
# In this image, many fatzap uint64 payloads are big-endian on disk.  
if le > (1 << 56) and be < (1 << 40):  
return be  
return le

def find_best_uber_rootbp(img: bytes) -> BP:  
# scan first label's uberblock ring at known area (offset 256K + 128K)  
# but easiest: use known good rootbp from zdb txg=43  
rootbp_txt = 'DVA[0]=<0:a6000:1000> DVA[1]=<0:10a5000:1000> DVA[2]=<0:2069000:1000>'  
# build blkptr from known words by reading from uberblock slot 44 in label 0  
# uberblock start guessed from VDEV_UBERBLOCK_OFFSET(0x20000) in label area.  
# We'll just brute-scan for bab10c magic and choose max txg with plausible rootbp.  
best = None  
best_txg = -1  
for off in range(0, min(len(img), 4*1024*1024), 1024):  
if off + 1024 > len(img):  
break  
magic = struct.unpack_from('<Q', img, off)[0]  
if magic != 0x00bab10c:  
continue  
txg = struct.unpack_from('<Q', img, off + 16)[0]  
if txg > best_txg:  
rb = BP.parse(img[off+40:off+40+128])  
if rb.dva[0].offset != 0:  
best_txg = txg  
best = rb  
if best is None:  
raise RuntimeError('no uberblock found')  
print(f'[+] selected uberblock txg={best_txg}, rootbp off=0x{best.dva[0].offset:x}')  
return best

def main():  
z = ZFSImage(IMG)  
z.unwrap_dataset_keys()  
print('[+] unwrapped dataset master/hmac keys')

rootbp = find_best_uber_rootbp(z.b)  
mos = z.read_bp_data(rootbp)  
print(f'[+] MOS objset len={len(mos)} type={rootbp.ot} comp={rootbp.comp}')

os_meta = parse_dnode(mos[:512])

# MOS object directory (obj 1)  
objdir = {k: u64(v) for k, v in parse_zap_object(z, os_meta, 1).items()}  
print('[+] MOS objdir keys sample:', list(objdir.keys())[:10])  
root_ddobj = objdir['root_dataset']

# root dsl_dir in bonus buffer  
root_dd = objset_get_dnode(z, os_meta, root_ddobj)  
if root_dd is None or root_dd['bonuslen'] < 11 * 8:  
raise RuntimeError('failed to load root dsl_dir')  
root_dd_q = struct.unpack('<16Q', root_dd['bonus'][:128])  
root_child_map = root_dd_q[4]  
print(f'[+] root dsl_dir obj={root_ddobj}, child_map={root_child_map}')

# child map -> locate \"flag\" dsl_dir  
child_dirs = {k: u64(v) for k, v in parse_zap_object(z, os_meta, root_child_map).items()}  
print('[+] child dirs:', child_dirs)  
if 'flag' not in child_dirs:  
raise RuntimeError('flag dsl_dir not found')  
flag_ddobj = child_dirs['flag']

flag_dd = objset_get_dnode(z, os_meta, flag_ddobj)  
if flag_dd is None or flag_dd['bonuslen'] < 11 * 8:  
raise RuntimeError('failed to load flag dsl_dir')  
flag_dd_q = struct.unpack('<16Q', flag_dd['bonus'][:128])  
head_dsobj = flag_dd_q[1]  
print(f'[+] flag dsl_dir obj={flag_ddobj}, head_dsobj={head_dsobj}')

# dsl_dataset bonus contains ds_bp at offset 16*8  
ds_dn = objset_get_dnode(z, os_meta, head_dsobj)  
if ds_dn is None or ds_dn['bonuslen'] < (16 * 8 + 128):  
raise RuntimeError('failed to load head dsl_dataset')  
ds_bp = BP.parse(ds_dn['bonus'][16*8:16*8+128])  
print(f'[+] ds_bp type={ds_bp.ot} level={ds_bp.level} crypt={ds_bp.uses_crypt} enc={ds_bp.encrypted} auth={ds_bp.authenticated}')

fs_os = z.read_bp_data(ds_bp)  
print(f'[+] fs objset len={len(fs_os)}')  
fs_meta = parse_dnode(fs_os[:512])

# find master node object from object set object directory (obj 1)  
fs_objdir_raw = parse_zap_object(z, fs_meta, 1)  
fs_objdir = {k: u64(v) for k, v in fs_objdir_raw.items()}  
print('[+] fs objdir keys:', sorted(fs_objdir.keys())[:16])

if 'ROOT' not in fs_objdir:  
raise RuntimeError('ROOT not found in fs objdir')

root_obj = fs_objdir['ROOT']  
print(f'[+] ROOT zpl object id = {root_obj}')

root_dir = parse_zap_object(z, fs_meta, root_obj)  
root_entries = {k: u64(v) for k, v in root_dir.items()}  
print('[+] root dir entries:', root_entries)

target_obj = None  
for k, v in root_entries.items():  
if k == 'flag.txt' or k == 'flag':  
target_obj = v  
break  
if target_obj is None:  
# fallback by scanning for key containing flag  
for k, v in root_entries.items():  
if 'flag' in k:  
target_obj = v  
break  
if target_obj is None:  
raise RuntimeError('flag entry not found')

# ZFS directory entries encode type in top 4 bits and object id in low 48 bits  
target_objid = target_obj & ((1 << 48) - 1)  
print(f'[+] target dirent=0x{target_obj:x}, object={target_objid}')  
fn_dn = objset_get_dnode(z, fs_meta, target_objid)  
assert fn_dn is not None

# file size from bonus: try SA layout with first 8-byte size-like field fallback to used blocks  
fsize = None  
if fn_dn['bonuslen'] >= 16:  
# heuristic: scan qwords for plausible small file size  
q = struct.unpack_from('<' + 'Q' * (fn_dn['bonuslen']//8), fn_dn['bonus'][:(fn_dn['bonuslen']//8)*8])  
for x in q:  
if 1 <= x <= 4096:  
fsize = x  
break  
if fsize is None:  
fsize = fn_dn['datablkszsec'] * 512

file_data = bytearray()  
maxblkid = fn_dn['maxblkid']  
for blkid in range(maxblkid + 1):  
bp = dnode_get_block(z, fn_dn, blkid)  
if bp is None:  
continue  
block = z.read_bp_data(bp)  
file_data += block

# heuristic trim  
txt = bytes(file_data)  
# Try common flag-style prefixes, then generic {...}  
for pref in (b'flag{', b'FLAG{', b'ENO{'):  
idx = txt.find(pref)  
if idx != -1:  
end = txt.find(b'}', idx)  
if end != -1:  
out = txt[idx:end+1]  
print('[+] FLAG:', out.decode('utf-8', 'ignore'))  
(BASE_DIR / 'flag.txt').write_bytes(out + b'\n')  
return

l = txt.find(b'{')  
r = txt.find(b'}', l + 1) if l != -1 else -1  
if l != -1 and r != -1:  
out = txt[max(0, l-16):r+1].split(b'\x00', 1)[0]  
print('[+] FLAG-CANDIDATE:', out.decode('utf-8', 'ignore'))  
(BASE_DIR / 'flag.txt').write_bytes(out + b'\n')  
return

# fallback: print first chunk  
(BASE_DIR / 'flag_raw.bin').write_bytes(txt)  
print('[-] failed direct extract; wrote flag_raw.bin, first 256 bytes:')  
print(txt[:256])

if __name__ == '__main__':  
main()  
```

\---
