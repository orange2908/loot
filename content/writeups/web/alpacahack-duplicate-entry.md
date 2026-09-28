---
title: "duplicate entry - AlpacaHack Daily"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "alpacahack", "duplicate", "entry", "web-exploitation", "duplicate-entry"]
summary: "web writeup for \"duplicate entry\" from AlpacaHack Daily - techniques: alpacahack, duplicate, entry, web-exploitation, duplicate-entry."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d06_duplicate_entry/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "duplicate entry"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** duplicate entry
- **Date:** 2026-07-06
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d06_duplicate_entry>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d06_duplicate_entry/README.md>

---
# duplicate entry

## 問題

解凍しても本物の flag.txt は得られません！　たぶん

```py
import os, zipfile

FLAG = os.getenv("FLAG", "Alpaca{DUMMY}")

def writestr(z, name, data):
    info = zipfile.ZipInfo(name)
    z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)

with zipfile.ZipFile("flag.zip", "w") as z:
    writestr(z, "README.txt", "The flag is in flag.txt.")
    for i in range(100):
        if i == 50:
            writestr(z, "flag.txt", FLAG)
        else:
            writestr(z, "flag.txt", "No flag here. Try harder.")
```

## 概要

添付のflag.zipを展開しようとすると、
```
101個の項目をコピー中: flag.zip から flag
宛先には同じ名前のファイルが 99 個存在します
```
とでてしまいます。

make_zip.pyで、flag.txtという同じファイル名でZIPファイルに100回書き込んでいるからですね。

i == 50のとき、すなわち51個目のflag.txtにフラグを書き込んでいるようですが、flag.zipをそのまま展開しても上書きまたは無視されてしまうのでフラグを得ることはできません。

どうすればフラグが書かれたflag.txtを取得できるのでしょうか？

## 解法

せっかくの面白そうな問題なので、いろいろな解法を思いつくままに書いていきたいと思います。

### 解法１: 展開せずエクスプローラーで開く

右クリックから「すべて展開」ではなく「プログラムから開く」→「エクスプローラー」をクリックします。

そうすると全てのflag.txtが表示されるので、上から51番目をダブルクリックで開くとフラグを取得できます。

※私のときはたまたまちゃんと51番目に並んだだけかもしれません。違ってたら前後をかたっぱしから開けばいつか見つかるでしょう。

### 解法２: すべて展開で「ファイルごとに決定する」を選ぶ

右クリックから「すべて展開」を選んだら、「ファイルを置き換える」でも「ファイルは置き換えずスキップする」でもなく「ファイルごとに決定する」を選びます。

どれを残すかきかれるので、全てチェックするとflag(2).txtやflag(3).txtのように番号が付加されます。

展開が終わったら、flag(51).txtを開きます。

### 解法３: zipfileライブラリを使って取り出す

Pythonのzipfileライブラリを使ってflag.zipを開いたら、.infolist()でファイル一覧を取得、51番目のファイルだけ展開して表示します。

※ファイルパスは適宜合わせてください。

```py
import zipfile

zip_file_path = 'c:/ctf/flag.zip'

with zipfile.ZipFile(zip_file_path, 'r') as z:
    file_list = [info for info in z.infolist() if info.filename == 'flag.txt']
    target_index = 50
    if len(file_list) > target_index:
        target_file = file_list[target_index]
        with z.open(target_file) as f:
            print(f.read())
```

### 解法４: バイナリをいじってファイル名を退避させる

実は私が最初に思い付いたのはこの方法で、「これ絶対Easy問題じゃないよね？」と勝手に思い込んでいました（笑）

以前、何かのきっかけでZIPファイルのバイナリ構造について調べたことがあって記憶に残っていたのですが、ZIPファイルって、
```
LFH(1)
Data(1)
LFH(2)
Data(2)
...
LFH(N)
Data(N)
CDFH(1)
CDFH(2)
...
CDFH(N)
EOCD

LFH = Local File Header
CDFH = Central Directory File Header
EOCD = End Of Central Directory
```
こんな構造になっているんですよね。

ファイル名はLFHとCDFHにそれぞれ平文で記録されています。

ということは、それぞれ51番目のflag.txtだけ別のファイル名にすり替えてしまえば、ちゃんと別名で展開されるのではないかと考えました。

```py
zip_file_path = 'c:/ctf/flag.zip'
edited_path = 'c:/ctf/edited_flag.zip'

with open(zip_file_path, "rb") as fr:
    data = bytearray(fr.read())

pos = -1

for _ in range(51):
    pos = data.find(b"flag.txt", pos + 1)
data[pos:pos+4] = b"paca"

for _ in range(100):
    pos = data.find(b"flag.txt", pos + 1)
data[pos:pos+4] = b"paca"

with open(edited_path, "wb") as fw:
    fw.write(data)
```
ファイル名の文字数を変えると面倒なので同じ文字数のpaca.txtにしてみました。

このedited_flag.zipを展開すると、狙い通り
```
flag.txt
paca.txt
README.txt
```
の3つのファイルが作られるので、paca.txtを開いてフラグを確認します。

### 解法５: バイナリをいじってファイルを１個だけにする

ZIPファイルが１冊の本だとすると、EOCDは表紙、CDFHは目次、LFHとDataは各章のタイトルと本文のようなものだと考えるといいかと思います。

EOCDはCDFHの情報をもっています。この情報を書き換えることで、展開対象のファイルをフラグをもつflag.txtファイルただ1つだけにしてしまうことができます。

```py
zip_file_path = 'c:/ctf/flag.zip'
edited_path = 'c:/ctf/edited_flag.zip'

with open(zip_file_path, "rb") as fr:
    data = bytearray(fr.read())

# フラグのCDFHの位置を探す
pos = -1
for _ in range(52): # README.txtを含めて52番目
    pos = data.find(b"PK\x01\x02", pos + 1)
cdfh_pos = pos
# フラグのCDFHのサイズを求める
pos = data.find(b"PK\x01\x02", pos + 1)
cdfh_size = pos - cdfh_pos

# EOCDの先頭位置を探す
pos = data.rfind(b"PK\x05\x06")
# CDFHの個数
pos += 8
val = 1
data[pos:pos+2] = val.to_bytes(2, 'little')
# CDFHの総数
pos += 2
val = 1
data[pos:pos+2] = val.to_bytes(2, 'little')
# CDFHの総サイズ
pos += 2
val = cdfh_size
data[pos:pos+4] = val.to_bytes(4, 'little')
# CDFHのオフセット
pos += 4
val = cdfh_pos
data[pos:pos+4] = val.to_bytes(4, 'little')

with open(edited_path, "wb") as fw:
    fw.write(data)
```
