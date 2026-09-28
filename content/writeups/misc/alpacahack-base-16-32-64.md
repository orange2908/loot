---
title: "base 16-32-64 - AlpacaHack Daily"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "alpacahack", "base64", "base32", "base", "miscellaneous"]
summary: "misc writeup for \"base 16-32-64\" from AlpacaHack Daily - techniques: alpacahack, base64, base32, base, miscellaneous."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d02_base_16-32-64/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "base 16-32-64"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** base 16-32-64
- **Date:** 2026-09-02
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d02_base_16-32-64>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d02_base_16-32-64/README.md>

---
# base 16-32-64

## 問題

base16、base32、base64 を組み合わせた新しいエンコーディング方式を考えました。

```py
flag = os.environ.get("FLAG", "Alpaca{**** REDACTED ****}").encode()

for i in range(20):
    base = random.choice([16, 32, 64])
    if base == 16:
        flag = b16encode(flag)
    elif base == 32:
        flag = b32encode(flag)
    elif base == 64:
        flag = b64encode(flag)

flag = flag.decode()

print(flag)
```

## 概要

フラグがBase16, Base32, Base64のうちどれかランダムなエンコーディング方式で20回エンコードされた文字列が与えられます。

もとのフラグを得るにはどうすればいいのでしょうか？

## 解法

### フラグ取得

この問題、解くだけならわりと簡単です。

各ステップでBase16, Base32, Base64のいずれかの方式でエンコードされているので、順にデコードを試みます。

※後述の通り、必ずこの順番で試す必要があります。

```py
from base64 import b16decode, b32decode, b64decode

flag = b"(output.txtからコピペ)"

for i in range(20):
    # Base16を試す
    try:
        flag = b16decode(flag)
        continue
    except:
        pass
    # Base16がダメならBase32を試す
    try:
        flag = b32decode(flag)
        continue
    except:
        pass
    # Base16もBase32もダメならBase64確定
    flag = b64decode(flag)

print(f"{flag = }")
```

デコードに失敗した場合は例外が発生するので、try-exceptで拾っています。（これがないとデコード失敗時に処理が終わってしまいます。）

この方法でフラグを取得することができました。

さて、難しいのはここからです。

### ホントにこの方法で良いの？

複数のエンコード方式に解釈できる文字列はないのでしょうか？

結論からいうと、あります。

実際、output.txtで与えられた文字列は、Base32とBase64のいずれでも解釈することができます。

というのも、それぞれのエンコード方式で使われる文字種は、

| エンコード方式 | 文字種(`=`を除く) | 種類数 | 文字数 | 末尾のパディング(`=`) |
|-------|-------|-------|-------|-------|
| Base16 | 0-9A-F | 16 | 偶数 | なし |
| Base32 | A-Z2-7 | 32 | 8の倍数 | 0,1,3,4,6個 |
| Base64 | A-Za-z0-9+/ | 64 | 4の倍数 | 最大2個 |

このようになっているため、文字数や末尾の`=`の個数で判断できることもありますが、もしそうでなければBase16やBase64でエンコードされたデータはBase64としても解釈できてしまうのです。

よって、正確には深さ優先探索または幅優先探索などで全通り試すべきなのかもしれませんが、Easy問題にしては難しい気がするしちょっと面倒くさいです。

なので、視点を変えて考えてみます。

ここで注目するのは、「逆にBase64エンコードしたデータがBase32やBase16としても解釈できる確率は極めて低いのではないか」ということです。

確認してみましょう。

例えば、Base64エンコードされたデータの長さが16だったとして、64種類の文字が均一に分布していると仮定します。

そうすると、これらの文字が全てBase32で使われている文字でもある確率は、

$`\left(\frac{1}{2}\right)^{16} = 0.0015\%`$

となり、無視できるくらい低いことがわかります。

Base16についてはもっと低くなりますし、データが長くなればさらに低くなります。

また、Base16とBase32についても同じように考えられます。（Base32では使われない0,1,8,9があるのでもっと低くなります。）

よって、Base16やBase32で解釈できる場合はそれがもしBase32やBase64でも解釈できたとしてもこれは無視して良さそうです。
