---
title: "Flag is A plus B - AlpacaHack Daily"
category: "rev"
subcategory: "python"
type: "writeup"
tags: ["rev", "alpacahack", "xor", "python-bytecode", "plus", "python"]
summary: "rev writeup for \"Flag is A plus B\" from AlpacaHack Daily - techniques: alpacahack, xor, python-bytecode, plus, python."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d02_Flag_is_A_plus_B/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Flag is A plus B"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Flag is A plus B
- **Date:** 2026-07-02
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d02_Flag_is_A_plus_B>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d02_Flag_is_A_plus_B/README.md>

---
# Flag is A+B

## 問題

A+B を計算すればフラグがわかるよ! あれ、A と B っていくつだっけ…?

chall.py
```py
from Crypto.Util.number import bytes_to_long
import os
import random

FLAG = bytes_to_long(os.getenv("FLAG", "Alpaca{DUMMY}").encode())

A = random.randint(0, FLAG)
B = FLAG - A

assert A + B == FLAG

print(f"A or B = {A | B}")
print(f"A xor B = {A ^ B}")
```
output.txt
```
A or B = 1708520672692343497693425015709016883325158039728511260268583494549501
A xor B = 1653224853895272618878301831150773792186632776885840473347068872416893
```

## 概要

`A + B`を計算すると、フラグを整数化した`FLAG`になるようです。

与えられるのは`A`と`B`のビット論理和`A | B`およびビット排他的論理和`A ^ B`のみですが、どうすれば`A + B`を計算できるのでしょうか？

## 解説

もしかしたら（Welcome問題を除いて）この問題からDaily AlpacaHackを始める方もいるかもしれないので、いつもよりかなり頑張って丁寧に説明していきたいと思います。

まず、Pythonのソースコードchall.pyを見てみましょう。

最初の
```py
from Crypto.Util.number import bytes_to_long
import os
import random
```
の部分は、特別な機能を使えるようにするための「おまじない」だと思ってください。

配布のソースコードを読む上では特に気する必要はありませんが、自分で書き換えたり一から作ったりする場合は正しく書き直す必要があります。

```py
FLAG = bytes_to_long(os.getenv("FLAG", "Alpaca{DUMMY}").encode())
```
ですが、これは配布ファイルではわからないように本番環境では環境変数からフラグの文字列をとる書き方で、CTFではよく見かけます。

配布ファイルにフラグをそのまま書いてしまったら問題を解かなくてもわかってしまいますからね（笑）

とはいえ配布ファイルに何も書かないのではローカルのテスト実行に支障が出るので、代替文字列を用意してあるというわけです。
```py
os.getenv("FLAG", "Alpaca{DUMMY}")
```
は、`FLAG`というキーの環境変数を取得し、もしそのキーが無ければ第二引数に設定されたデフォルト値`Alpaca{DUMMY}`が採用されます。

これを
```py
.encode()
```
で文字列からバイナリデータに変換、さらに、
```py
FLAG = bytes_to_long( ... )
```
で整数に変換して`FLAG`変数に代入しています。

```py
A = random.randint(0, FLAG)
```
は、`A`に`0`以上`FLAG`以下のランダムな整数を代入しています。

randomモジュールが吐く乱数は問題によっては推測できる場合もありますが、今回のように１回きりの場合は予測はできないと考えて良いです。

```py
B = FLAG - A
```
で、`FLAG`から`A`を引いたものを`B`に代入しています。これにより、`B`も`0`以上`FLAG`以下の整数で、かつ、問題文どおり`A + B == FLAG`の条件を満たすようになります。

```py
assert A + B == FLAG
```
は、もし`A + B == FLAG`という条件を満たさない場合にエラーを吐く書き方です。

CTFでは入力値や環境変数、乱数などの簡易チェックに使われることが多いようです。

実行時のオプションに`-O`(ハイフンオー)をつけると無効になることも頭に入れておきましょう。

ここでは、本当に`A + B`が`FLAG`と等しいことを明示的に確認しています。

```py
print( ... )
```
は、文字列をコンソールに出力します。

文字列は`"..."`または`'...'`で囲みます。

文字列の前にfを付けると、その中で`{ ... }`の中に書いた式が展開されるようになります。
```py
A | B
```
は、`A`と`B`のビット論理和（OR）を表します。少なくとも片方のビットが`1`のところだけ`1`になります。
```py
A ^ B
```
は、`A`と`B`のビット排他的論理和（XOR）を表します。どちらか片方のビットだけが`1`のところだけ`1`になります。

さて、今回の配布ファイルにはchall.pyの他にoutput.txtがあります。

これは、正しいフラグで実行したらこのような出力になったよ、ということを表すもので、これもCTFではよく見ます。

output.txtの内容を解析し、どんなフラグだったらこのような出力になるのかな？というのを逆算して求めていく形式の問題が多いようです。

## 解法

ではここから、与えられた`A or B`と`A xor B`を使って`A + B`を求めていきます。

`A or B`は、`A`と`B`のそれぞれのビットが、少なくとも1つのビットが`1`であるときに`1`、両方`0`のときに`0`になります。

`A xor B`は、`A`と`B`のそれぞれのビットが、ちょうど1つのビットが`1`であるときに`1`、それ以外のときに`0`になります。

簡単な例を見てみましょう。`A = 9`, `B = 12`とします。
```
      8 4 2 1
A= 9: 1 0 0 1
B=12: 1 1 0 0
```
このとき、
```
            8 4 2 1
A or B =13: 1 1 0 1
A xor B =5: 0 1 0 1
```
となります。

この結果からわかるように、`A`だけ`1`の部分と`B`だけ`1`の部分は区別することができません。

なので、実はこの問題`A`と`B`の値そのものを特定することはできません。

しかし、求めたいのは`A + B`だけなので、`A`と`B`を個別に特定する必要はありません。

さて、`1`のところの桁を全て足したものが合計値になるわけですが、どうせ区別できないんだったら、片方だけ`1`のところは全て`A`に寄せて考えてみましょう。
```
       8 4 2 1
A'=13: 1 1 0 1
B'= 8: 1 0 0 0
```
実際、`9 + 12 == 13 + 8`なので、合計は変わらないことがわかります。

こうすると、`A'`は`A or B`と同じになります。どちらかが`1`なら`A`に寄って来るのでそれはそうでしょうね。

あとは`B'`が求まればいいですが、どうすればいいでしょうか？

この状況において`B'`に`1`が残るのは両方とも`1`のときだけなので、ビット論理積（AND）になります。

与えられた情報から`A and B`を求めるには、`A or B`から`A xor B`を引きます。

これは、`1`の数が1,2個のケース(OR)から1個のケース(XOR)を除くと2個のケース(AND)が残るからです。

※`A or B`と`A xor B`の否定を`and`して`AorB & (~AxorB)`としてもいいです。ビット演算に慣れている人ならこっちの方が直感的でわかりやすいかもしれません。

以上より、`A' == A or B`, `B' == A and B`, `FLAG == A + B == A' + B'`であることがわかりました。

あとはこれを求めてバイナリに逆変換すればフラグを得ることができます。

## 開発環境準備

※Pythonのソースコードの実行のしかたがわからない方を対象としています。実行できる方は飛ばしてください。

※私の実施環境がWindows環境なので、Windows環境を想定しています。

### 1. Pythonのインストール

[Pythonの公式サイト](https://www.python.org/)を開き、Downloadsメニューからインストーラーをダウンロードします。（今だと3.14.6かな。）

インストールは基本そのまま進めていけばいいですが、１つだけ注意しなければならないことがあります。

最初の「Install Now」をクリックする前に、一番下の「□ Add python.exe to PATH」に**必ずチェックを付けてください**。（忘れるとあとで面倒になります。）

### 2. VSCodeのインストール

別にメモ帳とかでコードを書いても良いんですが、とくにこだわりが無ければVSCode(Visual Studio Code)をインストールして使用することをおすすめしたいです。

[VSCodeの公式サイト](https://code.visualstudio.com/)からインストーラーをダウンロードします。（※Windows以外はわかりません、ごめんなさい。）

インストールできたら、左の拡張機能(Extensions 田のようなアイコン)から、`Python`(発行元:Microsoft)を選んでインストールします。

メニューを日本語化したいときは、`Japanese Language Pack for VS Code`もインストールします。

### 3. 作業フォルダとソースファイル作成

適当な作業フォルダを作成します。ここでは`C:\AlpacaHack`とします。

VSCodeで、ファイル(File)→フォルダを開く(Open Folder)で作業フォルダを選択します。

左側のエクスプローラーにフォルダ名`AlpacaHack`が出てくるので、その下あたりで右クリック→新しいファイルでファイル名（例えばsolve.py）を入力すると、空のファイルが作成されます。

※運用上は、問題ごとにサブフォルダを分けたり、またDaily AlpacaHackでは毎日のように作っていくのでさらに月ごとに分けたりしても良いかもしれません。

ファイル名solve.pyをクリックすると中央のエディタで開くので、試しに次の1行を入力、保存してみます。
```py
print("hello")
```

### 4. 実行

右上の▷（三角ボタン）をクリックすると、プログラムが実行され、下にターミナルが現れて次のように表示されるはずです。
```
hello
```
※「制限モード」になっていると右上の▷ボタンが出ないことがあるようです。左下の「制限モード」をクリックし、間違いなく自分が作ったファイルやフォルダであることを確認したら、「信頼する」にしてください。

## ソルバー作成

CTF等で問題を解くためのプログラムを「ソルバー」というようです。これを作っていきます。

数値からバイナリへ逆変換をするので、long_to_bytesをインポートしておきます。
```py
from Crypto.Util.number import long_to_bytes
```

※もし実行時にModuleNotFoundErrorが発生する場合は、ターミナルで下記を実行してモジュールをインストールしてください。
```
pip install pycryptodome
```

次に、出力の値を使いたいので、output.txtの内容をコピペします。ただし、空白が入った変数名は使えないので、詰めるとかアンダーバーで置き換えるとかの措置が必要です。
```py
AorB = 1708520672692343497693425015709016883325158039728511260268583494549501
AxorB = 1653224853895272618878301831150773792186632776885840473347068872416893
```

そして、前記「解法」で確認した手順で`A + B`を求めます。
```py
AandB = AorB - AxorB
AplusB = AorB + AandB
```

最後に、バイナリに戻したフラグを表示します。
```py
flag = long_to_bytes(AplusB)
print(f"{flag = }")
```
※`{変数 = }`のように`=`を付けておくと変数名も一緒に出してくれるので確認に便利です。

※この`flag`はバイナリなので出力時に`b"..."`のように前に`b`が付きます。気になる場合は`.decode()`しましょう。

まとめると下記のようになります。
```py
from Crypto.Util.number import long_to_bytes

AorB = 1708520672692343497693425015709016883325158039728511260268583494549501
AxorB = 1653224853895272618878301831150773792186632776885840473347068872416893

AandB = AorB - AxorB
AplusB = AorB + AandB

flag = long_to_bytes(AplusB)
print(f"{flag = }")
```

## その他

私は7か月前このDaily AlpacaHackでCTFを始めましたが、プログラミングについてはもっと前から触っていました。

なので、このような問題には何の抵抗もなく入ることができましたが、中には「CTFには興味あるけど、プログラミングはちょっとなぁ…」という方もいるかもしれません。

そのような方の手助けや、続けてみようというきっかけに、この投稿が少しでもお役に立てたら幸いです。
