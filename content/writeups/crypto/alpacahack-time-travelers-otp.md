---
title: "Time Travelers OTP - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "cyberchef", "base32", "time", "travelers", "otp"]
summary: "crypto writeup for \"Time Travelers OTP\" from AlpacaHack Daily - techniques: alpacahack, cyberchef, base32, time, travelers, otp."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d22_Time_Travelers_OTP/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Time Travelers OTP"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Time Travelers OTP
- **Date:** 2026-05-22
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d22_Time_Travelers_OTP>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d22_Time_Travelers_OTP/README.md>

---
# Time Travelers' OTP

## 問題

4000年後もAlpacaHackは続いているでしょうか？

```js
app.post("/auth", async (c) => {
  const code = await c.req.text();

  if (code === getCurrentTOTP(secret)) {
    if (!isYearInFuture()) {
      return c.json({
        message: "Correct code. Come back again in 4000 years.",
      });
    } else {
      return c.json({
        message: `Finally you get the flag: ${flag}`,
      });
    }
  } else {
    return c.json({ error: "The code is incorrect." }, 401);
  }
});
```

## 概要

OTP(One Time Password)は、1回しか使えない使い捨てのパスワードの総称です。SMSで送られてくる認証コードなどで見たことがある方も多いと思います。

そのうち、今回の問題のように一定時間（標準は30秒）で区切った現在時刻を使って発行されるものをTOTP(Time-based One Time Password)といいます。

この問題のサーバーでは、2つのサービス`current`と`future`が稼働しています。

ブラウザで`current`にアクセスすると、現在時刻、QRコード、手動登録用のコードと、6桁の認証コードを入力できる検証用のフォームが表示されます。

実際に自分のiPhoneのMicrosoft AuthenticatorアプリにQRコードや手動登録用コードを使って登録し、認証をすることができました。

しかし、これではフラグを得ることはできません。

次に`future`にアクセスすると、現在時刻ではなく6019年6月14日の日時が表示されます。(`compose.yaml`をみると、128849018790秒先の時刻になっていることがわかります。)

この果てしない未来に発行されるであろう認証コードを入力することでフラグを得ることができるようです。

どうすればそんな未来の認証コードを得ることができるのでしょうか？

## 方針

ローカル環境でソースコードを書き換えて本番環境の認証コードの生成を再現する。

## 解法

※作問者が想定した解法であるかどうかはあまり自信ないです……

認証コードは、フラグをハッシュ化した`secret`と現在時刻（30秒刻み）から生成されるようです。

ということは、ローカル環境でもこの`secret`と時刻を合わせれば正しいコードを得ることができるのではないでしょうか？

まず、本番環境の`current`にアクセスし、画面に表示されている`MANUAL SETUP CODE`を取得します。
```
MQJZZVVPER3OXQ432ZS2LHPAEPHWWKAA
```

このコードは`secret`をBase32でエンコードしたものなので、例えば[CyberChef](https://gchq.github.io/CyberChef/)を使って`From Base32`+`To Hex`で`secret`の16進数値を得ます。[実行例](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',true)To_Hex('None',0)&input=TVFKWlpWVlBFUjNPWFE0MzJaUzJMSFBBRVBIV1dLQUE)
```
64139cd6af2476ebc39bd665a59de023cf6b2800
```

`secret`の16進数値を取得できたら、`index.js`の`secret`をセットしている部分をこの値に書き換えてしまいます。
```js
//const secret = crypto.createHash("sha1").update(flag).digest();
const secret = Buffer.from("64139cd6af2476ebc39bd665a59de023cf6b2800", "hex");
```

そして、チェックするところで正しいコードを出力してみます。
```js
  console.log("correct code: " + getCurrentTOTP(secret));
  if (code === getCurrentTOTP(secret)) {
    ...
```

この状態でローカル環境の`future`にアクセスし`123456`などのてきとーな値を送ると、`docker compose up`したコンソールに正しいコードが出力されます。
```
future-1  | correct code: 671366
```

この認証コードを本番環境の`future`で時刻に気を付けつつ送信し、フラグをゲットします。

※ローカルの時計を少し進めておくと余裕をもって楽に行うことができます。

## その他

認証コードを盗まれても30秒で無効になるけど、秘密鍵を盗まれると未来永劫自由に認証コードを生成できてしまうのでとても危険だよ、というお話でした。

しかも6019年というインパクト大な問題で面白かったです。

この問題の作成者のnozokareさんは、私が初めての問題作成をしたときにご自身のWriteupの中で「CTF初心者だけど頑張っているbaumroll1234さんを陰ながら応援している（要約）」とおっしゃってくれた方です。

問題作成もしてみたいとおっしゃっていたので、それならば、nozokareさんが出題をされたあかつきには、私としてはやはりファンサとして（？）なんとしても24時間以内に解いて次の日に真っ先にWriteupを投稿しようと思っていました。

ところで、問題文の
```
4000年後もAlpacaHackは続いているでしょうか？
```
ですが、もし4000年も続いていたらDailyだけでも365問/年 × 4000年 = 146万問というとんでもない問題数になってしまいますね（笑）

ただ間違いなく言えるのは今この問題を解いている私たちはその頃には絶対に生きていないということなので、後世の人たちに託すことにしましょう（笑）
