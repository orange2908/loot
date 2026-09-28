---
title: "vocaloid heardle - sekaictf 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "vocaloid", "heardle", "miscellaneous", "vocaloid-heardle", "sekaictf"]
summary: "vocaloidheardle.py suggests that the music file was generated based on the contents of an unprovided flag.txt, and choosing .mp3 files from the downloaded .json."
source:
  name: "project-sekai-ctf/sekaictf-2022"
  url: "https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/vocaloid-heardle/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2022
  challenge: "vocaloid heardle"
---

## Source

- **CTF:** sekaictf 2022
- **Challenge:** vocaloid heardle
- **Repository:** [project-sekai-ctf/sekaictf-2022](https://github.com/project-sekai-ctf/sekaictf-2022)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/vocaloid-heardle/solution/README.md>

---
# Writeup

`vocaloid_heardle.py` suggests that the music file was generated based on the contents of an unprovided `flag.txt`, and choosing `.mp3` files from the downloaded `.json`.

Thus, download the `.json` and `.mp3` files, and match each 3-second segment against the downloaded files to see which songs are included. Then, match the ID of each song to get the flag.

Players can match the tracks manually if they want to; it's also possible to use tools like [dejavu](https://github.com/worldveil/dejavu) for automation.

Flag: `SEKAI{v0CaloId<3u}`

> Vocaloid ❤️ U

## Credit

* [＊ハロー、プラネット。 / sasakure.UK](https://youtu.be/1gHHgx8bTxc)
* [ワールドイズマイン / ryo (supercell)](http://www.nicovideo.jp/watch/sm3504435)
* [自傷無色 / ねこぼーろ（ササノマリイ）](http://www.nicovideo.jp/watch/sm19870840)
* [霽れを待つ / Orangestar](https://youtu.be/wvlUWjqGQSA)
* [愛されなくても君がいる / ピノキオピー](https://youtu.be/ygY2qObZv24)
* [カトラリー / 有機酸](https://youtu.be/HHhFX9zUV2s)
* [ニア / 夏代孝明](http://www.nicovideo.jp/watch/sm31477166)
* [ECHO / Crusher](https://youtu.be/cQKGUgOfD8U)
* [悔やむと書いてミライ / まふまふ](https://youtu.be/jUyCN1229Ws)
* [セカイはまだ始まってすらいない / ピノキオピー](https://youtu.be/1s8NNPgdl5g)
* [ODDS & ENDS / ryo (supercell)](https://youtu.be/6OmwKZ9r07o)
