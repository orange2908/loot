---
title: "sus - sekaictf 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "sus", "miscellaneous", "sekaictf", "project-sekai-ctf", "sekaictf-2022"]
summary: "The italicized words in the challenge description suggests the game Project SEKAI: Colorful Stage!"
source:
  name: "project-sekai-ctf/sekaictf-2022"
  url: "https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/sus/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2022
  challenge: "sus"
---

## Source

- **CTF:** sekaictf 2022
- **Challenge:** sus
- **Repository:** [project-sekai-ctf/sekaictf-2022](https://github.com/project-sekai-ctf/sekaictf-2022)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/sus/solution/README.md>

---
# Writeup

The italicized words in the challenge description suggests the game [*Project SEKAI: Colorful Stage! feat. Hatsune Miku*](https://www.colorfulstage.com/) alongside a custom charting server, [*Purple Palette*](https://github.com/PurplePalette). Reading the [tutorial](https://wiki-en.purplepalette.net/create-charts/steps/preview-chart) of the custom chart server, we see that the `.sus` ඞ filename extension is used to define custom charts:

> **JP**: 譜面データ (\*.sus) を画像に書き起こしたい場合 このページを参照してください  
> **ENG**: If you want to transcribe score data (\*.sus) into an image, please refer to this page.

If you didn't get the hint, you can also Google "[Project SEKAI SUS file](https://www.google.com/search?q=project+sekai+sus+file)", which will lead you directly to the [SekaiSUS2img](https://github.com/k0tayan/SekaiSUS2img) repository:

![SekaiSUS2img repository card](https://opengraph.githubassets.com/1c4c9b8ed85ff097dc334917facda6fcc297bd426756f8eed99feb46b522f295/k0tayan/SekaiSUS2img)

Boot the `.sus` file into the [website](https://sekai-sus-2img.vercel.app/), and we can see the flag drawn letter by letter with sliders:

![Preview of the chart](https://raw.githubusercontent.com/project-sekai-ctf/sekaictf-2022/383b16da68c438c5d516e6f00b2716210141f7a4/misc/sus/solution/rendering.svg)

The flag is `SEKAI{SbtnFmnW2HnYbdDkryunTkrrtims}`.

> **RM**: **S**u**b**e**t**e**n**o **F**u**m**e**n** **W**a **2** **H**o**n** **Y**u**b**i**d**e **D**e**k**i**r**u**y**o**un**i **T**su**k**u**r**a**r**e**t**e**im**a**s**u.  
> **JP**: 全ての譜面は二本指でできるように作られています。  
> **EN**: All charts are made to be playable with two fingers.

## Credit

- Editor: [PaletteWorks](https://paletteworks.mkpo.li/)
- Imager: [SekaiSUS2img](https://github.com/k0tayan/SekaiSUS2img)
