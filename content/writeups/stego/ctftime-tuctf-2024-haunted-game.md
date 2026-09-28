---
title: "Haunted Game - TUCTF 2024"
category: "stego"
subcategory: "audio"
type: "writeup"
tags: ["stego", "spectrogram", "haunted", "game", "audio", "tuctf", "tuctf-2024", "2024", "ctf-writeup"]
summary: "We are provided with zip containing simple game written in Unity."
source:
  name: "CTFtime writeup #39834"
  url: "https://ctftime.org/writeup/39834"
original_source: "https://adamzvara.github.io/writeups/writeups/2025/TUCTF/Haunted-Game.html"
ctf:
  name: "TUCTF 2024"
  year: 2024
  challenge: "Haunted Game"
---

## Metadata

- **CTF:** TUCTF 2024
- **Task:** Haunted Game
- **Author team:** BlitzHack
- **CTFtime:** <https://ctftime.org/writeup/39834>
- **Original writeup:** <https://adamzvara.github.io/writeups/writeups/2025/TUCTF/Haunted-Game.html>

---
We are provided with zip containing simple game written in Unity. After running the game you can explore the map and collect notes, which often include some kind of hints about the challenge. The "gameplay" is interrupted by random ghosts appearing on screen with some kind of sound playing in the background. I've come across 3 different notes while playing the game. They included the following hints:  
\- there are **12** ghosts in total  
\- each of them communicates in **spectral sounds**  
\- ghosts have age - some of them are younger and some older - this is determined by how **visible** they are and the note called one ghost **Alpha**

From these hints I've formed a plan:  
\- try to search for assets included in the game, which should include ghost images and audio samples  
\- do spectral analysis over audio files, pair them with ghosts  
\- order ghosts and get the flag

At first, I didn't know how to recover any assets from the game, and I couldn't find any directly in the files. After some googling I came across this [article](<https://github.com/imadr/Unity-game-hacking>), which explains some structure behind Unity files and provides links to tools for extracting assets from them. I downloaded the first asset thing I could find: [AssetRipper](<https://github.com/AssetRipper/AssetRipper>). 

I opened the folder `MyFirstGame_Data` and tried searching for any images. 

I was able to find some interesting files in `sharedassets0.assets`. This asset file contains images of the ghosts and notes, which are being displayed to user in the game.

From this I was able to extract all 12 images of the ghosts. I also recovered one note, which I've missed when playing the game, but this will be useful later. I was not able to recover audio files this way. So I've decided to run the game and record audio in audacity to get the audio recordings for each ghosts (I've also recorded the screen so I could easily pair the audio recording with individual ghost). Audacity also supports showing the spectrum for your audio recording!

*Note: after finishing the challenge someone in discord channel mentioned that the audio files are in the same directory as image files, so there is no need to manually extract them from the game.*

Now I had to match the extracted values with ghosts and sort the ghosts by visibility (alpha value). I opened the images in Inkscape, ordered them and assigned the flag parts. Now is the time to revisit the note, which I've missed. It says:

> All of them speak in threes, but they often speak out of order. However, the ghosts also seem to have some kind of hex that also has three components. If I match those up from left to right and then reorder the pairs so the hex is from smallest to largest, maybe I can reassemble the ghosts' message... 

This means that for each ghost, we need to take it's color and split it into 3 chunks. Then sort these chunks and this will give us the correct positions for the three letters (e.g if ghost has color `237057`, then the correct ordering of letters is `[0, 2, 1]` because `23|57|70` is the correct order). Here is a python script to sort the letters:

```python  
strings = ["TUC", "F{T", "GOH", "S_T", "_NI", "ETH", "AM_", "ICH", "EN_", "210", "019", "18}"]  
colors = ["040969", "63e334", "237057", "17cfc1", "d41c08", "3d2d35", "c96a16", "4d0611", "3f064f", "1a4b09", "105fe0", "ee0ff2"] 

result = []  
for (f, o) in zip(strings, colors):  
tmp = []  
parts = [o[i:i+2] for i in range(0, len(o), 2)]  
parts_old = parts.copy()  
parts.sort()  
for p in parts:  
tmp.append(f[parts_old.index(p)])  
result.append(''.join(tmp))

print("".join(result))  
```

After running the script we get the flag: `TUCTF{GHOST_IN_THE_MACHINE_02101981}`
