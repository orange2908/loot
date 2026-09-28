---
title: "web/scrainbow - Lexington Informatics Tournament CTF 2024"
category: "web"
type: "writeup"
tags: ["web", "scrainbow", "lexington-informatics-tourname", "lexington-informatics-tournament-c", "2024", "ctf-writeup"]
summary: "Challenge URL: <http://litctf.org:31780/>"
source:
  name: "CTFtime writeup #39389"
  url: "https://ctftime.org/writeup/39389"
original_source: "https://github.com/Team-Kirby/litctf-2024-writeups/tree/main/web/scrainbow"
ctf:
  name: "Lexington Informatics Tournament CTF 2024"
  year: 2024
  challenge: "web/scrainbow"
---

## Metadata

- **CTF:** Lexington Informatics Tournament CTF 2024
- **Task:** web/scrainbow
- **Author team:** Team Kirby
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39389>
- **Original writeup:** <https://github.com/Team-Kirby/litctf-2024-writeups/tree/main/web/scrainbow>

---
# Scrainbow 

Challenge URL: <http://litctf.org:31780/>  
![](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/Pasted%20image%2020240813171726.png>)  
![](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/Pasted%20image%2020240813171834.png>)

# Solution

Scrainbow is a challenge that requires user to perform pixel swap (`rearrange the grid to be a rainbow gradient from top left to bottom right (red -> rainbow -> red)`), and then click the `Test` button to check if they have solved the puzzle.

If you open and check the network requests, you would find a few friends:

1\. The /data api that returns you the array of 10000 colors that are to be sorted. ![](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/Pasted%20image%2020240813172154.png>)  
2\. The /test api that sends your "swap positions" as an array in the payload to the checking server.![](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/Pasted%20image%2020240813172339.png>)

The result should appear as the figure below:  
![](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/Pasted%20image%2020240813171747.png>)

And if you use python counter on the data, you would see that there are 199 unique colors, with reoccurrence of from 100 to 1.

``` Python  
Counter({'#00fff7': 100, '#00fff0': 99, '#00ffff': 99, '#00f7ff': 98, '#00ffe8': 98, '#00f0ff': 97, '#00ffe0': 97, '#00ffd9': 96, '#00e8ff': 96, '#00ffd1': 95, '#00e0ff': 95, '#00d9ff': 94, '#00ffc9': 94, '#00ffc2': 93, '#00d1ff': 93, '#00ffba': 92, '#00c9ff': 92, '#00c2ff': 91, '#00ffb3': 91, '#00ffab': 90, '#00baff': 90, '#00b2ff': 89, '#00ffa3': 89, '#00abff': 88, '#00ff9c': 88, '#00ff94': 87, '#00a3ff': 87, '#009cff': 86, '#00ff8c': 86, '#0094ff': 85, '#00ff85': 85, '#008cff': 84, '#00ff7d': 84, '#0085ff': 83, '#00ff75': 83, '#00ff6e': 82, '#007dff': 82, '#0075ff': 81, '#00ff66': 81, '#006eff': 80, '#00ff5e': 80, '#00ff57': 79, '#0066ff': 79, '#00ff4f': 78, '#005eff': 78, '#0057ff': 77, '#00ff47': 77, '#004fff': 76, '#00ff40': 76, '#00ff38': 75, '#0047ff': 75, '#00ff30': 74, '#0040ff': 74, '#0038ff': 73, '#00ff29': 73, '#0030ff': 72, '#00ff21': 72, '#00ff19': 71, '#0029ff': 71, '#0021ff': 70, '#00ff12': 70, '#00ff0a': 69, '#0019ff': 69, '#0012ff': 68, '#00ff03': 68, '#05ff00': 67, '#000aff': 67, '#0003ff': 66, '#0dff00': 66, '#14ff00': 65, '#0500ff': 65, '#1cff00': 64, '#0d00ff': 64, '#1400ff': 63, '#24ff00': 63, '#2bff00': 62, '#1c00ff': 62, '#2400ff': 61, '#33ff00': 61, '#2b00ff': 60, '#3bff00': 60, '#3300ff': 59, '#42ff00': 59, '#4aff00': 58, '#3b00ff': 58, '#4200ff': 57, '#52ff00': 57, '#4a00ff': 56, '#59ff00': 56, '#5200ff': 55, '#61ff00': 55, '#5900ff': 54, '#69ff00': 54, '#70ff00': 53, '#6100ff': 53, '#78ff00': 52, '#6900ff': 52, '#80ff00': 51, '#7000ff': 51, '#87ff00': 50, '#7800ff': 50, '#8fff00': 49, '#8000ff': 49, '#8700ff': 48, '#96ff00': 48, '#9eff00': 47, '#8f00ff': 47, '#9600ff': 46, '#a6ff00': 46, '#9e00ff': 45, '#adff00': 45, '#a600ff': 44, '#b5ff00': 44, '#bdff00': 43, '#ad00ff': 43, '#b500ff': 42, '#c4ff00': 42, '#bd00ff': 41, '#ccff00': 41, '#c400ff': 40, '#d4ff00': 40, '#cc00ff': 39, '#dbff00': 39, '#d400ff': 38, '#e3ff00': 38, '#db00ff': 37, '#ebff00': 37, '#f2ff00': 36, '#e300ff': 36, '#eb00ff': 35, '#faff00': 35, '#f200ff': 34, '#fffc00': 34, '#fff500': 33, '#fa00ff': 33, '#ff00fc': 32, '#ffed00': 32, '#ff00f5': 31, '#ffe600': 31, '#ff00ed': 30, '#ffde00': 30, '#ffd600': 29, '#ff00e6': 29, '#ffcf00': 28, '#ff00de': 28, '#ffc700': 27, '#ff00d6': 27, '#ff00cf': 26, '#ffbf00': 26, '#ffb800': 25, '#ff00c7': 25, '#ffb000': 24, '#ff00bf': 24, '#ffa800': 23, '#ff00b8': 23, '#ff00b0': 22, '#ffa100': 22, '#ff00a8': 21, '#ff9900': 21, '#ff9100': 20, '#ff00a1': 20, '#ff8a00': 19, '#ff0099': 19, '#ff8200': 18, '#ff0091': 18, '#ff7a00': 17, '#ff008a': 17, '#ff0082': 16, '#ff7300': 16, '#ff6b00': 15, '#ff007a': 15, '#ff6300': 14, '#ff0073': 14, '#ff006b': 13, '#ff5c00': 13, '#ff0063': 12, '#ff5400': 12, '#ff005c': 11, '#ff4c00': 11, '#ff0054': 10, '#ff4500': 10, '#ff004c': 9, '#ff3d00': 9, '#ff3600': 8, '#ff0045': 8, '#ff2e00': 7, '#ff003d': 7, '#ff2600': 6, '#ff0036': 6, '#ff1f00': 5, '#ff002e': 5, '#ff1700': 4, '#ff0026': 4, '#ff001f': 3, '#ff0f00': 3, '#ff0017': 2, '#ff0800': 2, '#ff000f': 1, '#ff0000': 1})  
```

The 1s denote the 2 top left and bottom right corner, and the number of pixels required increase as it approach center.

See my [script](<https://github.com/Team-Kirby/litctf-2024-writeups/blob/main/web/scrainbow/solve.py>) for the full solution!
