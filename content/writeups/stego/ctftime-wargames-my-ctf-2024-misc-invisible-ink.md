---
title: "[Misc] Invisible Ink - Wargames.MY CTF 2024"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "stegsolve", "misc", "invisible", "ink", "image", "wargames-my-ctf", "wargames-my-ctf-2024", "2024", "ctf-writeup"]
summary: "Invisible Ink - WarGamesCTF2024"
source:
  name: "CTFtime writeup #39735"
  url: "https://ctftime.org/writeup/39735"
original_source: "https://k3sero.github.io/posts/Invisible-Ink-WarGamesCTF2024/"
ctf:
  name: "Wargames.MY CTF 2024"
  year: 2024
  challenge: "[Misc] Invisible Ink"
---

## Metadata

- **CTF:** Wargames.MY CTF 2024
- **Task:** [Misc] Invisible Ink
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39735>
- **Original writeup:** <https://k3sero.github.io/posts/Invisible-Ink-WarGamesCTF2024/>

---
Invisible Ink - WarGamesCTF2024 __

Contenido __

Invisible Ink - WarGamesCTF2024

__

Autor del reto: `Yes`

Dificultad: Fácil

## Enunciado __

“The flag is hidden somewhere in this GIF. You can’t see it? Must be written in transparent ink.”

##  Archivos __

En este reto, solo nos dan el siguiente archivo.

  * `challenge.gif` : Contiene un archivo .gif.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink).

## Analizando el código __

En este reto básicamente tenemos que extraer la información del gif aportado. Si abrimos dicho archivo, nos encontraremos con un mensaje sin mayor relevancia.

[![challenge](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/gif.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/gif.png)

##  Solución __

En este caso, teníamos que utilizar[stegsolve](https://wiki.bi0s.in/steganography/stegsolve/) para obtener todos los frames que contaba dicho gif, ya que si queremos extraerlos con herramientas como Pillow, nos da error debido a la gran cantidad de píxeles que contiene el gif. (Pillow sólo obtenía los frames 0, 1, 2 y 3, pero nos decía que los frames resultantes superaban el máximo de píxeles permitidos)

Para ello teníamos que obtener los frames resultantes que es donde realmente está la información oculta. Para ello utilicé la herramienta mencionada anteriormente para la extracción de estos dos últimos frames.

[![Frame5](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame5.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame5.png)

[![Frame6](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame6.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame6.png)

Finalmente, para obtener la flag, tenemos que combinar los frames anteriores. En Gimp, simplemente tenemos que añadir cada imagen a una capa diferente, no sin antes aplicar un color distinto a cada frame, para que el resultado sea mucho más visible que en blanco y negro.

[![Final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/final.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/final.png)

## Flag __

`wgmy{d41d8cd98f00b204e9800998ecf8427e}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Esteganografía](https://k3sero.github.io/categories/esteganograf%C3%ADa/)

__[Estego](https://k3sero.github.io/tags/estego/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [WarGamesCTF](https://k3sero.github.io/tags/wargamesctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Invisible%20Ink%20-%20WarGamesCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInvisible-Ink-WarGamesCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Invisible%20Ink%20-%20WarGamesCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInvisible-Ink-WarGamesCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInvisible-Ink-WarGamesCTF2024%2F&text=Invisible%20Ink%20-%20WarGamesCTF2024%20-%20Kesero "Telegram") __
