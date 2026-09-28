---
title: "[GamePwn] Insert Coin 2 - UniVsThreats 25 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "gamepwn", "insert", "coin", "univsthreats-25-ctf", "ctf-writeup"]
summary: "Insert coin to play Part [1-2] - UnivsthreatsCTF2025"
source:
  name: "CTFtime writeup #40233"
  url: "https://ctftime.org/writeup/40233"
original_source: "https://k3sero.github.io/posts/Insert-coin-to-play-UniVsThreatsCTF2025/#insert-coin-to-play-part-2"
ctf:
  name: "UniVsThreats 25 CTF"
  challenge: "[GamePwn] Insert Coin 2"
---

## Metadata

- **CTF:** UniVsThreats 25 CTF
- **Task:** [GamePwn] Insert Coin 2
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40233>
- **Original writeup:** <https://k3sero.github.io/posts/Insert-coin-to-play-UniVsThreatsCTF2025/#insert-coin-to-play-part-2>

---
Insert coin to play Part [1-2] - UnivsthreatsCTF2025 __

Contenido __

Insert coin to play Part [1-2] - UnivsthreatsCTF2025

__

Autor del reto: `sc0F`

Dificultad: Fácil

## Introducción __

En este post, se verán los retos`Insert coin to play Part 1` y `Insert coin to play Part 2`, ambos tematizados en el mismo ejercicio.

## Insert coin to play Part 1 __

### Enunciado __

“A lone cube awakens in an earthen box, the painted sky and silent peaks beckoning through the walls. The coin counter demands ten, but only five gleam in plain sight. Somewhere in the shadows of the game’s memory, the missing coins await discovery. Strike the counter’s memory until it reads “10,” and let the mystery unfold.”

###  Archivos __

Este reto, tenemos el siguiente archivo.

  * `Insert coin to play - Part 1.rar` : Carpeta de archivos necesarios para ejecutar el juego.


Archivos utilizados en mi [repositorio de Github](https://drive.google.com/drive/folders/1zl7a9cuc_UhSyukWFGzUdot7X18UY0e7?usp=sharing).

### Analizando el reto __

Una vez tengamos la carpeta descomprimida, tendremos que ejecutar el binario`GTA5.exe`.

[![ejecu](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png)

Nuestra misión será conseguir las 10 monedas para que el juego nos arroje la flag, pero es sencillo, ¿no?

### Solver __

Como he mencionado anteriormente, tenemos que conseguir las 10 monedas, pero en el escenario en el que se encuentra nuestro personaje solo tenemos acceso a 5 de ellas, el resto no aparecerán.

Para conseguir modificar el registro del contador de nuestras monedas, utilizaremos el software `Cheat Engine`

Para ello, ejecutaremos nuestro binario.exe y ejecutaremos `Cheat Engine`, para posteriormente añadir el proceso del binario.exe en `Cheat Engine` y acto seguido ir filtrando por las direcciones de memoria.

Como el contador empieza por 0 monedas, buscaremos registros cuyas direcciones de memoria tengan 0 en su interior. Posteriormente cogemos una moneda y buscaremos la siguiente ocurrencia por un valor de 1 en el registro. Realizando el paso anterior varias veces, nos daremos cuenta de que solo tenemos 3 direcciones potenciales donde se guardan el contador de monedas.

Lo siguiente será cambiar el valor de los registros mencionados por 10 y acto seguido para actualizar el contador, cogeremos una de las monedas que quedan en el escenario

[![Cheat_Engine](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/cheat.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/cheat.png)

Al hacerlo, nos saldrá la flag por pantalla.

[![flag_1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/flag.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/flag.png)

### Flag __

`UVT{L00ks_l1K3_Th3r3_w3R3_M0r3_c01N5}`

##  Insert coin to play Part 2 __

### Enunciado __

“A lone cube returns to the same earthen area where ten coins now glint at every corner. Nine surrender easily, but the tenth eludes your grasp, slipping through the cracks of reality until it vanishes. A secret forge exists, quietly stamping new coins for those who dare to listen.”

###  Archivos __

Este reto nos da el siguiente archivo.

  * `Insert coin to play - Part 2.rar` : Carpeta con los archivos necesarios para ejecutar el juego.


Archivos utilizados [aquí](https://drive.google.com/drive/folders/1zl7a9cuc_UhSyukWFGzUdot7X18UY0e7?usp=sharing).

### Analizando el reto __

Una vez tengamos la carpeta descomprimida, tendremos que ejecutar el binario`GTA6.exe`.

[![ejecu](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png)

Nuestra misión será conseguir las 10 monedas para que el juego nos arroje la flag, pero es sencillo no?

### Solver __

En este caso, en el escenario se encuentran las 10 monedas que necesitamos para que nos arroje la flag, pero justo cuando intentamos obtener la décima, esta moneda será como un imán con el personaje y nunca la podremos obtener, ya que la repeleremos. Al obtener la penúltima moneda obtendremos el siguiente mensaje.

[![err_msg](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/err_msg.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/err_msg.png)

En este caso, utilizaremos nuevamente `Cheat Engine` para resolver este reto, pero en vez de filtrar por direcciones de memoria para introducir valores a nuestra voluntad, utilizaremos la herramienta de hipervelocidad, para engañar al juego en el último momento y obtener la décima moneda forzando al juego a que no ejecute la función que repele la última moneda.

Como tenemos dos monedas en el suelo, tendremos que coger todas las demás para que en el último momento, activemos el cheat de la hipervelocidad y acto seguido recoger las dos últimas monedas del tirón.

[![cheat_engine_hipervelocidad](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/paint2.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/paint2.png)

Al hacerlo, obtendremos la flag por pantalla.

[![flag2](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/flag2.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/flag2.png)

### Flag __

`UVT{Wh4t?!_D1d_Y0u_r3aLly_c4TcH_1t?}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [GamePwn](https://k3sero.github.io/categories/gamepwn/)

__[GamePwn](https://k3sero.github.io/tags/gamepwn/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [UnivsthreatsCTF](https://k3sero.github.io/tags/univsthreatsctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Insert%20coin%20to%20play%20Part%20\[1-2\]%20-%20UnivsthreatsCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInsert-coin-to-play-UniVsThreatsCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Insert%20coin%20to%20play%20Part%20\[1-2\]%20-%20UnivsthreatsCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInsert-coin-to-play-UniVsThreatsCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FInsert-coin-to-play-UniVsThreatsCTF2025%2F&text=Insert%20coin%20to%20play%20Part%20\[1-2\]%20-%20UnivsthreatsCTF2025%20-%20Kesero "Telegram") __
