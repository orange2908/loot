---
title: "[Misc] NeoPrivSec - THCon 2K25 CTF"
category: "misc"
subcategory: "audio"
type: "writeup"
tags: ["morse", "gtfobins", "misc", "neoprivsec", "audio", "thcon-2k25-ctf", "ctf-writeup"]
summary: "We saw that Gideon Morse is a keen artist and that he loves beautiful things… perhaps a bit too much."
source:
  name: "CTFtime writeup #40192"
  url: "https://ctftime.org/writeup/40192"
original_source: "https://k3sero.github.io/posts/NeoPrivSec-THC2025/"
ctf:
  name: "THCon 2K25 CTF"
  challenge: "[Misc] NeoPrivSec"
---

## Metadata

- **CTF:** THCon 2K25 CTF
- **Task:** [Misc] NeoPrivSec
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40192>
- **Original writeup:** <https://k3sero.github.io/posts/NeoPrivSec-THC2025/>

---
NeoPrivesc - THCON2025 __

Contenido __

NeoPrivesc - THCON2025

__

Autor del reto: `nin70`

Dificultad: Fácil

## Enunciado __

We saw that Gideon Morse is a keen artist and that he loves beautiful things… perhaps a bit too much. Looks like he’s been into ricing his NixOS/LibreBoot/Hyprland/Astrovim/Neofetch/Btop a lot lately and we think this may help us.

We have access to a user session on his laptop but all important files are only available to administrator.

The -very secure- connexion info we gathered were bud:bud

## Archivos __

Este reto, nos dan los siguientes archivos.

  * `server.py` : Contiene el código que se ejecuta en el servidor.
  * `nc` : Instancia con netcat para acceder al reto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3_Continue).

## Analizando el reto __

Para conectarnos con dicha instancia, tenemos que hacerlo mediante`ssh`. Una vez dentro tendremos una bash con el usuario `bud:bud`

## Solver __

En este tipo de retos tenemos que encontrar la manera de escalar privilegios para poder leer el archivo deseado, en este caso`flag.txt`. Para ello realizaremos lo de siempre: mirar capabilities, permisos SUID entre otras.

En este caso, primero tenemos que ver los comandos que podemos ejecutar con permisos de root utilizando el comando `sudo -l`.

____

`

```
    1
    2
```

| 

```
        ┌──(kesero㉿kali)-[~]
        └─$ sudo -l
```  
  
---|---  
`

Una vez ejecutamos este comando, podemos observar que podemos ejecutar `neofetch` como administrador. Para ello nos iremos a [GTFobins](https://gtfobins.github.io/gtfobins/neofetch/) y obtendremos la inyección.

____

`

```
    1
    2
```

| 

```
        ┌──(kesero㉿kali)-[~]
        └─$ sudo -u blossom /usr/bin/neofetch neofetch --ascii /home/bud/flag.txt
```  
  
---|---  
`

## Flag __

`THC{Ne0f37CH_i5_B34u71fUL}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Misc](https://k3sero.github.io/tags/misc/) [Misc - Jail](https://k3sero.github.io/tags/misc-jail/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [THCONCTF](https://k3sero.github.io/tags/thconctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=NeoPrivesc%20-%20THCON2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FNeoPrivSec-THC2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=NeoPrivesc%20-%20THCON2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FNeoPrivSec-THC2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FNeoPrivSec-THC2025%2F&text=NeoPrivesc%20-%20THCON2025%20-%20Kesero "Telegram") __
