---
title: "[Misc] Strange Sightings - SpookyCTF 2024"
category: "misc"
subcategory: "audio"
type: "writeup"
tags: ["misc", "ftp", "ip", "morsecode", "video", "morse", "cyberchef", "audio", "spookyctf", "spookyctf-2024", "2024", "ctf-writeup"]
summary: "Strange Sightings - SpookyCTF2024"
source:
  name: "CTFtime writeup #39621"
  url: "https://ctftime.org/writeup/39621"
original_source: "https://k3sero.github.io/posts/Strange-Sightings-Miscelanea-SpookyCTF2024/"
ctf:
  name: "SpookyCTF 2024"
  year: 2024
  challenge: "[Misc] Strange Sightings"
---

## Metadata

- **CTF:** SpookyCTF 2024
- **Task:** [Misc] Strange Sightings
- **Author team:** Caliphal Hounds
- **CTFtime tags:** ftp, ip, morsecode, video
- **CTFtime:** <https://ctftime.org/writeup/39621>
- **Original writeup:** <https://k3sero.github.io/posts/Strange-Sightings-Miscelanea-SpookyCTF2024/>

---
Strange Sightings - SpookyCTF2024 __

Contenido __

Strange Sightings - SpookyCTF2024

__

Autor del reto: `Cyb0rgSw0rd`

Dificultad: Media

# Enunciado

“NICC agents were sent this video by an anonymous source. What does it mean?!

Warning: The video is very spooky.”

# Archivos

En este reto solo nos dan un enlace a un video de YouTube.

  * `https://www.youtube.com/watch?v=4Xv8pLoDVP0`: “Strange Sightings”


Video en mi [repositorio de Drive](https://drive.google.com/file/d/1lCyRp8TWrhw3XPwhtGK6F317hfYmq0fz/view?usp=sharing).

## Analizando el reto __

En este reto, básicamente tenemos un vídeo de 12 minutos el cual está basado en diversos clips con temática de terror de alrededor de 15 segundos cada uno en los que se van mostrando diversos lugares. ¿Alguna idea con estos retos?

Este tipo de retos se basan principalmente en descubrir pequeños detalles ocultos dentro de dichos clips, hay que analizarlo una y otra vez para encontrar alguna serie de patrones o pistas que nos lleven a la flag.

Es por ello que hay que tener mucha paciencia con ellos y visualizarlos detenidamente.

## Solución __

En este caso se encuentran diversas pistas relevantes a lo largo de la duración de los clips.

  1. Al comienzo se muestran carcteres de forma rápida los cuales uniéndolos forman la frase “COME GET YOUR FILE”
  2. Hay varias partes donde un hombre habla durante algunos segundos, pero esta pista no termina de ser relevante.
  3. A partir del minuto 7:20 se muestran unas lámparas que parpadean continuamente de forma errática ¿Casualidad?


Después de analizar detenidamente dichos parpadeos, podemos intuir que dicha lámpara está mostrando un mensaje en `código morse`.

Básicamente el código Morse es un sistema de comunicación que representa letras, números y signos mediante combinaciones de puntos y rayas (cortas y largas) donde los puntos se suelen definir con 1 duración y las rayas con el doble de la duración de un punto.

Es por ello que extrayendo dicha información de la lámpara obtenemos lo siguiente.

____

`

```
    1
```

| 

```
    .---- ...-- --... .-.-.- .---- ---.. ....- .-.-.- ..... --... .-.-.- .---- ---.. --...
```  
  
---|---  
`

Utilizando herramientas como `CyberChef` o de forma manual, podemos observar el siguiente texto en claro.

____

`

```
    1
```

| 

```
    137.184.57.187
```  
  
---|---  
`

A partir de este punto se nos puede venir a la cabeza realizar miles de cosas con esa IP, pero primero de todo se me ocurrió geolocalizarla para saber si ibamos en buen camino o se trataba de un lugar sin salida y descubrimos que dicha IP pertenece a un servicio de Hosting llamado DigitalOcean encontrándose en Estados Unidos New Jersey.

Recordad, que una de las pistas nos dice “COME GET YOUR FILE” por lo que tenemos que encontrar un fichero con esa IP ¿Alguna idea?

Pues básicamente lo que nos están pidiendo que hagamos es que nos conectemos por FTP a dicha IP y nos traigamos la `flag.txt`. Es por ello que hice lo siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ ftp 137.184.57.187
    
    Connected to 137.184.57.187.
    220 Boo!
    Name (137.184.57.187:kali): dir
    530 This FTP server is anonymous only.
    ftp: Login failed
    
    ftp> cd
    (remote-directory) cd
    530 Please login with USER and PASS.
    
    ftp> user
    (username) anonymous
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    
    ftp> dir
    229 Entering Extended Passive Mode (|||47926|)
    150 Here comes the directory listing.
    -rw-r--r--    1 ftp      ftp            56 Oct 25 19:24 flag.txt
    226 Directory send OK.
    
    ftp> get flag.txt
    local: flag.txt remote: flag.txt
    229 Entering Extended Passive Mode (|||31580|)
    150 Opening BINARY mode data connection for flag.txt (56 bytes).
    100% |*************************************************************************************************************************************************|    56        0.13 KiB/s    00:00 ETA
    226 Transfer complete.
    56 bytes received in 00:00 (0.08 KiB/s)
    
    ftp> exit
    221 Goodbye.
```  
  
---|---  
`

Abrimos el archivo y leemos la flag.

## Flag __

`NICC{I_h0p3_whatever_is_in_the_backrooms_brought_candy}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Misc](https://k3sero.github.io/tags/misc/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [SpookyCTF](https://k3sero.github.io/tags/spookyctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Strange%20Sightings%20-%20SpookyCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStrange-Sightings-Miscelanea-SpookyCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Strange%20Sightings%20-%20SpookyCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStrange-Sightings-Miscelanea-SpookyCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStrange-Sightings-Miscelanea-SpookyCTF2024%2F&text=Strange%20Sightings%20-%20SpookyCTF2024%20-%20Kesero "Telegram") __
