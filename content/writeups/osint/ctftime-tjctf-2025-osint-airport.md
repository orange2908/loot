---
title: "[Osint] Airport - TJCTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "airport", "tjctf", "tjctf-2025", "2025", "ctf-writeup"]
summary: "“i made a mIstake and got lost, i always lose traCk of where i am oh no somebody kidnApped me please find where i am save me before i gO on this horrific plane tjctf{uppercasecode}”"
source:
  name: "CTFtime writeup #40517"
  url: "https://ctftime.org/writeup/40517"
original_source: "https://k3sero.github.io/posts/Airport-TJCTF2025/"
ctf:
  name: "TJCTF 2025"
  year: 2025
  challenge: "[Osint] Airport"
---

## Metadata

- **CTF:** TJCTF 2025
- **Task:** [Osint] Airport
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40517>
- **Original writeup:** <https://k3sero.github.io/posts/Airport-TJCTF2025/>

---
Airport - TJCTF2025 __

Contenido __

Airport - TJCTF2025

__

Autor del reto: `2027aliu`

Dificultad: Fácil

## Enunciado __

“i made a mIstake and got lost, i always lose traCk of where i am oh no somebody kidnApped me please find where i am save me before i gO on this horrific plane tjctf{uppercasecode}”

##  Archivos __

Este reto tenemos el siguiente archivo.

  * `lost.png`: Contiene la imagen del aeropuerto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport).

[![lost](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/lost.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/lost.png)

## Analizando el reto __

Si analizamos el enunciado, podemos observar un comportamiento anómalo y es que hay letras que están en mayúsculas en el propio enunciado.

Si unimos cada letra, nos damos cuenta que se forma la palabra `ICAO`

`ICAO` (Organización de Aviación Civil Internacional), es un organismo especializado de las Naciones Unidas que se encarga de establecer normas y regulaciones internacionales para la aviación civil en todo el mundo. Cada aeropuerto tiene su propia identificación `ICAO`. Por ejemplo, el aeropuerto de Madrid-Barajas tiene un código `ICAO` de LEMD.

En este caso, nos piden que introduzcamos el `ICAO` correspondiente al aeropuerto de la imagen.

## Solver __

Si analizamos la imagen, podemos observar como hay palabras escritas en español, esto nos puede ayudar a descartar aeropuertos y quedarnos únicamente con lugares donde se hable el castellano, como puede ser en Latinoamérica o España.

Además, en este tipo de ejercicios, siempre podemos afinar aún más nuestra búsqueda utilizando `Google Lens` y `Chatgpt` para afinar nuestro rango de ubicaciones.

Al hacerlo, encontramos que el aeropuerto se llama “Nuevo Aeropuerto Internacional Jorge Chávez” perteneciente a Perú.

[![find](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/aereopuerto%20peru.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/aereopuerto%20peru.png)

Una vez encontrado el aeropuerto, obtenemos su `ICAO` y lo convertimos al formato de la flag. En este caso se corresponde con SPJC.

## Flag __

`tjctf{SPJC}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Osint](https://k3sero.github.io/categories/osint/)

__[Osint](https://k3sero.github.io/tags/osint/) [Osint - Geo](https://k3sero.github.io/tags/osint-geo/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [TJCTF](https://k3sero.github.io/tags/tjctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Airport%20-%20TJCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAirport-TJCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Airport%20-%20TJCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAirport-TJCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAirport-TJCTF2025%2F&text=Airport%20-%20TJCTF2025%20-%20Kesero "Telegram") __
