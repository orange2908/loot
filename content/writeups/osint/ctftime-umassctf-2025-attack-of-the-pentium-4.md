---
title: "Attack of the Pentium 4 - UMassCTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "attack", "pentium", "umassctf", "umassctf-2025", "2025", "ctf-writeup"]
summary: "Attack of the Pentium 4 - UmassCTF2025"
source:
  name: "CTFtime writeup #40204"
  url: "https://ctftime.org/writeup/40204"
original_source: "https://k3sero.github.io/posts/Attack-of-Pentium-4-UmassCTF2025/"
ctf:
  name: "UMassCTF 2025"
  year: 2025
  challenge: "Attack of the Pentium 4"
---

## Metadata

- **CTF:** UMassCTF 2025
- **Task:** Attack of the Pentium 4
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40204>
- **Original writeup:** <https://k3sero.github.io/posts/Attack-of-Pentium-4-UmassCTF2025/>

---
Attack of the Pentium 4 - UmassCTF2025 __

Contenido __

Attack of the Pentium 4 - UmassCTF2025

__

Autor del reto: `Posco`

Dificultad: Media

## Enunciado __

“You really want to play Run 3, but your poor Pentium 4 isn’t fast enough! You’ve heard there’s a computer shop worthy of thunderous praise in this building, but you need an expert opinion on their services first. If a computer is good enough to work on games, it should be good enough to play them. It’s been rumored that someone who works on games once purchased a computer from here. Can you find their first game?

Flag format: UMASS{name of the game in English}, for example UMASS{Elden Ring}”

## Archivos __

En este reto, tenemos el siguiente archivo.

  * `image.jpeg` : Contiene la 1º localización


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204).

[![image.jpeg](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/image.jpeg)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/image.jpeg)

## Analizando el reto __

Tenemos que encontrar el primer juego que desarrolló una persona que compró un ordenador en la tienda que muestra la imagen. La información que podemos extraer del enunciado es la siguiente.

____

`

```
    1
    2
    3
    4
```

| 

```
    Hay tiendas de ordenadores en ese edificio en concreto
    Necesitamos una opinión experta en dicha tienda
    Si el ordenador es bueno para trabajar con videojuegos, también lo será para jugarlos
    Buscamos a alguien que una vez compró de esa tienda un ordenador
```  
  
---|---  
`

## Solver __

Para comenzar con este reto, tenemos que ir por partes. Primero vamos a encontrar la ubiación exacta de la imagen que tenemos. La imagen muestra un lugar en Tokio, en esta ubicación.

[![ubi](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/ubicacion.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/ubicacion.png)

Si observamos justo en el edificio donde enfocan, podemos observar que dentro de ese edificio, se encuentra una tienda de ordenadores genérica. Dicha tienda alberga unas 4 tiendas distintas llamadas `acharge`, `hercules`, `vspec` y `zeus`.

[![pag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/pagina.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/pagina.png)

[![achar](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/acharge.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/acharge.png) [![hercules](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/hercules.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/hercules.png) [![zeus](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/zeus.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/zeus.png) [![vspec](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/vspec.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/vspec.png)

Llegados a este punto tenemos que mirar en las reseñas de cada página, una opinión experta que relacione los conceptos que se hablan en el enunciado.

Después de muchas búsquedas y reseñas, podemos decir que la opinión experta es la [siguiente](https://pc-zeus.com/example_13.html).

[![reseña](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/rese%C3%B1a.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/rese%C3%B1a.png)

[![japones](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/japones.jpg)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/japones.jpg)

Sabemos que es la que se menciona porque en la propia reseña incluye una mini entrevista, la cual detalla su trabajo.

Si buscamos por la imagen adjunta a la reseña, podemos saber que su nombre es “Shouhei Tsuchiya” además en su [fanpage](https://www.mobygames.com/person/333977/shouhei-tsuchiya/credits/) se listan los juegos a los cuales ha ayudado a desarrollar. En este caso su primera participación en un juego es en 2003 y pertenece al título “Otogi 2: Immortal Warriors”

## Flag __

`UMASS{Otogi 2: Immortal Warriors}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Osint](https://k3sero.github.io/categories/osint/)

__[Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [Osint](https://k3sero.github.io/tags/osint/) [Osint - Research](https://k3sero.github.io/tags/osint-research/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [UmassCTF](https://k3sero.github.io/tags/umassctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Attack%20of%20the%20Pentium%204%20-%20UmassCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAttack-of-Pentium-4-UmassCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Attack%20of%20the%20Pentium%204%20-%20UmassCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAttack-of-Pentium-4-UmassCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAttack-of-Pentium-4-UmassCTF2025%2F&text=Attack%20of%20the%20Pentium%204%20-%20UmassCTF2025%20-%20Kesero "Telegram") __
