---
title: "[Cripto] Tracking The Beast - SpookyCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "elipticcurves", "greenlantern", "eliptic", "subgroup", "points", "curves", "sage", "spookyctf", "spookyctf-2024", "2024", "ctf-writeup"]
summary: "Tracking The Beast - SpookyCTF2024"
source:
  name: "CTFtime writeup #39622"
  url: "https://ctftime.org/writeup/39622"
original_source: "https://k3sero.github.io/posts/Tracking-The-Beast-Cripto-SpookyCTF2024/"
ctf:
  name: "SpookyCTF 2024"
  year: 2024
  challenge: "[Cripto] Tracking The Beast"
---

## Metadata

- **CTF:** SpookyCTF 2024
- **Task:** [Cripto] Tracking The Beast
- **Author team:** Caliphal Hounds
- **CTFtime tags:** elipticcurves, greenlantern, eliptic, subgroup, points, curves
- **CTFtime:** <https://ctftime.org/writeup/39622>
- **Original writeup:** <https://k3sero.github.io/posts/Tracking-The-Beast-Cripto-SpookyCTF2024/>

---
Tracking The Beast - SpookyCTF2024 __

Contenido __

Tracking The Beast - SpookyCTF2024

__

Autor del reto: `thatoganGuy`

Dificultad: Difícil

## Enunciado __

NICC is hot on the trail of bigfoot! He has been following a path equivalent to the curve y^2 = x^3 + 73x + 42 mod 251. Each point along this curve represents one of Bigfoot’s hideouts. NICC dicovered in his cave located at (26,38), many references to Green Lantern comics. A large depiction of Green Lantern with 13 rings on his fingers was drawn on the cave wall. I think this is the cover to an old issue of Green Lantern, could something about the issue point to how many more hideouts Bigfoot will travel through before stopping again?

##  Archivos __

En este reto no nos dan ningún archivo, solamente el enunciado.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best)

## Analizando el Enunciado __

Básicamente el enunciado nos dice que están investigando los escondites de Bigfoot a lo largo de la curva elíptica descrita por la ecuación ( y^2 = x^3 + 73x + 42 ) módulo 251.

Además se ha encontrado una de sus cuevas en el punto (26, 38) donde dentro hay referencias a cómics de Green Lantern, incluida una representación de Green Lantern con 13 anillos en los dedos.

Para obtener la flag, tenemos que encontrar el próximo escondite de Bigfoot, ¿podremos encontrarlo?

## Solución __

Básicamente, en este reto nos piden calcular el siguiente punto de la curva donde el Bigfoot puede estar. Para comenzar podemos ver los próximos puntos donde el Bigfoot puede estar, para ello utilizaré la herramienta online[Elliptic Curves over Finite Fields](https://graui.de/code/elliptic2/)

Pero antes de comenzar, vamos a desglosar todos los datos que tenemos.

  1. Tenemos la curva elíptica ( y^2 = x^3 + 73x + 42 mod 251), donde p = 251, a = 73 y b = 42
  2. Además tenemos un punto P (26, 38) dentro de la curva.
  3. Por último, tenemos una pista (un tanto guessy) la cual nos dice que en la cueva donde se encontró El Bigfoot, hay una referencia de una portada de cómic protagonizada por Linterna Verde con 13 anillos en los dedos.


Antes de continuar desarrollando la pista, vamos a observar los posibles puntos en los que puede estar escondido Bigfoot.

[![Grafica](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Grafica.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Grafica.png) [![Subgrupos](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Subgrupos.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Subgrupos.png)

Es importante saber que elegimos subgrupos dentro del punto P ya que las curvas elípticas tienen estructuras algebraicas que permiten la definición de grupos de puntos. Estos grupos tienen subgrupos que son útiles para realizar operaciones y cálculos específicos. La clave en este reto viene dada por encontrar dichos puntos a lo largo de la curva. Como sabemos que para seguir el camino tenemos un punto inicial P, simplemente tenemos que multiplicar el punto inicial P por un escalar N.

Dicho escalar N lo obtenemos mediante la tercera pista, por lo que tenemos que encontrar la portada a la que se refieren en el enunciado, para ello un poco de OSINT y encontramos lo [siguiente.](https://www.reddit.com/r/comicbooks/comments/a6prip/green_lantern_49_cover_art_by_darryl_banks/)

[![Portada](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/portada.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/portada.png)

Como podemos observar, dicha portada del cómic se corresonde con lo descrito en el enunciado, ¿y ahora que hacemos?

Pues básicamente tenemos que tomar el número 49 equivalente a el número de tomo del cómic como escalar N y operar en la curva elíptica para obtener el punto multiplicativo. N x P

Realizando un breve script en `sage` obtenemos la flag.

____

`

```
    1
    2
    3
    4
    5
    6
```

| 

```
     F = GF(251)
    E = EllipticCurve(F, [73, 42])
    
    P = E.point([26,38])
    
    print(49*P)
```  
  
---|---  
`

Ejecutando el código anterior obtenemos el punto del siguiente escondite del Bigfoot el cual se corresponde con (72, 17) y como podemos observar dicho punto existe dentro de la lista.

## Flag __

`NICC{72,17}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Curvas Elípticas](https://k3sero.github.io/tags/cripto-curvas-el%C3%ADpticas/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Difícil](https://k3sero.github.io/tags/dificultad-dif%C3%ADcil/) [SpookyCTF](https://k3sero.github.io/tags/spookyctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Tracking%20The%20Beast%20-%20SpookyCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FTracking-The-Beast-Cripto-SpookyCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Tracking%20The%20Beast%20-%20SpookyCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FTracking-The-Beast-Cripto-SpookyCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FTracking-The-Beast-Cripto-SpookyCTF2024%2F&text=Tracking%20The%20Beast%20-%20SpookyCTF2024%20-%20Kesero "Telegram") __
