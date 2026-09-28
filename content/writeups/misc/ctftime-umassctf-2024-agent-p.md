---
title: "Agent P - UMassCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "agent", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "“Patrick sees secret, he puts it into computer immediately."
source:
  name: "CTFtime writeup #39650"
  url: "https://ctftime.org/writeup/39650"
original_source: "https://k3sero.github.io/posts/Agent-P-UmassCTF2024/"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "Agent P"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** Agent P
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39650>
- **Original writeup:** <https://k3sero.github.io/posts/Agent-P-UmassCTF2024/>

---
Agent P - UmassCTF2024 __

Contenido __

Agent P - UmassCTF2024

__

Autor del reto: `unknown`

Dificultad: Fácil

## Enunciado __

“Patrick sees secret, he puts it into computer immediately. But can you read the flag?”

##  Archivos __

En este reto solo tenemos el siguiente archivo.

  * `a.txt` : Contiene una cadena de texto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Agent_P).

## Analizando el código __

Si abrimos el archivo`a.txt` podemos ver la siguiente cadena de texto.

____

`

```
    1
```

| 

```
    EDCVGT VFRGYHN CFTGB YTRFGBV YTRFGHBV 6TFGVB FGYTRFV XDRFV RTYTGB 4RFV456YTFGN 7UJM 65RDCVB 5RFVYGGB EDCFTGBHU XDRFV TREDFGBVC RFVFGHYHN ERTDFGCVBEDC 3EDC345TFDFB EDCERTDFGCVB 7YUJKIJN
```  
  
---|---  
`

## Solución __

La solución es mucho más simple de lo que parece. En este caso se nos pueden ocurrir mil cosas, como por ejemplo que se trata de un`Cifrado César`, algún tipo de `cifrado afín` o que debemos de usar un `análisis de frecuencia` para decodificar la flag. Aunque recordemos que estamos en la categoría Miscelánea.

Además, el enunciado nos dice que Patricio Estrella nos ha arrojado esta cadena de forma instantánea y supuestamente “codificada”

También, si somos observadores y suponiendo que la flag comienza por `umassctf{`, podemos ver que la `s` coincide con dos cadenas `YTRFGBV` `YTRFGHBV` pero, ¿por qué son diferentes si deberían de ser iguales? ¿Qué es esto y cómo lo resolvemos?

Si observamos detenidamente, nos damos cuenta de que esta cadena no tiene ninguna codificación. Simplemente, si seguimos el trazo de la cadena en el teclado, observamos que se van dibujando caracteres como si de un folio se tratase.

Por ejemplo, la cadena `EDCVGT` dibuja en nuestro teclado una `U`, `VFRGYHN` dibuja una `M`, `CFTGB` dibuja una `A` y así sucesivamente, por lo que si seguimos el trazo completo de todas las cadenas obtendremos la flag.

## Flag __

`UMASSCTF{PATRICWASHERE}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Misc](https://k3sero.github.io/tags/misc/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [UmassCTF](https://k3sero.github.io/tags/umassctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Agent%20P%20-%20UmassCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAgent-P-UmassCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Agent%20P%20-%20UmassCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAgent-P-UmassCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FAgent-P-UmassCTF2024%2F&text=Agent%20P%20-%20UmassCTF2024%20-%20Kesero "Telegram") __
