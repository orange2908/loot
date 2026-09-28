---
title: "[Misc] Masked - TJCTF 2025"
category: "misc"
subcategory: "image"
type: "writeup"
tags: ["xor", "qr-code", "misc", "masked", "image", "tjctf", "tjctf-2025", "2025", "ctf-writeup"]
summary: "“my qr code cant get covid so I put all the masks on him”"
source:
  name: "CTFtime writeup #40518"
  url: "https://ctftime.org/writeup/40518"
original_source: "https://k3sero.github.io/posts/Masked-TJCTF2025/"
ctf:
  name: "TJCTF 2025"
  year: 2025
  challenge: "[Misc] Masked"
---

## Metadata

- **CTF:** TJCTF 2025
- **Task:** [Misc] Masked
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40518>
- **Original writeup:** <https://k3sero.github.io/posts/Masked-TJCTF2025/>

---
Masked - TJCTF2025 __

Contenido __

Masked - TJCTF2025

__

Autor del reto: `addison`

Dificultad: Fácil

## Enunciado __

“my qr code cant get covid so I put all the masks on him”

##  Archivos __

En este reto tenemos el siguiente archivo.

  * `qrcode.png` : Contiene el código QR enmascarado.


[![qrcode](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qrcode.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qrcode.png)

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked).

## Analizando el reto __

Según el enunciado, tenemos un código QR que ha sido enmascarado utilizando todas las máscaras estandarizadas de un QR.

De manera más formal, las máscaras de un código QR son patrones de bits que se aplican a la matriz de datos del código QR para mejorar su legibilidad y fiabilidad durante la lectura, especialmente en situaciones con ruido o distorsión. La función principal de estas máscaras es asegurar que los módulos (los pequeños cuadrados en el código QR) estén distribuidos de manera uniforme en toda la matriz, lo que mejora la calidad de la lectura del código.

Las máscaras son patrones binarios que se aplican a la matriz de módulos para alterar la disposición de los mismos. Estas máscaras no afectan los datos codificados, pero ayudan a mejorar la distribución visual de los módulos y a evitar patrones que dificulten su lectura.

Hay 8 posibles máscaras para un código QR, y cada una tiene un patrón diferente para alterar la forma en que los módulos se colocan. Estos patrones están diseñados para hacer que el código QR sea más fácil de leer bajo diferentes condiciones. La elección de la máscara correcta depende de varios factores, como el contraste, la cantidad de datos y el entorno de lectura.

Al aplicar una máscara, se “pinta” un patrón específico sobre el código QR de forma que los módulos de datos se modifican de acuerdo con el patrón de la máscara. Esto puede cambiar la posición de los módulos, pero no altera los datos codificados.

De manera visual, estas son las máscaras.

[![mascaras](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/mascaras.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/mascaras.png)

Si queréis profundizar en el tema, recomiendo esta referencia perteneciente a [csie.ntu.edu](https://www.csie.ntu.edu.tw/~kmchao/bcc16spr/20160329_QR%20Code.pdf)

## Solver __

En este caso, en el enunciado nos comentan que se han aplicado todas las máscaras posibles, por ende nosotros tenemos que realizar la operación inversa.

Para ello tenemos que deshacer las máscaras de un código QR pero, ¿cómo realizamos la operación?

Para deshacer las máscaras de un código QR hay que aplicar la misma máscara nuevamente, esto se debe a las propiedades de las operaciones de XOR, que es la operación que se utiliza para aplicar las máscaras a un código QR.

Cuando aplicamos una máscara a un código QR, lo que estamos haciendo en realidad es aplicar una operación XOR entre el patrón de bits de la máscara y los bits de la matriz de datos del QR.

Imagina que tienes un módulo en el código QR con valor 1 (negro). Si aplicas una máscara que tenga un valor de 1 en esa posición, realizarás la operación 1 XOR 1 lo que dará 0 (blanco). De forma similar, si el valor del módulo es 0 y la máscara tiene 1 en esa posición, 0 XOR 1 = 1, lo que cambiaría el valor a negro.

En conclusión, podemos afirmar que debido a las propiedades de XOR, aplicar la misma operación dos veces sobre un valor retorna el valor original.

Además en esta ocasión, el orden de operación de las máscaras no importa ya que la operación XOR es conmutativa y asociativa. Esto significa que el orden en el que aplicas las máscaras no afecta el resultado final.

Una vez entendido la vía de deshacer las máscaras, podemos programarnos nosotros mismos la funcionalidad o utilizar herramientas que permiten deshacer estos cambios.

En mi caso, utilicé la página web oficial de [qrcrazy](https://merri.cx/qrazybox/) la cual permite realizar numerosas funcionalidades de aplicar máscaras, realizar fuerza bruta de patrones entre muchas otras herramientas.

[![qrcrazy](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qrcrazy.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qrcrazy.png)

Las herramientas que ofrece la página son las siguientes.

[![toollist](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/toollist.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/toollist.png)

Una vez familiarizados con la herramienta, deberemos de aplicr cada una de las máscaras para ello utilizaremos “Data Masking” y seleccionaremos 1 a 1 cada máscara a aplicar.

Una vez tenemos todas las máscaras aplicadas, tenemos que darle un formato al resultado obtenido. Para ello podemos hacerlo de manera manual o utilizar la herramienta “Brute-force Format Info Pattern” la cual realiza dicha operatoria.

Una vez realizado los pasos anteriores, ya tenemos el código QR original y listo para escanear.

[![qroriginal](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qroriginal.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/misc/masked/qroriginal.png)

## Flag __

`tjctf{n0tc4tchingc0vid}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Misc](https://k3sero.github.io/tags/misc/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Misc - QR](https://k3sero.github.io/tags/misc-qr/) [TJCTF](https://k3sero.github.io/tags/tjctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Masked%20-%20TJCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMasked-TJCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Masked%20-%20TJCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMasked-TJCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMasked-TJCTF2025%2F&text=Masked%20-%20TJCTF2025%20-%20Kesero "Telegram") __
