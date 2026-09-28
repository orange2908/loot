---
title: "Character - Cyber Apocalypse 2024: Hacker Royale"
category: "misc"
type: "writeup"
tags: ["misc", "character", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Character - CyberApocalypse2024"
source:
  name: "CTFtime writeup #39645"
  url: "https://ctftime.org/writeup/39645"
original_source: "https://k3sero.github.io/posts/Character-CyberApocalypse2024/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Character"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Character
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39645>
- **Original writeup:** <https://k3sero.github.io/posts/Character-CyberApocalypse2024/>

---
Character - CyberApocalypse2024 __

Contenido __

Character - CyberApocalypse2024

__

Autor del reto: `ir0nstone`

Dificultad: Muy Fácil

## Enunciado __

“Security through Induced Boredom is a personal favourite approach of mine. Not as exciting as something like The Fray, but I love making it as tedious as possible to see my secrets, so you can only get one character at a time!”

##  Archivos __

En este reto, solamente nos dan una conexión por`netcat`, al conectarnos encontramos lo siguiente.

____

`

```
    1
    2
```

| 

```
     $ nc <ip> <port>
    Which character of the flag do you want? Enter an index: 
```  
  
---|---  
`

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Character).

Si introducimos números de forma consecutiva por ejemplo `0`, `1` etc, podemos ver que ocurre lo siguiente.

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
    Which character of the flag do you want? Enter an index: 0
    Character at Index 0: H
    Which character of the flag do you want? Enter an index: 1
    Character at Index 1: T
    Which character of the flag do you want? Enter an index: 2
    Character at Index 2: B
```  
  
---|---  
`

Podemos observar que son los primeros tres caracteres de la flag `HTB` por lo que nos están dando la flag directamente solamente al introducir los índices.

## Solución __

La solución es muy simple, simplemente introducimos los indices desde el $0$ hasta el tamaño de la flag de forma consecutiva y ya tendriamos la flag, pero en este caso vamos a realizar un breve script para familiarizarnos con este tipo de conexiones.

Solamente tenemos que crear una variable `flag`, introducir los índices cuando el programa nos lo pida e ir filtrando por la información que nos arroja para obtener la flag de forma dinámica. Para ello el código final es el siguiente.

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
```

| 

```
     from pwn import *
    
    p = remote('127.0.0.1', 1337)
    
    flag = ''
    idx = 0
    while True:
        p.sendlineafter(b'index: ', str(idx).encode())
        p.recvuntil(b': ')
        char = p.recvS(1)
    
        flag += char
        idx += 1
    
        if char == '}':
            break
    
    print(flag)
```  
  
---|---  
`

### NOTA __

Tanto la función`sendlineafter` como `recvS` son muy útiles para scriptear el recibir/transmitir datos en una conexión de forma muy eficiente.

## Flag __

`tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Dificultad - Muy Fácil](https://k3sero.github.io/tags/dificultad-muy-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Misc](https://k3sero.github.io/tags/misc/) [CyberApocalypseCTF](https://k3sero.github.io/tags/cyberapocalypsectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Character%20-%20CyberApocalypse2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCharacter-CyberApocalypse2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Character%20-%20CyberApocalypse2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCharacter-CyberApocalypse2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCharacter-CyberApocalypse2024%2F&text=Character%20-%20CyberApocalypse2024%20-%20Kesero "Telegram") __
