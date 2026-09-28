---
title: "Makeshift - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "makeshift", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Makeshift - CyberApocalypse2024"
source:
  name: "CTFtime writeup #39639"
  url: "https://ctftime.org/writeup/39639"
original_source: "https://k3sero.github.io/posts/Makeshift-CyberApocalypse2024/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Makeshift"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Makeshift
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39639>
- **Original writeup:** <https://k3sero.github.io/posts/Makeshift-CyberApocalypse2024/>

---
Makeshift - CyberApocalypse2024 __

Contenido __

Makeshift - CyberApocalypse2024

__

Autor del reto: `ir0nstone`

Dificultad: Muy Fácil

## Enunciado __

“Weak and starved, you struggle to plod on. Food is a commodity at this stage, but you can’t lose your alertness - to do so would spell death. You realise that to survive you will need a weapon, both to kill and to hunt, but the field is bare of stones. As you drop your body to the floor, something sharp sticks out of the undergrowth and into your thigh. As you grab a hold and pull it out, you realise it’s a long stick; not the finest of weapons, but once sharpened could be the difference between dying of hunger and dying with honour in combat.”

##  Archivos __

En este reto nos dan dos archivos:

  * `source.py` : Contiene el script de incriptación principal
  * `output.txt` : El archivo de salida el cual contiene la flag rotada


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Makeshift).

## Analizando el código __

Este ejercicio es muy simple, simplemente tenemos el siguiente código:

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
```

| 

```
     from secret import FLAG
    
    flag = FLAG[::-1]
    new_flag = ''
    
    for i in range(0, len(flag), 3):
        new_flag += flag[i+1]
        new_flag += flag[i+2]
        new_flag += flag[i]
    
    print(new_flag)
```  
  
---|---  
`

Como podemos ver, este programa funciona de la siguiente forma.

  1. Primero en la línea de código $FLAG[::-1]$ invierte la flag de forma que la parte principal pasa a la parte final y viceversa.

  2. Posteriormente se recorre en un bucle for para tratar los caracteres en bloques de 3 en 3.

  3. Por último cada bloque se trata de la siguiente manera. El segundo carácter es puesto en primera posición, el tercer carácter es puesto en la segunda posición y el primer carácter es puesto en la última posición. Por ejemplo si tenemos la cadena `YES` después de ejecutar esta función quedaría la cadena `ESY`.


# Solución

Básicamente para obtener la flag original, lo único que necesitamos hacer es invertir la cadena inversa que nos dan en el fichero `output.txt` nuevamente y ejecutar de nuevo las iteraciones mencionadas anteriormente ya que de este modo se ordenarían como estaban en un principio.

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
```

| 

```
     flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
    flag = flag[::-1]
    plaintext = ''
     
    for i in range(0, len(flag), 3):
        plaintext += flag[i+1]
        plaintext += flag[i+2]
        plaintext += flag[i]
    
    print(plaintext)
```  
  
---|---  
`

## Flag __

`HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Algoritmos](https://k3sero.github.io/tags/cripto-algoritmos/) [Dificultad - Muy Fácil](https://k3sero.github.io/tags/dificultad-muy-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [CyberApocalypseCTF](https://k3sero.github.io/tags/cyberapocalypsectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Makeshift%20-%20CyberApocalypse2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMakeshift-CyberApocalypse2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Makeshift%20-%20CyberApocalypse2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMakeshift-CyberApocalypse2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FMakeshift-CyberApocalypse2024%2F&text=Makeshift%20-%20CyberApocalypse2024%20-%20Kesero "Telegram") __
