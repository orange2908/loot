---
title: "In Plain Sight - 1337UP LIVE CTF"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "zsteg", "stegseek", "exiftool", "plain", "sight", "disk", "1337up-live-ctf", "ctf-writeup"]
summary: "In Plain Sight - 1337UP LIVE CTF2024"
source:
  name: "CTFtime writeup #39659"
  url: "https://ctftime.org/writeup/39659"
original_source: "https://k3sero.github.io/posts/In-Plain-Sight-1337UpCTF2024/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "In Plain Sight"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** In Plain Sight
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39659>
- **Original writeup:** <https://k3sero.github.io/posts/In-Plain-Sight-1337UpCTF2024/>

---
In Plain Sight - 1337UP LIVE CTF2024 __

Contenido __

In Plain Sight - 1337UP LIVE CTF2024

__

Autor del reto: `CryptoCat`

Dificultad: Fácil

## Enunciado __

“Barely hidden tbh..”

##  Archivos __

En este reto, solo nos dan el siguiente archivo.

  * `meow.jpg` : Fichero de imagen.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight).

## Analizando la imagen __

El archivo que nos dan se corresponde con la imagen de un gato.

[![Gato](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/meow.jpg)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/meow.jpg)

Aparentemente tenemos que encontrar algo de información en esta imagen, para ello iremos jugando con distintas herramientas como `exiftool`, `binwalk`, `zsteg`, `stegseek`, `stegsnow`, `strings`, `file` para tratar de recuperar datos incrustados en dicha imagen.

## Solución __

El primer paso que deberemos de hacer es ejecutar la herramienta`binwalk` la cual nos mostrará la siguiente información.

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
    ┌──(kesero㉿kali)-[~]
    └─$ binwalk meow.jpg
    
    
    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    2144878       0x20BA6E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1938, uncompressed size: 3446, name: flag.png
    2146976       0x20C2A0        End of Zip archive, footer length: 22
```  
  
---|---  
`

Como podemos ver, dicha imagen contiene un archivo `.zip` con información en su interior, para extraer dicho `fichero.zip` utilizaremos el parámetro `-e`.

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
    ┌──(kesero㉿kali)-[~]
    └─$ binwalk -e meow.jpg
    
    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    2144878       0x20BA6E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1938, uncompressed size: 3446, name: flag.png
```  
  
---|---  
`

Una vez extraído dicho fichero, se nos creará una carpeta llamada `_meow.jpg.extracted` donde estará dicho fichero zip.

Al intentar descomprimir dicho fichero zip, nos piden una contraseña para poder hacerlo, es por ello que en este punto tendremos que seguir probando con herramientas e ir jugando un poco con ellas.

En este caso la contraseña se encontraba dentro de la imagen `meow.jpg`, simplemente lanzando un `string` a la imagen, podemos ver la contraseña.

____

`

```
    1
```

| 

```
    YoullNeverGetThis719482
```  
  
---|---  
`

Una vez tenemos la contraseña, descomprimimos el fichero `.zip` y obtenemos un archivo llamado `flag.png` el cual se corresponde con la siguiente imagen.

____

`

```
    1
    2
    3
    4
    5
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ unzip -P YoullNeverGetThis719482 20BA6E.zip
    
    Archive:  20BA6E.zip
    inflating: flag.png 
```  
  
---|---  
`

[![flag.png](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/flag.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/flag.png)

Podemos observar lanzando un `file`, que efectivamente se corresponde con el formato de una imagen .png la cual contiene información en su interior. Es por ello que nuevamente deberemos de seguir jugando con las distintas herramientas esteganográficas.

Por último, el siguiente paso que hay que dar viene dado por observar las distintas capas que contiene dicha imagen con herramientas como `Gimp`, `Photoshop`, las cuales permiten obtener una descomposición en sus capas mostrando información contenida en ellas. A su vez, podemos jugar con el brillo y el contraste para observar posibles cambios en la imagen.

En mi caso, yo utilicé la herramienta `convert` la cual extrae la posible información existente en las capas de una imagen aparentemente oculta. Es por ello que ejecuté el siguiente comando.

____

`

```
    1
    2
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ convert flag.png -auto-level output.png
```  
  
---|---  
`

Abrimos la imagen y efectivamente, encontramos la flag.

[![output.png](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/output.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/output.png)

### NOTA __

Mirando otros Writeups, hay gente que lanza busquedas de Estego online mediante el siguiente enlace:[https://georgeom.net/StegOnline/image ](https://georgeom.net/StegOnline/image)

## Flag __

`INTIGRITI{w4rmup_fl46z}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Esteganografía](https://k3sero.github.io/categories/esteganograf%C3%ADa/)

__[Estego](https://k3sero.github.io/tags/estego/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [337UPLIVECTF](https://k3sero.github.io/tags/337uplivectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=In%20Plain%20Sight%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIn-Plain-Sight-1337UpCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=In%20Plain%20Sight%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIn-Plain-Sight-1337UpCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIn-Plain-Sight-1337UpCTF2024%2F&text=In%20Plain%20Sight%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero "Telegram") __
