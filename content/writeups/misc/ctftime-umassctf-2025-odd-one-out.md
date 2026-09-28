---
title: "Odd One Out - UMassCTF 2025"
category: "misc"
subcategory: "classical"
type: "writeup"
tags: ["misc", "vigenere", "lsb", "zsteg", "odd", "out", "classical", "umassctf", "umassctf-2025", "2025", "ctf-writeup"]
summary: "Odd one out - UmassCTF2025"
source:
  name: "CTFtime writeup #40202"
  url: "https://ctftime.org/writeup/40202"
original_source: "https://k3sero.github.io/posts/Odd-one-out-UmassCTF2025/"
ctf:
  name: "UMassCTF 2025"
  year: 2025
  challenge: "Odd One Out"
---

## Metadata

- **CTF:** UMassCTF 2025
- **Task:** Odd One Out
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40202>
- **Original writeup:** <https://k3sero.github.io/posts/Odd-one-out-UmassCTF2025/>

---
Odd one out - UmassCTF2025 __

Contenido __

Odd one out - UmassCTF2025

__

Autor del reto: `Cosmicator`

Dificultad: Fácil

## Enunciado __

“I forgot to organize my encrypted flags for this challenge! Can you find the odd one out? I could have sworn it was a different color…

Hint Not all solvers will work on this. If you get stuck, try a different way!

Hint The oddoneout challenge is multilayer! You’ll know you have the right one if it looks like a real word.”

## Archivos __

En este reto, tenemos el siguiente archivo.

  * `OddOneOut.png` : Imagen con QRs en su interior.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Misc/Odd%20one%20out).

## Analizando el reto __

En la imágen obtenida, podemos encontrar un panel con 64 códigos qr (8 x 8)

[![odd_one](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Misc/Odd%20one%20out/OddOneOut.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Misc/Odd%20one%20out/OddOneOut.png)

##  Solver __

Primero tenemos que dividir todos los QR en entidades atómicas para poder escanear su contenido, para ello realizaremos tratamiento de imágenes con python. El script utilizado es el siguiente.

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
```

| 

```
     from PIL import Image
    import os
    
    img = Image.open("OddOneOut.png")
    
    rows, cols = 8, 8  # 12x12 códigos QR
    w, h = img.width // cols, img.height // rows
    
    output_dir = "qr_parts"
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(rows):
        for j in range(cols):
            left = j * w
            upper = i * h
            right = left + w
            lower = upper + h
    
            qr_img = img.crop((left, upper, right, lower))
            filename = f"{output_dir}/qr_{i:02d}_{j:02d}.png"
            qr_img.save(filename)
    
    print(f"[+] Guardados {rows * cols} códigos QR en la carpeta '{output_dir}'")
```  
  
---|---  
`

Una vez tenemos todos los QR por partes, podemos escanear manualmente los 64 QR o podemos realizar dicha operatoria mediante python nuevamente. El script es el siguiente.

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
```

| 

```
     from pyzbar.pyzbar import decode
    from PIL import Image
    import os
    
    input_dir = "qr_parts"
    
    results = []
    
    for filename in sorted(os.listdir(input_dir)):
        if filename.endswith(".png"):
            path = os.path.join(input_dir, filename)
            img = Image.open(path)
            decoded = decode(img)
    
            if decoded:
                data = decoded[0].data.decode("utf-8")
                print(f"[{filename}] ➜ {data}")
                results.append((filename, data))
            else:
                print(f"[{filename}] No se pudo decodificar")
    
    with open("qr_results.txt", "w") as f:
        for filename, data in results:
            f.write(f"{filename}: {data}\n")
```  
  
---|---  
`

Las cadenas resultantes de la decodificación son las siguientes.

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
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
    56
    57
    58
    59
    60
    61
    62
    63
    64
    65
```

| 

```
    UMASS{g6dYFYeMygiouF7J}
    UMASS{WqLwY5LlUNC5WH2b}
    UMASS{LrmEXGVAJaza5i1L}
    UMASS{7KRGbzBczJgWbSYG}
    UMASS{4etimmjB4RuvjoCQ}
    UMASS{u4T3zJKeeZ8BRKqU}
    UMASS{IlQyFfv7QSVF1R0E}
    UMASS{wnM7ESPt7YyAnM4t}
    UMASS{y4XBKtNnuW3raJpd}
    UMASS{pdG5GKbktBhBiiRT}
    UMASS{gelYqLhk5RC0OvY5}
    UMASS{Eizg9Rw8hpyPq2xQ}
    UMASS{1P7j6euvTCv5fjlW}
    UMASS{LAlKHgA2PBYYldGX}
    UMASS{XZRizmHwE5mssAg2}
    UMASS{72QiZnbtX0ufJph4}
    UMASS{f1FA0aVumqYMRoGR}
    UMASS{BIufRviwelyyldBX}
    UMASS{u1C0Ql9BLALgf60h}
    UMASS{T5Nu7T1mzCKtXIOC}
    UMASS{uKoczPwmF2O186IM}
    UMASS{nHCximnsxJdxfPZ9}
    UMASS{RVLv3VvVLSj2a1R9}
    UMASS{y3iR7DbeNwu2n34Y}
    UMASS{9c40K5lRpI2LXdn9}
    UMASS{mjVqIzWNibamnFDB}
    UMASS{uKSRWReI4biAuJgy}
    UMASS{8VKOrzaLwpW5Pr46}
    UMASS{lEUXW1XKCftRgHwe}
    UMASS{IG2oid7zGryAGLeH}
    UMASS{T342wXhy2JkfY0Wy}
    UMASS{bxb5EkHgO2UV52lB}
    UMASS{15f5UAomkKPy8vVS}
    UMASS{wMElKIwwofQWBSJv}
    UMASS{lvFxc4AXg3EPjVEI}
    UMASS{Bi9nwZZveyGGouTp}
    UMASS{BNotDRN9NvrXrL7u}
    UMASS{PAKa4nGLzh0rLH7U}
    UMASS{aY5uLvOkofvMnhkh}
    UMASS
    UMASS{c6s9b81RdpQWbDjI}
    UMASS{2ZNeiFZO6PzoMS1V}
    UMASS{gzofvUaIVTtYyeH2}
    UMASS{KjGKarWvqPtPDozc}
    UMASS{S2iDIsYv3I0OUWqH}
    UMASS{ju0Mg55zr7pYPgqB}
    UMASS{RnwT3VMLBMAYMm1A}
    UMASS{v7Fe99n1GBotNXK7}
    UMASS{bY50KerHKxChLDLP}
    UMASS{BWREzA1YW0qYYygc}
    UMASS{vBuUMY5Jtp2zMINJ}
    UMASS{CdSZsT0Qw01bCm5U}
    UMASS{OTJJGj3P0ia1TgES}
    UMASS{NVquFWK4xyQ3qlx8}
    UMASS{fmP30KraVX1i5cTO}
    UMASS{zVD2yupMeWutdVA8}
    UMASS{jqcZQA35RD4ucI2A}
    UMASS{Xe5711DpsN0IYnkn}
    UMASS{R4Rm51Ghe5kmr0Kp}
    UMASS{EcgToCpEAgR72RtU}
    UMASS{Cug4u9hs3Qg1o5kc}
    UMASS{AghURsxFTttKYFWY}
    UMASS{M0eRVFhQgxYC4Blf}
    UMASS{Q6moX3k4mXOb8KbD}
```  
  
---|---  
`

Llegados a este punto, podemos ver que tenemos muchisimas flags potenciales. Podemos observar como la flag `UMASS` tiene una doble llave, lo cual puede ser un indicio de que es justo esa la que necesitamos.

Además si abrimos la imagen con `gimp` y mirando los colores de los QR, podemos observar como justo el QR proveniente de esa flag, se encuentra en un color levemente más claro (no visible a simple vista) y justo en el enunciado nos menciona que el verdadero QR tiene un color distinto por lo que podemos asegurar que esa es nuestra flag.

Vale, y ¿ahora qué hacemos?

Llegados a este punto podemos probar a listar información oculta con `zsteg` en búsqueda de posibles `lsb` oculto en la imagen principal y así podemos encontrar la siguiente información.

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
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ zsteg OddOneOut.png
    
    b1,b,msb,xy         .. file: MIPSEL ECOFF executable not stripped - version 105.35
    b1,rgb,lsb,xy       .. text: "Man I REALLY like squares. I think cubes are cool too. QR codes are truly the pinnacle of modern data encoding.\n\nAlso, while you're rooting around in here, I'm taking a poll: did you ever play coolmath games as a kid?\n\nIf you did: great! I hope you played "
    b1,bgr,msb,xy       .. file: OpenPGP Public Key
    b2,g,lsb,xy         .. file: Encore unsupported executable not stripped
    b3,r,msb,xy         .. file: Applesoft BASIC program data, first line number 146
    b3,bgr,lsb,xy       .. file: gfxboot compiled html help file
    b4,b,lsb,xy         .. file: Targa image data - Map 1 x 4353 x 16 +257 "\001\021\020"
    b4,rgb,lsb,xy       .. file: Targa image data 4096 x 65536 x 1 +4097 +4113 "\020\001"
    b4,bgr,lsb,xy       .. file: PDP-11 UNIX/RT ldp
```  
  
---|---  
`

____

`

```
    1
```

| 

```
    "Man I REALLY like squares. I think cubes are cool too. QR codes are truly the pinnacle of modern data encoding.\n\nAlso, while you're rooting around in here, I'm taking a poll: did you ever play coolmath games as a kid?\n\nIf you did: great! I hope you played "
```  
  
---|---  
`

Llegados a este punto se nos pueden ocurrir mil cosas más, pero que tal si pensamos que hay más `lsbs` ocultos en la imagen? Podemos observar como en la pista nos dicen que probemos distintas herramientas, ¿será por algo en particular?

En este caso sí. Para obtener todos los `lsbs` pertenecientes a una imagen sin depender de encontrarse en el comienzo o en el final, se pueden utilizar páginas online como [Stylesuxx](https://stylesuxx.github.io/steganography/) la cual le subes la foto y obtienes toda su información perteniciente a `lsb`

El mensaje completo que revela la página es el siguiente.

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
    Man I REALLY like squares. I think cubes are cool too. QR codes are truly the pinnacle of modern data encoding.
    
    Also, while you're rooting around in here, I'm taking a poll: did you ever play coolmath games as a kid?
    
    If you did: great! I hope you played Bloxorz.
    If you didn't: that's a travesty and you should go play Bloxorz right now. Or maybe aft`
```  
  
---|---  
`

Llegados a la recta final, una observación de nuestra flag candidata es que es diferente al resto, debido a que únicamente se compone de letras del alfabeto, por lo que se nos puede ocurrir que dicha flag cifrada en `Vigenere`, con la clave `Bloxorz`.

Al desencriptar con esa clave, obtenemos la flag.

____

`

```
    1
```

| 

```
    UMASS{qrongratulations}
```  
  
---|---  
`

## Flag __

`UMASSCTF{qrongratulations}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Esteganografía](https://k3sero.github.io/categories/esteganograf%C3%ADa/)

__[Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Estego](https://k3sero.github.io/tags/estego/) [Estego - LSB](https://k3sero.github.io/tags/estego-lsb/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [UmassCTF](https://k3sero.github.io/tags/umassctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Odd%20one%20out%20-%20UmassCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FOdd-one-out-UmassCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Odd%20one%20out%20-%20UmassCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FOdd-one-out-UmassCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FOdd-one-out-UmassCTF2025%2F&text=Odd%20one%20out%20-%20UmassCTF2025%20-%20Kesero "Telegram") __
