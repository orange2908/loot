---
title: "Dynastic - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "trithemius", "incremental", "cipher", "dynastic", "classical", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Dynastic - CyberApocalypse2024"
source:
  name: "CTFtime writeup #39638"
  url: "https://ctftime.org/writeup/39638"
original_source: "https://k3sero.github.io/posts/Dynastic-Cripto-CyberApocalypse2024/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Dynastic"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Dynastic
- **Author team:** Caliphal Hounds
- **CTFtime tags:** caesar, trithemius, incremental, cipher
- **CTFtime:** <https://ctftime.org/writeup/39638>
- **Original writeup:** <https://k3sero.github.io/posts/Dynastic-Cripto-CyberApocalypse2024/>

---
Dynastic - CyberApocalypse2024 __

Contenido __

Dynastic - CyberApocalypse2024

__

Autor del reto: `aris`

Dificultad: Muy Fácil

## Enunciado __

” You find yourself trapped inside a sealed gas chamber, and suddenly, the air is pierced by the sound of a distorted voice played through a pre-recorded tape. Through this eerie transmission, you discover that within the next 15 minutes, this very chamber will be inundated with lethal hydrogen cyanide. As the tape’s message concludes, a sudden mechanical whirring fills the chamber, followed by the ominous ticking of a clock. You realise that each beat is one step closer to death. Darkness envelops you, your right hand restrained by handcuffs, and the exit door is locked. Your situation deteriorates as you realise that both the door and the handcuffs demand the same passcode to unlock. Panic is a luxury you cannot afford; swift action is imperative. As you explore your surroundings, your trembling fingers encounter a torch. Instantly, upon flipping the switch, the chamber is bathed in a dim glow, unveiling cryptic letters etched into the walls and a disturbing image of a Roman emperor drawn in blood. Decrypting the letters will provide you the key required to unlock the locks. Use the torch wisely as its battery is almost drained out!”

##  Archivos __

En este reto nos dan dos archivos:

  * `source.py` : Contiene el código fuente que procesa la flag.
  * `output.txt` : Contiene la flag encriptada


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Dynastic).

## Analizando el código __

Si le echamos un vistazo al script`source.py` podemos ver que la flag se procesa en una función que la cifra, nosotros en este caso tenemos que crear una función que la descifre.

Si le echamos un ojo al algoritmo de cifrado podemos ver lo siguiente:

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
```

| 

```
     def to_identity_map(a):
        return ord(a) - 0x41
    
    def from_identity_map(a):
        return chr(a % 26 + 0x41)
    
    def encrypt(m):
        c = ''
        for i in range(len(m)):
            ch = m[i]
            if not ch.isalpha():
                ech = ch
            else:
                chi = to_identity_map(ch)
                ech = from_identity_map(chi + i)
            c += ech
        return c
```  
  
---|---  
`

  1. Se itera sobre los caracteres de la flag.
  2. Si el carácter de la posición flag[i] no pertenece a el alfabeto `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` se une directamente con el texto cifrado sin ser encriptado.
  3. Si el carácter de la posición flag[i] pertenece a un carácter del alfabeto, entonces se procesa en la función `to_identity_map` la cual se basa en pasar dicho carácter a un valor numérico de la tabla ASCII y posteriormente le resta el valor 0x41. Esto está basado en asignar un número a cada letra del alfabeto, de modo en el que obtenemos la tabla $[A=0, B=1, C=2, …, Z=25]$ Por ejemplo, si $ch = 0x45$ (E), entonces se mapea al valor $0x45 - 0x41 = 4$ entre el rango de $[0, 25]$.

  4. Finalmente, pasamos el valor numérico de la tabla descrita anteriormente + la iteración actual del bucle a la función `from_identity_map` la cual se encarga de hacer el módulo al número introducido para asegurar que el numero introducido esté dentro del alfabeto (módulo 25), posteriormente, se suma 0x41 correspondiente al valor 65 y por ultimo se pasa dicho entero a un carácter de la talbla ASCII y arroja el valor. De este modo se produce un incremento de $i posiciones siendo $i iterativo del largo del mensaje de la flag. Por ejemplo, cuando $i = 4$ y $ch = 0x44 = \ ‘D’$, el carácter mapeado sería $0x44 - 0x41 = 3$. Luego el carácter cifrado sera $ech = 3 + 4 = 7$. Mirando la conversión de la tabla (La cual empieza con índice 0) arroja la letra $’H’$


A este tipo de cifrado se le denomina `Trithemius cipher` el cual si ignoramos que el cifrado incrementa iterativamente en 1 por cada letra y no es estático, este es idéntico al `cifrado César`.

## Solución __

La vulnerabilidad de este cifrado reside en las mismas de los cifrados de sustitución monoalfabéticos en los cuales el conjunto de posibilidades es muy pequeño, lo que resulta en un ataque de fuerza bruta factible.

De todos modos no hay necesidad de hacerlo en este reto debido a que sabemos que el desplazamiento es iterativo y es conocido.

La primera letra se desplaza a la **izquierda** por 1, la segunda a la izquierda por 2 y así sucesivamente. Entonces, lo único que tenemos que hacer es desplazar el texto cifrado hacia la **derecha** para contrarestar dicho desplazamiento.

Básicamente el único cambio para obtener la función decrypt será cambiar el desplazamiento hacia a la derecha restando $i - 1$ a su vez nos basaremos en la funcion encrypt para desarrollarla.

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
```

| 

```
     def to_identity_map(a):
        return ord(a) - 0x41
    
    def from_identity_map(a):
        return chr(a % 26 + 0x41)
    
    def decrypt(m):
        flag = ''
        for i in range(len(m)):
            ch = m[i]
            if not ch.isalpha():
                ech = ch
            else:
                chi = to_identity_map(ch)
                ech = from_identity_map(chi - i)
            flag += ech
        return flag
    
    def load_data(filename):
        with open(filename) as f:
            f.readline()
            cipher = f.readline()
            return cipher
    
    
    cipher = load_data('output.txt')
    flag = decrypt(cipher)
    print(f'HTB}')'''
```  
  
---|---  
`

## Flag __

`HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Cifrados Clásicos](https://k3sero.github.io/tags/cripto-cifrados-cl%C3%A1sicos/) [Dificultad - Muy Fácil](https://k3sero.github.io/tags/dificultad-muy-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [CyberApocalypseCTF](https://k3sero.github.io/tags/cyberapocalypsectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Dynastic%20-%20CyberApocalypse2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDynastic-Cripto-CyberApocalypse2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Dynastic%20-%20CyberApocalypse2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDynastic-Cripto-CyberApocalypse2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDynastic-Cripto-CyberApocalypse2024%2F&text=Dynastic%20-%20CyberApocalypse2024%20-%20Kesero "Telegram") __
