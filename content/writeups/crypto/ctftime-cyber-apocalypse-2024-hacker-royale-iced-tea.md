---
title: "Iced TEA - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "ecb", "cbc", "xor", "iced", "tea", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "IcedTEA - CyberApocalypse2024"
source:
  name: "CTFtime writeup #39640"
  url: "https://ctftime.org/writeup/39640"
original_source: "https://k3sero.github.io/posts/Iced-Tea-CyberApocalypse2024/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Iced TEA"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Iced TEA
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39640>
- **Original writeup:** <https://k3sero.github.io/posts/Iced-Tea-CyberApocalypse2024/>

---
IcedTEA - CyberApocalypse2024 __

Contenido __

IcedTEA - CyberApocalypse2024

__

Autor del reto: `aris`

Dificultad: Fácil

## Enunciado __

“Locked within a cabin crafted entirely from ice, you’re enveloped in a chilling silence. Your eyes land upon an old notebook, its pages adorned with thousands of cryptic mathematical symbols. Tasked with deciphering these enigmatic glyphs to secure your escape, you set to work, your fingers tracing each intricate curve and line with determination. As you delve deeper into the mysterious symbols, you notice that patterns appear in several pages and a glimmer of hope begins to emerge. Time is flying and the temperature is dropping, will you make it before you become one with the cabin?”

##  Archivos __

En este reto tenemos los siguientes archivos.

  * `source.py` : Contiene el script de cifrado principal
  * `output.txt` : El archivo de salida, el cual contiene la llave de cifrado junto la flag cifrada, ambas en formato hexadecimal.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/IcedTEA).

## Analizando el código __

Para comenzar, podemos observar que el código principal muestra un algoritmo de cifrado llamado`TEA` el cual puede usar el modo de bloques `CBC` o `ECB` para cifrar un mensaje proporcionado.

Comencemos a analizar con la función `main` y la iremos desglosando poco a poco.

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
     if __name__ == '__main__':
        KEY = os.urandom(16)
        cipher = Cipher(KEY)
        ct = cipher.encrypt(FLAG)
        with open('output.txt', 'w') as f:
            f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```  
  
---|---  
`

Como podemos ver, se genera de forma aleatoria una llave de 16 bytes que se usará como llave de cifrado. Posteriormente se cifra la flag y ambas son arrojadas al fichero `output.txt` en hexadecimal.

Vamos a entender cómo funciona la clase `Cipher`

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
```

| 

```
     from enum import Enum
    
    class Mode(Enum):
        ECB = 0x01
        CBC = 0x02
    
    class Cipher:
        def __init__(self, key, iv=None):
            self.BLOCK_SIZE = 64
            self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
            self.DELTA = 0x9e3779b9
            self.IV = iv
            if self.IV:
                self.mode = Mode.CBC
            else:
                self.mode = Mode.ECB
        
        def _xor(self, a, b):
            # ...
    
        def encrypt(self, msg):
            # ...
    
        def encrypt_block(self, msg):
            # ...
```  
  
---|---  
`

Desglosando la información proporcionada por los constructores de la clase, podemos afirmar lo siguiente:

  1. Podemos concluir que el cifrado es un cifrado de bloques donde cada bloque es de 64 bits.

  2. Dicho cifrado propone dos modos de cifrado de bloques `ECB` y `CBC`. En el caso en el que la función reciba el `IV` y el modo de cifrado de bloques, se pasa automáticamente a establecerse en `CBC`. Por el otro lado, si no se proporciona el IV a la función, el modo de cifrado de bloques pasará a establecerse a `ECB`.

  3. La `Key` esta separada en $\dfrac{64}{16}=4$ palabras (cuatro cuartetos de bytes)


Podemos observar que, como en la función main no se proporciona el IV correspondiente, podemos garantizar que la flag está encriptada únicamente con el cifrado de bloques ECB, por lo que vamos a echar un vistazo a cómo está creada la funcion `encrypt` usando únicamente el modo ECB.

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
     def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
    
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
        		# ...
            
    		return ct
```  
  
---|---  
`

Como podemos ver, la implementación es trivial ya que cada bloque en texto claro es cifrado y concatenado con el anterior texto cifrado.

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
     def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
    
        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
    
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1
    
        return l2b(m)
```  
  
---|---  
`

Como en el ejercicio nos dan la llave del cifrado, no es necesario romper en sí el algoritmo de cifrado. Simplemente necesitamos crear una función para descifrar el texto cifrado utilizando las operaciones inversas utilizadas en la función `encrypt`, solamente necesitamos saber revertir las operaciones.

En la página oficial de Wikipedia del [Algoritmo TEA](https://es.wikipedia.org/wiki/Tiny_Encryption_Algorithm#:~:text=En%20criptograf%C3%ADa%2C%20el%20Tiny%20Encryption,unas%20pocas%20l%C3%ADneas%20de%20c%C3%B3digo), nos dan una funcion genérica de cifrado y de descifrado y ya establecidas (escritas en C) pero siguiendo la misma metodología, podemos replicarla en python y crear dicha función.

## Solución __

Como hemos mencionado anteriormente, como tenemos la llave del cifrado, no tenemos necesidad de explotar ninguna vulnerabilidad relacionado con el algoritmo implementado. Además, también tenemos la constante DELTA`0x9e3779b9` del cifrado; esto es esencial para revertir la funcion de encriptación.

Además, como he mencionado anteriormente, en la página de Wikipedia se proporciona el algoritmo de cifrado como el de descifrado utilizando el algoritmo TEA, por lo que recapitulando, tenemos la llave del cifrado, el tamaño de bloque, la constante delta y por último el texto cifrado por lo que tenemos todo lo necesario para revertir el proceso

Lo que yo hice básicamente fue implementar en python la función de descifrado de Wikipedia, modificando una serie de parámetros para obtener los valores directamente del constructor de la `clase Cipher`.

Pero antes de proceder con el script, necesitamos un tratamiento previo de la Key ya que como hemos mencionado anteriormente, tenemos que transformar la llave en cuatro partes y también separar los bloques de manera en que cada bloque opere con la lista de claves.

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
```

| 

```
     from Crypto.Util.number import bytes_to_long, long_to_bytes
    
    
    def decrypt_block(msg, key_list):
        m = bytes_to_long(msg)
        K = key_list
        msk = (1 << (64//2)) - 1
    
        s = 0x9e3779b9 << 5
        for i in range(32):
            m1 = m & msk
            m0 = m >> (64//2)
            
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            
            s -= 0x9e3779b9
            
            m = ((m0 << (64//2)) + m1) & ((1 << 64) - 1)
    
        return long_to_bytes(m)
    
    
    key_hex = "850c1413787c389e0b34437a6828a1b2"
    cipher_hex = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"
    
    key_bytes = bytes.fromhex(key_hex)
    cipher_bytes = bytes.fromhex(cipher_hex)
    
    key_long = bytes_to_long(key_bytes)
    cipher_long = bytes_to_long(cipher_bytes)
    
    key_list = [bytes_to_long(key_bytes[i:i+64//16]) for i in range(0, len(key_bytes), 64//16)]
    
    
    # Cuidado Pad msg = pad(msg, 64//8)
    blocks = [cipher_bytes[i:i+64//8] for i in range(0, len(cipher_bytes), 64//8)]
    
    plaintext_blocks = [decrypt_block(block, key_list) for block in blocks]
    
    plaintext = b''.join(plaintext_blocks)
    print(plaintext)
```  
  
---|---  
`

## Flag __

`HTB{th1s_1s_th3_t1ny_3ncryp710n_4lg0r1thm_____y0u_m1ght_h4v3_4lr34dy_s7umbl3d_up0n_1t_1f_y0u_d0_r3v3rs1ng}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Algoritmos](https://k3sero.github.io/tags/cripto-algoritmos/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [CyberApocalypseCTF](https://k3sero.github.io/tags/cyberapocalypsectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=IcedTEA%20-%20CyberApocalypse2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIced-Tea-CyberApocalypse2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=IcedTEA%20-%20CyberApocalypse2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIced-Tea-CyberApocalypse2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FIced-Tea-CyberApocalypse2024%2F&text=IcedTEA%20-%20CyberApocalypse2024%20-%20Kesero "Telegram") __
