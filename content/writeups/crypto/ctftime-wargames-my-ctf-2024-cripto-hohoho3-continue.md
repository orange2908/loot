---
title: "[Cripto] Hohoho3 Continue - Wargames.MY CTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "cripto", "hohoho3", "continue", "wargames-my-ctf", "wargames-my-ctf-2024", "2024", "ctf-writeup"]
summary: "Hohoho3 Continue (First Blood) - WarGamesCTF2024"
source:
  name: "CTFtime writeup #39737"
  url: "https://ctftime.org/writeup/39737"
original_source: "https://k3sero.github.io/posts/Hohoho3-Continue-WarGamesCTF2024/"
ctf:
  name: "Wargames.MY CTF 2024"
  year: 2024
  challenge: "[Cripto] Hohoho3 Continue"
---

## Metadata

- **CTF:** Wargames.MY CTF 2024
- **Task:** [Cripto] Hohoho3 Continue
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39737>
- **Original writeup:** <https://k3sero.github.io/posts/Hohoho3-Continue-WarGamesCTF2024/>

---
Hohoho3 Continue (First Blood) - WarGamesCTF2024 __

Contenido __

Hohoho3 Continue (First Blood) - WarGamesCTF2024

__

Autor del reto: `SKR`

Dificultad: Media

## Enunciado __

“Someone broke the service! Now everyone can only register once…”

##  Archivos __

En este reto nos dan los siguientes archivos.

  * `server.py` : Contiene el código que se ejecuta en el servidor.
  * `nc 43.216.228.210 32923` : Conexión por netcat al servidor del reto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3_Continue).

## Preámbulo __

Este reto es la continuación de[Hohoho3](https://k3sero.github.io/posts/Hohoho3-WarGamesCTF2024/), como este lo resolví de manera `unintended`, la resolución de ese ejercicio es justo la que piden en esta continuación.

## Analizando el código __

El script`server.py` contiene lo siguiente.

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
    66
    67
    68
    69
    70
    71
    72
    73
    74
    75
    76
    77
    78
    79
    80
    81
    82
    83
    84
    85
    86
    87
    88
    89
```

| 

```
     #!/usr/bin/env python3
    import hashlib
    from Crypto.Util.number import *
    
    m = getRandomNBitInteger(128)
    
    class User:
    	def __init__(self, name, token):
    		self.name = name
    		self.mac = token
    
    	def verifyToken(self):
    		data = self.name.encode(errors="surrogateescape")
    		crc = (1 << 128) - 1
    		for b in data:
    			crc ^= b
    			for _ in range(8):
    				crc = (crc >> 1) ^ (m & -(crc & 1))
    		return hex(crc ^ ((1 << 128) - 1))[2:] == self.mac
    
    def generateToken(name):
    	data = name.encode(errors="surrogateescape")
    	crc = (1 << 128) - 1
    	for b in data:
    		crc ^= b
    		for _ in range(8):
    			crc = (crc >> 1) ^ (m & -(crc & 1))
    	return hex(crc ^ ((1 << 128) - 1))[2:]
    
    def printMenu():
    	print("1. Register")
    	print("2. Login")
    	print("3. Make a wish")
    	print("4. Wishlist (Santa Only)")
    	print("5. Exit")
    
    def main():
    	print("Want to make a wish for this Christmas? Submit here and we will tell Santa!!\n")
    	user = None
    	while(1):
    		printMenu()
    		try:
    			option = int(input("Enter option: "))
    			if option == 1:
    				name = str(input("Enter your name: "))
    
    				print(m)
    
    				if "Santa Claus" in name:
    					print("Cannot register as Santa!\n")
    					continue
    				print(f"Use this token to login: {generateToken(name)}\n")
    				
    			elif option == 2:
    				name = input("Enter your name: ")
    				mac = input("Enter your token: ")
    				user = User(name, mac)
    				if user.verifyToken():
    					print(f"Login successfully as {user.name}")
    					print("Now you can make a wish!\n")
    				else:
    					print("Ho Ho Ho! No cheating!")
    					break
    			elif option == 3:
    				if user:
    					wish = input("Enter your wish: ")
    					open("wishes.txt","a").write(f"{user.name}: {wish}\n")
    					print("Your wish has recorded! Santa will look for it!\n")
    				else:
    					print("You have not login yet!\n")
    
    			elif option == 4:
    				if user and "Santa Claus" in user.name:
    					wishes = open("wishes.txt","r").read()
    					print("Wishes:")
    					print(wishes)
    				else:
    					print("Only Santa is allow to access!\n")
    			elif option == 5:
    				print("Bye!!")
    				break
    			else:
    				print("Invalid choice!")
    		except Exception as e:
    			print(str(e))
    			break
    
    if __name__ == "__main__":
    	main()
```  
  
---|---  
`

Este reto es un sistema de autenticación basado en tokens generados mediante un algoritmo `CRC` personalizado con una constante aleatoria `m`. Los usuarios pueden registrarse, obtener un token único, iniciar sesión, y guardar deseos en un archivo. Solo `Santa Claus` tiene permiso para leer todos los deseos y es por ello que no podemos registrar el usuario `Santa Claus` y deberemos loguearnos con su nombre para poder leer la lista de deseos y recuperar la flag.

Antes de continuar, tenemos que echarle un vistazo en detalle de la función `generateTokens()` y sobre todo entender cómo funciona la lógica operacional en ella.

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
     def generateToken(name):
    	data = name.encode(errors="surrogateescape")
    	crc = (1 << 128) - 1
    	for b in data:
    		crc ^= b
    		for _ in range(8):
    			crc = (crc >> 1) ^ (m & -(crc & 1))
    	return hex(crc ^ ((1 << 128) - 1))[2:]
```  
  
---|---  
`

  1. La función obtiene un string con el nombre del token a generar el cual se convierte en una representación en bytes utilizando la codificación por defecto (UTF-8), pero con un comportamiento especial para manejar errores de codificación.

  2. Se establece un valor inicial de crc de `340282366920938463463374607431768211455`.

  3. Se recorre un bucle for por cada caracter `b` de la variable `data`. (NOTA: Es muy importante saber que b se interpreta como un valor entre 0 hasta 255)

  4. Se realiza una operación `XOR` tal que \\(\text{crc} = \text{crc} \oplus b\\)

  5. Posteriormente se realiza un bucle con 8 iteraciones (1 para cada bit menos significativo) en la cual se realiza la operación `XOR` entre el `primer término` (crc rotado a la derecha una posición) junto el `segundo término` (realiza la operación `AND` del bit menos significativo de `crc` con `1`, se niega el resultado y por último, se vuelve a realizar la operación `AND` con `m`, siendo `m` un valor generado aleatoriamente).

  6. Para finalizar, la función devuelve los bits invertidos de crc y convierte el resultado en una cadena hexadecimal sin el prefijo ‘0x’.


## Solución __

Una vez comprendido a groso modo todo el comportamiento del script y sobre todo de la función que genera los tokens, se nos ocurrieron una gran diversidad de ideas. Una de ellas viene por la realización de colisión de Hashes del hash perteneciente a Santa Claus, pero esto es inviable ya que el problema reside en que no tenemos el hash original.

Es por ello que una idea que tuve desde el comienzo fue en recuperar la semilla `m` para posteriormente, realizar un registro válido como el usuario Santa Claus sin la restricción por parte del servidor y por último introducir dicho hash en el servidor para iniciar sesión exitosamente y observar la preciada lista de deseos con la flag en ella.

Vale, pero ¿cómo recuperamos `m`?

Para recuperar m deberemos de ir más allá. Primero tendremos que realizar un breve script de testing/debug, para observar de primera mano el valor de cada variable en cada iteración. En este caso el que utilicé fue el siguiente.

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
```

| 

```
     import hashlib
    from Crypto.Util.number import *
    
    def generateToken(name, m):
        data = name.encode(errors="surrogateescape")
        crc = (1 << 128) - 1
    
        print(f"Este es el crc inicial {crc}")
    
        for b in data:
    
            print(f"Este es el valor de b: {b}")
    
            crc ^= b
            print(f"Este es el resultado de los bytes: {crc}")
            print(f"Este es el crc ^ b : {crc}")
    
            for _ in range(8):
    
                #print(f"Este es crc antes de actualizarse {crc}")
    
                print(f"Valor de crc >> 1 : {crc >> 1}")
                print(f"Valor de -(crc & 1) : {-(crc & 1)}")
                print(f"Segunda parte del XOR {(m & -(crc & 1))}")
                print(f"")
    
                crc = (crc >> 1) ^ (m & -(crc & 1))
    
                print(f"Este es crc despues de actualizarse {crc}")
    
        print(crc)
    
        return hex(crc ^ ((1 << 128) - 1))[2:]
    
    name = str(input("Enter your name: "))
    print(f"Valor de name es : {name}")
    
    m = 314320694760960186183647210177372466087
    print(f"Este es el m generado: {m}")
    print(f"")
    token = generateToken(name, m)
    print(f"Este es el resultado final: {token}")
    
    
    token = int(hex_value, 16)
    
    token = token ^ ((1 << 128) - 1)
    print(token)
    #name = "\x7f"
```  
  
---|---  
`

Después de muchas iteraciones y de realizar numerosas pruebas en el intérprete de Python me di cuenta de lo siguiente. Comencemos con la función más importante de la generación de Tokens `crc = (crc >> 1) ^ (m & -(crc & 1))`.

  1. Sabemos que si realizamos por ejemplo 4 ^ 0 = 4, cuando la parte de la derecha valga 0, se realizará la operación `XOR` de crc ^ 0 = crc, por tanto `m` no tendrá efecto en dicha iteración.


Llegados a este punto, me dí cuenta de que `m` se puede recuperar siempre y cuando de en las 8 iteraciónes, 7 de ellas el segundo término `(m & -(crc & 1))` sea `0` y solamente en una de ellas, el resultado debe ser distinto de `0`, ya que si esto se cumple, el valor de `m` estará presente únicamente en dicha iteración (ya que se computaría como `crc = crc ^ m`) y no debe de haber más valores iguales ya que no tendríamos control en las siguientes iteraciones de la variable `crc`.

Para lograr obtener un `0` en el segundo término `(m & -(crc & 1))`, tenemos que saber que para que el resultado de la operación `AND` entre dos variables sea `0`, el primer término debe de ser `0` y en nuestra casuística, siempre tendremos un término disinto de `0`.

Tabla de la operación `AND`

(A)| (B)| (A AND B)  
---|---|---  
0| 0| 0  
0| 1| 0  
1| 0| 0  
1| 1| 1  
  
Como en el segundo término la operación más externa es `(m & (resultado))`, sabemos que para obtener un `0`, tenemos que hacer forzosamente que `resultado` tenga el valor `0`, ya que el resultado final del segundo termino, sería un `0` también.

Siguiendo la misma filosofía con la operación interna, para que `-(crc & 1)` sea `0`, tenemos que hacer que el bit menos significativo de `crc`, sea `0` también.

Por tanto, tenemos que manipular el valor de `crc`, para que de las 8 iteraciones, 7 de ellas los resultados sean `0` y solamente en una de ellas el resultado sea `1` pero, ¿cómo hacemos esto?

El único control que tenemos es el de la variable `name` el cual incluye el nombre a registrar que como hemos comentado anteriormente con el bucle `for b in data:`, se recorren en forma de bytes cada caracter. En este caso nosotros solo tenemos que trabajar con un carácter, ya que si trabajásemos con más caracteres, las iteraciones se duplican por 2, es decir, en vez de 8 iteraciones en el bucle, tendríamos 16 y sería mucho mas difícil de controlar cada valor.

Por tanto, tenemos que encontrar un caracter, que al realizar `crc ^= b`, deje los 8 bits menos significativos a un valor, los cuales 7 de ellos deben ser `0` y solo uno de ellos tiene que ser `1`.

Recordemos que la expresion binaria del crc inicial es la siguiente.

____

`

```
    1
    2
```

| 

```
    >>> bin(crc)
    '0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'
```  
  
---|---  
`

Probando combinaciones, nos damos cuenta de que el valor `01111111`, voltea los últimos bits convirtiéndolos en:

____

`

```
    1
    2
    3
    4
```

| 

```
    >>> int(0b01111111)
    127
    >>> bin(crc ^ 127)
    '0b1111111111111111111111 (...) 1111111111111111111111111111111110000000'
```  
  
---|---  
`

NOTA: Realmente podemos dejar dentro de los 8 bits, el menos significativo a 1 ya que el procedimiento sería el mismo pero al contrario.

Listo, simplemente tenemos que hacer que `b` valga `127` una vez que `data` se ha procesado y ya estaría, ¿no?

El problema es que la variable `name` se interpreta con un `str()` de la siguiente manera:

____

`

```
    1
```

| 

```
    name = str(input("Enter your name: "))
```  
  
---|---  
`

Por tanto, si realizamos la conversión del valor `127` a `chr()`, obtenemos que el valor a introducir es el byte `'\x7f'`, el cual al ejecutar el programa este se interpreta como caracteres individuales y no como el valor del propio byte. Entonces deberemos de buscar un valor de entre los caracteres imprimibles de python, que al realizar la operación `str()`, devuelva un valor en `ASCII` que nos sirva para poder manipular la variable `crc` y poder obtener `m`.

Sabemos de antemano que los caracteres imprimibles de python son los siguientes.

____

`

```
    1
```

| 

```
    0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ 
```  
  
---|---  
`

Probando combinaciones nuevamente, nos damos cuenta de que uno de los valores potenciales es `'?'` ya que, al realizar:

____

`

```
    1
    2
```

| 

```
    bin(crc ^ ord("?"))
    '0b111111111111111111111111111(...)1111111111111111 11000000'
```  
  
---|---  
`

Pero, ¿por qué nos sirve este caracter imprimible?

A pesar de que contamos con los dos bits más significativos a `1`, realmente cuando se haga la primera iteración con el valor de `m` (es decir, cuando se calcule el primer `1`) el resultado será impredecible, ya que entra en juego `m`, por tanto en la siguiente iteración no tendríamos control de dicho bit, pudiendo ser `1` o `0` dependiendo de los bits de `m`, que es aleatorio.

Por ende, nosotros lo que haremos sera ejecutar el programa varias veces hasta que se dé la casuística de que el bit más significativo sea `0`.

En este punto, realizamos una conexión en remoto y registramos el usuario con el nombre `?` para obtener un hash con las condiciones mencionadas anteriormente.

Para concluir, una vez tenemos en control de las 8 ejecuciones del bucle, simplemente tenemos que revertir el hash que nos arrojan al registrar un usuario, hacer el proceso contrario, para que mediante puertas `XOR`, podamos despejar `m` de la siguiente manera.

\\[\text{crc}_{\text{final}} = \text{crc}_{\text{anterior}} \oplus m\\]

Para obtener el `crc_final` simplemente revertimos el hash obtenido mediante el siguiente código.

____

`

```
    1
    2
    3
    4
```

| 

```
     hex_value = "893bfb5e64002449d089a2c04b04d5d3"
    
    token = int(hex_value, 16)
    crc_final = token ^ ((1 << 128) - 1)
```  
  
---|---  
`

Además, tenemos que rotar un bit a la izquierda `crc_final` ya que sabemos que `m` se ha utilizado únicamente en la iteración 7 y como he mencionado anterior, suponemos que en la iteración 8 del bucle, el resultado es `0`. Por tanto tenemos que rotar `crc_final` una vez a la izquierda.

____

`

```
    1
```

| 

```
     crc_final = crc_final << 1
```  
  
---|---  
`

Tenemos que hacer el mismo procedimiento con `crc_inicial`, ya que para obtener el valor de `crc` en la iteración 7, este se ha rotado únicamente 7 veces a la derecha, por tanto tenemos que deshacer las rotaciones rotando 7 veces a la izquierda para obtener dicho valor.

____

`

```
    1
    2
```

| 

```
     crc_i = 340282366920938463463374607431768211455
    crc_inicial = crc_i >> 7
```  
  
---|---  
`

Por último realizamos el `XOR` mencionado anteriormente y obtenemos el valor de `m`. El código que utilicé fue el siguiente (Tenemos que introducir un hash válido computado en remoto para obtener un `m` valido)

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
     hex_value = "893bfb5e64002449d089a2c04b04d5d3"
    
    token = int(hex_value, 16)
    x2 = token ^ ((1 << 128) - 1)
    x2 = x2 << 1
    
    crc = 340282366920938463463374607431768211455
    x1 = crc >> 7
    
    m = x1 ^ x2
    
    print(f"Este es el m recuperado es : {m}")
```  
  
---|---  
`

Una vez que tenemos el `m` válido, simplemente tenemos que registrar en local el nombre de `Santa Claus` e introducir el hash obtenido en el servidor remoto, para loguearnos como `Santa Claus` en él (En este punto, si es válido sabemos que la iteración 8 ha sido 0 tal cual hemos supuesto, pero si es invalido pues hacemos el mismo proceso).

Este fue el código que utilicé. (Necesitamos el `m` recuperado anteriormente).

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
```

| 

```
     m = 189037830245809490512965016070455766621
    
    def generateToken(name):
    	data = name.encode(errors="surrogateescape")
    	crc = (1 << 128) - 1
    	for b in data:
    		crc ^= b
    		for _ in range(8):
    			crc = crc & 1 ^ (m & -(crc & 1))
    	return hex(crc ^ ((1 << 128) - 1))[2:]
    
    name = str(input("Enter your name: "))
    token = generateToken(name)
    print(token)
```  
  
---|---  
`

Una vez obtenido, lo introducimos en el servidor remoto para obtener la `flag`.

[![Final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3/final.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3/final.png)

## Flag __

`wgmy{3fa42c79018552d4419e67d186c91875}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Algoritmos](https://k3sero.github.io/tags/cripto-algoritmos/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [WarGamesCTF](https://k3sero.github.io/tags/wargamesctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Hohoho3%20Continue%20\(First%20Blood\)%20-%20WarGamesCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHohoho3-Continue-WarGamesCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Hohoho3%20Continue%20\(First%20Blood\)%20-%20WarGamesCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHohoho3-Continue-WarGamesCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHohoho3-Continue-WarGamesCTF2024%2F&text=Hohoho3%20Continue%20\(First%20Blood\)%20-%20WarGamesCTF2024%20-%20Kesero "Telegram") __
