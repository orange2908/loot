---
title: "Hidden in Flash - UMassCTF 2025"
category: "hardware"
subcategory: "firmware"
type: "writeup"
tags: ["hardware", "firmware", "uart", "subprocess", "hidden", "flash", "umassctf", "umassctf-2025", "2025", "ctf-writeup"]
summary: "Hidden in Fash - UmassCTF2025"
source:
  name: "CTFtime writeup #40199"
  url: "https://ctftime.org/writeup/40199"
original_source: "https://k3sero.github.io/posts/Hidden-Flash-UmassCTF/"
ctf:
  name: "UMassCTF 2025"
  year: 2025
  challenge: "Hidden in Flash"
---

## Metadata

- **CTF:** UMassCTF 2025
- **Task:** Hidden in Flash
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40199>
- **Original writeup:** <https://k3sero.github.io/posts/Hidden-Flash-UmassCTF/>

---
Hidden in Fash - UmassCTF2025 __

Contenido __

Hidden in Fash - UmassCTF2025

__

Autor del reto: `Sanderbeggar`

Dificultad: Fácil

## Enunciado __

“My friend gave me a tiny square chip and said it had a flash player game with a secret in it. I figured out the chip is an CAT24C64B EEPROM module and hooked it up to an Arduino UNO R3. Can you help me write some code to read the game and find the secret?

Server Details:

Accepts ELF binaries up to 64 KiB Max runtime of 5 seconds (based on clock cycles) Max UART output of 4 kiB

python client.py  Ver pista I wonder what file format this is?

Ver pista I think I saw a program that could open this but I need to get the file off the chip.

Ver pista I wonder what metadata this file has?”

## Archivos __

Este reto nos da el siguiente archivo.

  * `client.py` : Contiene el archivo de conexión a la EPROM.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/Hidden%20in%20Flash).

## Analizando el reto __

En este reto, tenemos que leer la EPROM CAT24C64B para poder conseguir el juego flash en su interior y obtener la flag. Para ello tenemos un script de conexión`client.py`

## Solver __

Primero que nada tenemos que encontrar el esquemático oficial de la EPROM`CAT24C64B EEPROM` para ello una búsqueda rápida en internet y encontramos su [datasheet](https://www.onsemi.com/download/data-sheet/pdf/cat24c64bac4-d.pdf).

Para leer la EPROM a través del servidor, primero que encontrar la dirección de memoria donde comienza el I2C. Según el datasheet la dirección de comienzo se encuentra entre la dirección `0x50` y `0x57`. Para encontrarla exactamente utilicé el siguiente script.

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
     #include <avr/io.h>
    #include <util/twi.h>
    #include <util/delay.h>
    
    #define F_CPU 16000000UL
    
    void uart_init(void) {
        UBRR0H = 0;
        UBRR0L = 103;
        UCSR0B = (1 << TXEN0);
        UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
    }
    
    void uart_send(uint8_t b) {
        while (!(UCSR0A & (1 << UDRE0)));
        UDR0 = b;
    }
    
    void uart_print(const char *s) {
        while (*s) uart_send(*s++);
    }
    
    void uart_print_hex(uint8_t b) {
        const char hex[] = "0123456789ABCDEF";
        uart_send(hex[b >> 4]);
        uart_send(hex[b & 0x0F]);
    }
    
    void i2c_init(void) {
        TWSR = 0;
        TWBR = 72;
        TWCR = (1 << TWEN);
    }
    
    uint8_t i2c_check(uint8_t addr) {
        TWCR = (1 << TWINT) | (1 << TWSTA) | (1 << TWEN);
        while (!(TWCR & (1 << TWINT)));
    
        TWDR = addr << 1;
        TWCR = (1 << TWINT) | (1 << TWEN);
        while (!(TWCR & (1 << TWINT)));
    
        uint8_t status = TWSR & 0xF8;
        TWCR = (1 << TWINT) | (1 << TWEN) | (1 << TWSTO);
    
        return (status == 0x18 || status == 0x40);  // ACK received
    }
    
    int main(void) {
        uart_init();
        i2c_init();
    
        uart_print("I2C Scan:\n");
    
        for (uint8_t addr = 0; addr < 128; addr++) {
            if (i2c_check(addr)) {
                uart_print("Found device at 0x");
                uart_print_hex(addr);
                uart_send('\n');
            }
            _delay_ms(50);
        }
    
        return 0;
    }
```  
  
---|---  
`

Par ello, primero tenemos que compilarlo para obtener el binario .elf y pasarlo junto a un script actualizado de `client.py` al que llamaremos `dump.py` al cual le pasaremos dicho binario.elf

Para compilarlo crearemos un `Makefile` con las siguientes instrucciones.

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
    MCU      = atmega328p
    F_CPU    = 16000000UL
    CC       = avr-gcc
    CFLAGS   = -std=gnu11 -Wall -Os -mmcu=$(MCU) -DF_CPU=$(F_CPU)
    
    all: dump.elf
    
    dump.elf: main.c
            $(CC) $(CFLAGS) -o dump.elf main.c
    
    clean:
            rm -f dump.elf
```  
  
---|---  
`

El script `dump.py` es el siguiente:

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
```

| 

```
     from sys import argv
    import sys
    import socket
    import time
    
    MAX_SIZE = 64 * 1024
    HOST = "hardware.ctf.umasscybersec.org"
    PORT = 10003
    
    if len(argv) != 2:
        sys.stderr.write(f"Usage: {argv[0]} FIRMWARE_PATH\n")
        exit(1)
    
    with open(argv[1], 'rb') as f:
        firmware = f.read()
    
    if len(firmware) > MAX_SIZE:
        sys.stderr.write(f"Firmware too large: {len(firmware)} > {MAX_SIZE}\n")
        exit(1)
    
    time_err = TimeoutError(
        "Did not receive expected data in time. Please make sure you are submitting an ELF and try again or submit a ticket"
    )
    
    def recv(sock: socket.socket, num_bytes: int, timeout: float = 5) -> bytes:
        data = b''
        start = time.time()
        while num_bytes > 0 and time.time() - start < timeout:
            chunk = sock.recv(num_bytes)
            if not chunk:
                break
            data += chunk
            num_bytes -= len(chunk)
        if num_bytes:
            raise time_err
        return data
    
    def recv_until(sock: socket.socket, end: bytes, timeout: float = 5) -> bytes:
        buf = b''
        start = time.time()
        while time.time() - start < timeout:
            byte = sock.recv(1)
            if byte == end:
                return buf
            buf += byte
        raise time_err
    
    with socket.socket(socket.AF_INET, socket.SocketKind.SOCK_STREAM) as s:
        sys.stderr.write("Connecting...\n")
        s.connect((HOST, PORT))
        sys.stderr.write("Sending firmware...\n")
        s.sendall(len(firmware).to_bytes(4, "little") + firmware)
    
        # initial handshake
        resp = recv(s, 1)
        if resp != b"\x00":
            sys.stderr.write("Unknown response from server\n")
            exit(1)
    
        sys.stderr.write("Running code...\n")
        rsp_msgs = [
            "Code ran successfully!",
            "Internal error occurred while setting up sim. Please make sure you are uploading an ELF file for the atmega328p at 16MHz. If the issue persists, submit a ticket.",
            "The sim crashed while running your code. Please make sure your code is built for the atmega328p at 16MHz."
        ]
        ret = int.from_bytes(recv(s, 1), 'little')
        if ret < len(rsp_msgs):
            sys.stderr.write(rsp_msgs[ret] + "\n")
        else:
            sys.stderr.write("Unknown response from server\n")
            exit(1)
    
        # read length-prefixed UART data
        length = int.from_bytes(recv(s, 4), 'little')
        data = recv(s, length)
    
        # dump raw UART bytes to stdout
        sys.stdout.buffer.write(data)
```  
  
---|---  
`

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
    ┌──(kesero㉿kali)-[~]
    └─$ python dump.py dump.elf
    
    Found device at 0x54.
```  
  
---|---  
`

Listo! Una vez tenemos la dirección de comienzo, partiremos de ahí para comenzar a dumpear toda la información en su interior.

Antes que nada, volveremos a modificar el script `client.py` para ir leyendo cada 4.096B hasta que llegue al final y reconstruir el firwmare en cada iteración.

El script es el siguiente. (El código perteneciente a [yun](https://yun.ng/c/ctf/2025-umass-ctf/hardware/hidden-in-flash) es mucho mejor y está más optimizado que el mío propio)

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
    90
    91
    92
    93
    94
    95
    96
    97
    98
    99
    100
    101
    102
    103
    104
    105
    106
    107
    108
    109
    110
    111
    112
    113
    114
    115
    116
    117
    118
    119
    120
```

| 

```
     import os
    import re
    import sys
    import subprocess
    import socket
    import time
    
    START = 0
    TOTAL = 4 * 1024
    HOST = "hardware.ctf.umasscybersec.org"
    PORT = 10003
    BUILD_DIR = "build"
    
    
    def update_bounds(sketch_name="eeprom_dump.ino"):
        path = os.path.join('.', sketch_name)
        with open(path, 'r') as f:
            code = f.read()
    
        new_line = f"const uint32_t TOTAL   = {TOTAL};\n"
        pattern = r"const\s+uint\d+_t\s+TOTAL\s*=.*?;"
        updated_code, count = re.subn(pattern, new_line.strip(), code)
        if count == 0:
            print("WARNING: No TOTAL definition found")
    
        new_line = f"const uint32_t START   = {START};\n"
        pattern = r"const\s+uint\d+_t\s+START\s*=.*?;"
        updated_code, count = re.subn(pattern, new_line.strip(), updated_code)
        if count == 0:
            print("WARNING: No START definition found")
    
        with open(path, 'w') as f:
            f.write(updated_code)
        print(f"Updated TOTAL&START in {sketch_name}.")
    
    
    def compile_sketch():
        cmd = [
            "arduino-cli", "compile",
            "--fqbn", "arduino:avr:uno",
            "--build-path", 'build',
            '.'
        ]
        print("Compiling sketch...")
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Compilation failed: {e}")
            sys.exit(1)
    
        build_path = os.path.join('.', BUILD_DIR)
        return os.path.join(build_path, "eeprom_dump.ino.elf")
    
    
    def send_firmware(elf_path):
        with open(elf_path, 'rb') as f:
            data = f.read()
    
        time_err = TimeoutError("Did not receive expected data in time.")
    
        def recv(sock, num_bytes, timeout=5.0):
            output = b''
            start = time.time()
            while num_bytes > 0 and time.time() - start < timeout:
                recvd = sock.recv(num_bytes)
                if not recvd:
                    break
                num_bytes -= len(recvd)
                output += recvd
            if num_bytes:
                raise time_err
            return output
    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("Connecting...")
            s.connect((HOST, PORT))
            print("Sending firmware...")
            s.sendall(len(data).to_bytes(4, 'little') + data)
            if recv(s, 1) != b"\x00":
                print("Unknown response from server")
                sys.exit(1)
    
            print("Running code...")
            rsp_msgs = [
                "Code ran successfully!",
                "Internal error setting up sim."
                "The sim crashed while running your code."
            ]
            ret = int.from_bytes(recv(s, 1), 'little')
            if ret < len(rsp_msgs):
                print(rsp_msgs[ret])
            else:
                print("Unknown response from server")
            out_len = int.from_bytes(recv(s, 4), 'little')
            data = recv(s, out_len)
            return data
    
    
    def main():
        global TOTAL, START
        all_data = b''
        total_iterations = 16
        for i in range(total_iterations):
            START = i * 1024*4
            TOTAL = (i + 1) * 1024*4
            print(f"Trying with START={START} and TOTAL={TOTAL}")
            update_bounds()
            elf = compile_sketch()
            data = send_firmware(elf)
            all_data += data
            print(f"Received {len(data)} bytes of data.")
            print(f"{i}/{total_iterations}")
        print("Writing data to eeprom_dump.bin")
        with open("eeprom_dump.bin", "wb") as f:
            f.write(all_data)
        print("Done!")
    
    
    if __name__ == '__main__':
        main()
```  
  
---|---  
`

Por último, tenemos que crear un código de extracción, para ello podemos hacerlo en `c` o en `.ino` directamente. En este caso el script es el siguiente.

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
```

| 

```
     #include <Wire.h>
    
    const uint8_t  EE_ADDR = 0x54;
    const uint32_t START = 0;
    const uint32_t TOTAL = 4096;
    
    void setup() {
        Wire.begin();
        Serial.begin(115200);
        delay(100);
    }
    
    void loop() {
        for (uint32_t addr = START; addr < TOTAL; addr += 1) {
            Wire.beginTransmission(EE_ADDR);
            Wire.write(uint8_t(addr & 0xFF));
            Wire.write(uint8_t(addr >> 8));
            Wire.endTransmission(false);
            uint8_t  chunk = 1;
            Wire.requestFrom(EE_ADDR, chunk);
            for (int i = 0; i < chunk; i++) {
                while (!Wire.available()) delayMicroseconds(1);
                Serial.write(Wire.read());
            }
        }
        while (1);
    }
```  
  
---|---  
`

Una vez extraida el binario perteneciente a la rom, con elcomando `file` podemos comprobar que tipo de archivo es.

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
    ┌──(kesero㉿kali)-[~]
    └─$ file dump.bin
    
    eeprom_dump.bin: Macromedia Flash data (compressed), version 6
```  
  
---|---  
`

Si le lanzamos un `xxd` a dicho binario encontramos lo siguiente.

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
    ┌──(kesero㉿kali)-[~]
    └─$ xxd dump.bin
    
    00000000:  43 57 53 06 88 9F 00 00 78 9C E4 BD 07 58 14 CD  CWS.....x....X..
    00000010:  D2 30 DA B3 89 05 96 9C A3 48 06 C9 48 10 50 16  .......H..H.P.
    00000020:  24 E7 9C 24 C3 92 24 09 0B 82 71 41 45 50 54 40  $..$..$...qAEPT@
    00000030:  39 B6 2A Fd B3 9B 17 78 A9 48 F9 48 4C D8 7B 40  9.*....x.H.HL.{@
    00000040:  D6 E1 C9 F7 92 88 F8 C9 B0 4A 88 58 83 FB B5 87  .........J.X....
    
    (...)
```  
  
---|---  
`

Como podemos observar, los magic bytes son `CWS`, este tipo de archivo corresponde a un archivo `flash.swf`.

Ahora solo tenemos que decompilarlo, para ello hay herramientas como [jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) que realizan decompilados en formato `.swf`.

Al introducir el binario en el decompilador, podemos leer la flag en texto claro.

[![decompiled](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/Hidden%20in%20Flash/decompiled.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/Hidden%20in%20Flash/decompiled.png)

## Flag __

`UMASS{asT3r0iDs!1}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Hardware](https://k3sero.github.io/categories/hardware/)

__[Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Hardware](https://k3sero.github.io/tags/hardware/) [Hardware - EPROM](https://k3sero.github.io/tags/hardware-eprom/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [UmassCTF](https://k3sero.github.io/tags/umassctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Hidden%20in%20Fash%20-%20UmassCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHidden-Flash-UmassCTF%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Hidden%20in%20Fash%20-%20UmassCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHidden-Flash-UmassCTF%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FHidden-Flash-UmassCTF%2F&text=Hidden%20in%20Fash%20-%20UmassCTF2025%20-%20Kesero "Telegram") __
