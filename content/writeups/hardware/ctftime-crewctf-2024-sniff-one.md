---
title: "Sniff one - CrewCTF 2024"
category: "hardware"
subcategory: "protocols"
type: "writeup"
tags: ["hardware", "misc", "logic-analyzer", "sniff", "protocols", "crewctf", "crewctf-2024", "2024", "ctf-writeup"]
summary: "This was a two parts hardware challenge, we were provided with an attachment dist.zip, that contains a README.pdf and a .sal capture (check the attachment)."
source:
  name: "CTFtime writeup #39383"
  url: "https://ctftime.org/writeup/39383"
original_source: "https://mwlik.github.io/2024-08-05-crewctf-2024-sniff-challenge/"
ctf:
  name: "CrewCTF 2024"
  year: 2024
  challenge: "Sniff one"
---

## Metadata

- **CTF:** CrewCTF 2024
- **Task:** Sniff one
- **Author team:** Akasec
- **CTFtime tags:** hardware, misc
- **CTFtime:** <https://ctftime.org/writeup/39383>
- **Original writeup:** <https://mwlik.github.io/2024-08-05-crewctf-2024-sniff-challenge/>

---
* Sniff One = 27 solves, Sniff Two = 16 solves
  * Overview
  * Sniff One
  * Sniff Two
    * Pin layout
    * Setting The Image
    * Splitting The Image
    * Sending The Image


## Sniff One = 27 solves, Sniff Two = 16 solves

![image](https://github.com/user-attachments/assets/419aaaca-70a6-421a-a535-995fb2372d8c) ![image](https://github.com/user-attachments/assets/3236cfd0-47e4-409b-9c02-84f491f87118)

## Overview

This was a two parts hardware challenge, we were provided with an attachment [dist.zip](https://github.com/user-attachments/files/16499353/dist.zip), that contains a [README.pdf](https://github.com/user-attachments/files/16499323/README.pdf) and a `.sal` capture (check the attachment).

It was a setup linking a cardKB mini keyboard and an e-paper display with Raspy 4 model b:

![image](https://github.com/user-attachments/assets/89ed837a-b018-4c18-b051-da7b03ddfa49) ![image](https://github.com/user-attachments/assets/fdf39b01-edfc-4f45-b77f-eb7acc48093f)

```
    This challenge has two flags in the flag{} format:
      - The first (easier) is the password that was typed on the keyboard.
      - The second (significantly harder) is what was displayed to the screen after the password was entered.
```

So the challenge was depicting a person that entered the password (first easier flag) then the flag (second much harder flag) was displayed on the display, while everything was [sniffed](https://en.wikipedia.org/wiki/Sniffing_attack) by the [salae logic analyzer](https://www.saleae.com/), thus the job is to decode everything that was recoded to what it represent either its what was entered by the keyboard, or what was displayed in the e-ink display.

## Sniff One

So to find the first flag we need to find what was typed by the user of the keyboard, after researching the keyboard that was used, i found this pretty good [reference](https://docs.m5stack.com/en/unit/cardkb), and in it we find that the Communication method is [I2C](https://en.wikipedia.org/wiki/I%C2%B2C), for those that don’t know how I2C there is some good references u can consult, one of these is this [video](https://youtu.be/CAvawEcxoPU?si=dEOXzUjc35swLupM), so I2C is a communication protocal that has generally two channels `SDA` (the one responsiblle for transmitting data), `SCL` (the clock that synchronize the communication):

![image](https://github.com/user-attachments/assets/4bf58ea0-7e35-4729-8fa1-5ba62a7b9e66)

And looking at the sal capture:

![image](https://github.com/user-attachments/assets/2ad141d7-2dbb-40fb-be76-1b47a4420224)

I figured that D0 and D1 is SDA and SCL respectively, but you can verify this looking at pictures of the wiring like this one:

![image](https://github.com/user-attachments/assets/7ea5953b-e470-4cf3-8dcc-6615ec8c8775)

So I added the I2C analyzer to [Logic 2](https://www.saleae.com/pages/downloads) and exported the data as csv.

![image](https://github.com/user-attachments/assets/5e2c66b9-928e-405f-9482-c1a2efeabe95)

Now its time to decode those signals, but instead of doing it by hand why not just find a libray an already implemented library that will handle that for me?

That’s exactly what I did and found [this one](https://github.com/ian-antking/cardkb), so I made some modification to the code to suit my use case:

`ascii_codes.py`

```
    ascii = {
      # number row
        0x1B: ["KEY_ESC"],
        0x31: ["KEY_1"],
        0x32: ["KEY_2"],
        0x33: ["KEY_3"],
        0x34: ["KEY_4"],
        0x35: ["KEY_5"],
        0x36: ["KEY_6"],
        0x37: ["KEY_7"],
        0x38: ["KEY_8"],
        0x39: ["KEY_9"],
        0x30: ["KEY_0"],
        0x08: ["KEY_BACKSPACE"],
    
      # top row
        0x09: ["KEY_TAB"],
        0x71: ["KEY_Q"],
        0x77: ["KEY_W"],
        0x65: ["KEY_E"],
        0x72: ["KEY_R"],
        0x74: ["KEY_T"],
        0x79: ["KEY_Y"],
        0x75: ["KEY_U"],
        0x69: ["KEY_I"],
        0x6F: ["KEY_O"],
        0x70: ["KEY_P"],
    
      # home row
        0x61: ["KEY_A"],
        0x73: ["KEY_S"],
        0x64: ["KEY_D"],
        0x66: ["KEY_F"],
        0x67: ["KEY_G"],
        0x68: ["KEY_H"],
        0x6A: ["KEY_J"],
        0x6B: ["KEY_K"],
        0x6C: ["KEY_L"],
        0x0D: ["KEY_ENTER"],
    
      # bottom row
        0x7A: ["KEY_Z"],
        0x78: ["KEY_X"],
        0x63: ["KEY_C"],
        0x76: ["KEY_V"],
        0x62: ["KEY_B"],
        0x6E: ["KEY_N"],
        0x6D: ["KEY_M"],
        0x2C: ["KEY_COMMA"],
        0x2E: ["KEY_DOT"],
        0x20: ["KEY_SPACE"],
    
      # arrow keys
        0xB4: ["KEY_LEFT"],
        0xB5: ["KEY_UP"],
        0xB6: ["KEY_DOWN"],
        0xB7: ["KEY_RIGHT"],
    
        ... (check the above repo for the rest)
    
    }
```

`solve.py`

```
    import csv
    from ascii_codes import ascii
    import sys
    import time
    import traceback
    
    with open("../dist/i2c_keyboard.csv") as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            address = int(row[2], 16)
            data = int(row[3], 16)
            if address == 0x5F and data in ascii:
                button = ascii[data]
                #print(hex(data))
                print(*button)
```

and tada!

```
    KEY_F
    KEY_L
    KEY_A
    KEY_G
    KEY_LEFTSHIFT KEY_LEFTBRACE
    KEY_7
    KEY_1
    KEY_7
    KEY_F
    KEY_7
    KEY_5
    KEY_3
    KEY_2
    KEY_LEFTSHIFT KEY_RIGHTBRACE
    KEY_ENTER
```

flag: `flag{717f7532}`

## Sniff Two

This second part had to do with the display. which was a Pimoroni Inky pHAT, so I had the [pin layout](https://pinout.xyz/pinout/inky_phat), and the [library](https://github.com/pimoroni/inky) that can be used to display images to the screen to reverse its behavior, so that’s what I did, and luckily library code was fairly readable so here is the code flow from the image to the screen.

### Pin layout

Figuring out which pin was which was fairly simple given the pictures:

```
    CLK  -> brown  -> G6
    DIN  -> red    -> G5
    CS   -> blue   -> G7
    DC   -> orange -> G4
    RST  -> yellow -> G3
    
    BUSY -> pastel green -> G2
    CSB (CS): Slave chip selection signal, low active. When CS is low level, the chip is enabled.
    SCL (SCK/SCLK): Serial clock signal.
    D/C (DC): Data/Command control signal, writes commands at a low level; writes data/parameter at a high level.
    SDA (DIN): Serial data signal.
```

Timing sequence: CPHL=0, CPOL=0 (that is, SPI mode 0).

### Setting The Image

This [snippet](https://github.com/pimoroni/inky/blob/6162b5fbc2eba8b7a56b41eb03e4438db9bea6eb/library/inky/inky.py#L358) is responsible of setting the `buf` variable that represents the image:

```
    def set_image(self, image):
        """Copy an image to the buffer.
    
        The dimensions of `image` should match the dimensions of the display being used.
    
        :param image: Image to copy.
        :type image: :class:`PIL.Image.Image` or :class:`numpy.ndarray` or list
        """
        if self.rotation % 180 == 0:
            self.buf = numpy.array(image, dtype=numpy.uint8).reshape((self.width, self.height))
        else:
            self.buf = numpy.array(image, dtype=numpy.uint8).reshape((self.height, self.width))
```

### Splitting The Image

And this [snippet](https://github.com/pimoroni/inky/blob/6162b5fbc2eba8b7a56b41eb03e4438db9bea6eb/library/inky/inky.py#L329) splits the image (`buf` array) to `buf_a` that has represents the black part of the image, and `buf_b` that represents the red/yellow/etc.. part of the image:

```
    def show(self, busy_wait=True):
        """Show buffer on display.
    
        :param bool busy_wait: If True, wait for display update to finish before returning, default: `True`.
        """
        region = self.buf
    
        if self.v_flip:
            region = numpy.fliplr(region)
    
        if self.h_flip:
            region = numpy.flipud(region)
    
        if self.rotation:
            region = numpy.rot90(region, self.rotation // 90)
    
        buf_a = numpy.packbits(numpy.where(region == BLACK, 0, 1)).tolist()
        buf_b = numpy.packbits(numpy.where(region == RED, 1, 0)).tolist()
```

### Sending The Image

This is the [juicy part](https://github.com/pimoroni/inky/blob/6162b5fbc2eba8b7a56b41eb03e4438db9bea6eb/library/inky/inky.py#L256) where the two buffers (representing the whole image) get sent to the device:

```
    def _update(self, buf_a, buf_b, busy_wait=True):
        """Update display.
    
        :param buf_a: Black/White pixels
        :param buf_b: Yellow/Red pixels
    
        """
        self.setup()
    
        packed_height = list(struct.pack('<H', self.rows))
    
        if isinstance(packed_height[0], str):
            packed_height = map(ord, packed_height)
    
        self._send_command(0x74, 0x54)  # Set Analog Block Control
        self._send_command(0x7e, 0x3b)  # Set Digital Block Control
    
        self._send_command(0x01, packed_height + [0x00])  # Gate setting
    
        self._send_command(0x03, 0x17)  # Gate Driving Voltage
        self._send_command(0x04, [0x41, 0xAC, 0x32])  # Source Driving Voltage
    
        self._send_command(0x3a, 0x07)  # Dummy line period
        self._send_command(0x3b, 0x04)  # Gate line width
        self._send_command(0x11, 0x03)  # Data entry mode setting 0x03 = X/Y increment
    
        self._send_command(0x2c, 0x3c)  # VCOM Register, 0x3c = -1.5v?
    
        self._send_command(0x3c, 0b00000000)
        if self.border_colour == self.BLACK:
            self._send_command(0x3c, 0b00000000)  # GS Transition Define A + VSS + LUT0
        elif self.border_colour == self.RED and self.colour == 'red':
            self._send_command(0x3c, 0b01110011)  # Fix Level Define A + VSH2 + LUT3
        elif self.border_colour == self.YELLOW and self.colour == 'yellow':
            self._send_command(0x3c, 0b00110011)  # GS Transition Define A + VSH2 + LUT3
        elif self.border_colour == self.WHITE:
            self._send_command(0x3c, 0b00110001)  # GS Transition Define A + VSH2 + LUT1
    
        if self.colour == 'yellow':
            self._send_command(0x04, [0x07, 0xAC, 0x32])  # Set voltage of VSH and VSL
        if self.colour == 'red' and self.resolution == (400, 300):
            self._send_command(0x04, [0x30, 0xAC, 0x22])
    
        self._send_command(0x32, self._luts[self.lut])  # Set LUTs
    
        self._send_command(0x44, [0x00, (self.cols // 8) - 1])  # Set RAM X Start/End
        self._send_command(0x45, [0x00, 0x00] + packed_height)  # Set RAM Y Start/End
    
        # 0x24 == RAM B/W, 0x26 == RAM Red/Yellow/etc
        for data in ((0x24, buf_a), (0x26, buf_b)):
            cmd, buf = data
            self._send_command(0x4e, 0x00)  # Set RAM X Pointer Start
            self._send_command(0x4f, [0x00, 0x00])  # Set RAM Y Pointer Start
            self._send_command(cmd, buf)
    
        self._send_command(0x22, 0xC7)  # Display Update Sequence
        self._send_command(0x20)  # Trigger Display Update
        time.sleep(0.05)
    
        if busy_wait:
            self._busy_wait()
            self._send_command(0x10, 0x01)  # Enter Deep Sleep
```

So it was all about reversing this behavior and finding connections between this code and the captured signals, in fact we can distinguish when the two pictures that were written to the screen:

![image](https://github.com/user-attachments/assets/2d2eb017-328a-4f1c-aeac-43d10550d36f)

Now after comparing the signals sent with library code we can understand what its actually doing.

Like here we can see that it’s sending the height `0x00F9` \+ `0x00` (It’s little ending so the lower address is getting sent first that’s why you see `0xF9` being sent first in the capture)

![image](https://github.com/user-attachments/assets/122b7b1b-3a1b-4472-8b3d-c1834c6e8f35)

And this part of the operation is the most important, cause its sends in it the `buf_a`, `buf_b` buffers (our original image) to the device:

```
    # 0x24 == RAM B/W, 0x26 == RAM Red/Yellow/etc
    for data in ((0x24, buf_a), (0x26, buf_b)):
        cmd, buf = data
        self._send_command(0x4e, 0x00)  # Set RAM X Pointer Start
        self._send_command(0x4f, [0x00, 0x00])  # Set RAM Y Pointer Start
        self._send_command(cmd, buf)
```

Which we can actually see in the capture:

Sending `buf_a`:

![image](https://github.com/user-attachments/assets/465a9ab5-e81f-466f-a5f7-f76180b8b03f)

Sending `buf_b`:

![image](https://github.com/user-attachments/assets/d38ebe65-d150-439b-a866-8220d0f9fc0b)

So now after the image is clear (pun intended), it’s time for writing a [script](https://github.com/mwlik/inky-phat-signals-to-frames) for this.

```
    with open("./inky_spi.csv") as file:
        reader = csv.reader(file)
        header = next(reader)
        in_packet = False
        in_b_w = False
        in_y = False
        b_w = []
        y = []
        for row in reader:
            record = [int(row[2], 16), int(row[3], 16)]
            is_command = record[1] == 0x00
            is_data = not is_command
            if is_command:
                command = record[0]
                if command == 0x01:
                    in_packet = True
                elif command == 0x20:
                    in_packet = False
                    display(b_w, y)
                    b_w = []
                    y = []
                elif command == 0x24:
                    in_b_w = True
                elif command == 0x26:
                    in_y = True
                    in_b_w = False
            elif is_data:
                if in_packet:
                    data = record[0]
                    if in_b_w:
                        b_w.append(data)
                    elif in_y:
                        y.append(data)
```

This part is just for taking the `buf_a`, `buf_b` arrays which sends them to the `display` function which does the real job.

```
    def display(buf_a, buf_b):
    	BLACK = 1
    	RED = 2
    
    	color_mapping = {
    		0: (255, 255, 255),
    		1: (0, 0, 0),
    		2: (255, 0, 0)
    	}
    
    	buf_a_unpacked = np.unpackbits(np.array(buf_a, dtype=np.uint8))
    	buf_b_unpacked = np.unpackbits(np.array(buf_b, dtype=np.uint8))
    
    	width = 136
    	height = 250
    
    	buf_a = buf_a_unpacked[:height * width].reshape((height, width))
    	buf_b = buf_b_unpacked[:height * width].reshape((height, width))
    
    	buf = np.zeros((height, width), dtype=np.uint8)
    
    	for i in range(height):
    		for j in range(width):
    			if buf_a[i, j] == 0:
    				buf[i, j] = BLACK
    			elif buf_b[i, j] == 1:
    				buf[i, j] = RED
    			else:
    				buf[i, j] = 0
    
    	height, width = buf.shape
    	image_array = np.zeros((height, width, 3), dtype=np.uint8)
    	for y in range(height):
    		for x in range(width):
    			image_array[y, x] = color_mapping[buf[y,x]]
    	image = Image.fromarray(image_array, 'RGB')
    	image.show()
```

Note: The implementating, especially width/height handling is not implemented right that’s why the second image is kinda screwed.

And tada!

![image](https://github.com/user-attachments/assets/76261bc1-3914-495c-b430-b97956e930dc) ![image](https://github.com/user-attachments/assets/afd213e1-7331-49ae-96d3-d8b8144d9f64)

flag: `flag{ec9cf2b7}`

Tags: [CTFs Writeups](https://mwlik.github.io/tags#CTFs Writeups) [Hardware](https://mwlik.github.io/tags#Hardware)

Share:  [ X (Twitter) ](https://twitter.com/intent/tweet?text=CrewCTF+2024+Sniff+One%2C+Sniff+Two+Writeup&url=https%3A%2F%2Fmwlik.github.io%2F2024-08-05-crewctf-2024-sniff-challenge%2F "Share on X \(Twitter\)") [ LinkedIn ](https://www.linkedin.com/shareArticle?mini=true&url=https%3A%2F%2Fmwlik.github.io%2F2024-08-05-crewctf-2024-sniff-challenge%2F "Share on LinkedIn") [ VK ](https://vk.com/share.php?url=https%3A%2F%2Fmwlik.github.io%2F2024-08-05-crewctf-2024-sniff-challenge%2F "Share on VK")

  * [ __ Previous Post ](https://mwlik.github.io/2024-07-14-hitcon-quals-flag-reader-challenge/ "HITCON CTF 2024 Flag Reader Writeup")
  * [ Next Post __](https://mwlik.github.io/2025-01-13-why-whitebox/ "Why Whitebox?")
