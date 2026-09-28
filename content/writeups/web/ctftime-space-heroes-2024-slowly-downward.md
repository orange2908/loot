---
title: "Slowly Downward - Space Heroes 2024"
category: "web"
type: "writeup"
tags: ["web", "slowly", "downward", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "We've found what appears to be a schizophrenic alien's personal blog."
source:
  name: "CTFtime writeup #39062"
  url: "https://ctftime.org/writeup/39062"
original_source: "https://github.com/Aryt3/writeups/tree/main/jeopardy_ctfs/2024/space_heroes_ctf_2024/slowly_downward"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "Slowly Downward"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** Slowly Downward
- **Author team:** Katipwnan
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39062>
- **Original writeup:** <https://github.com/Aryt3/writeups/tree/main/jeopardy_ctfs/2024/space_heroes_ctf_2024/slowly_downward>

---
# Slowly Downward

## Description  
```  
We've found what appears to be a schizophrenic alien's personal blog. Poke around and see if you can find anything interesting.

<http://slow.martiansonly.net>  
```

## Writeup

Starting off, we can look at the `html` of the website.   
  
```html

<html lang="en">  
<head>  
<meta charset="UTF-8">  
<meta name="viewport" content="width=device-width, initial-scale=1.0">  
<title>N O T I T L E</title>  
<link rel="stylesheet" href="/static/style.css">  
</head>  
<body>  
<div class="container">  
<h2>Small Thoughts:</h1>  
<nav class="thoughts">  


  

  * [A MAN WHO THINKS HE IS A PIG](https://ctftime.org/A_MAN_WHO_THINKS_HE_IS_A_PIG.html)
  

  * [A QUIET AFTERNOON](https://ctftime.org/A_QUIET_AFTERNOON.html)
  

  * [A WET NIGHT](https://ctftime.org/A_WET_NIGHT.html)
  

  * [ACTING WITH CERTAINTY](https://ctftime.org/ACTING_WITH_CERTAINTY.html)
  

  * [AIRBORNE](https://ctftime.org/AIRBORNE.html)
  

  * [ALIENS AGAIN](https://ctftime.org/ALIENS_AGAIN.html)
  

  * [AN ACCIDENT INVOLVING TRELLIS](https://ctftime.org/AN_ACCIDENT_INVOLVING_TRELLIS.html)
  

  * [ART](https://ctftime.org/ART.html)
  

  * [BIG BIRD](https://ctftime.org/BIG_BIRD.html)
  

  * [BOND JAMES BOND](https://ctftime.org/BOND_JAMES_BOND.html)
  

  * [DOWN IN THE TUBE STATION](https://ctftime.org/DOWN_IN_THE_TUBE_STATION.html)
  

  * [DRACULA](https://ctftime.org/DRACULA.html)
  

  * [HAPPY STORY](https://ctftime.org/HAPPY_STORY.html)
  

  * [HAUNTED](https://ctftime.org/HAUNTED.html)
  

  * [LOVE STORY](https://ctftime.org/LOVE_STORY.html)
  

  * [MACHINE](https://ctftime.org/MACHINE.html)
  

  * [MUSEUM](https://ctftime.org/MUSEUM.html)
  

  * [NEARLY GOT](https://ctftime.org/NEARLY_GOT.html)
  

  * [ON SUNDAYS RINGROAD SUPERMARKET](https://ctftime.org/ON_SUNDAYS_RINGROAD_SUPERMARKET.html)
  

  * [SHEARS](https://ctftime.org/SHEARS.html)
  

  * [SHOPPING IN THE EARLY MORNING](https://ctftime.org/SHOPPING_IN_THE_EARLY_MORNING.html)
  

  * [SPACE](https://ctftime.org/SPACE.html)
  

  * [STATUE](https://ctftime.org/STATUE.html)
  

  * [ADMIN](https://ctftime.org/ADMIN.html)
  

  
</nav>  
<h2>There are some more, if you like.</h1>  
<nav>  


  

  * [BACK TO THE CONTENTS PAGE](https://ctftime.org/)
  

  
</nav>  
</div>

<div style="display: none;">  
<div id="A_MAN_WHO_THINKS_HE_IS_A_PIG">ANTIBIOTICS</div>  
<div id="A_QUIET_AFTERNOON">NO SURPRISES</div>  
<div id="A_WET_NIGHT">COLD</div>  
<div id="ACTING_WITH_CERTAINTY">IF WE GET THE CHANCE</div>  
<div id="AIRBORNE">PLANE</div>  
<div id="ALIENS_AGAIN">THEY'RE TRYING TO LOG IN</div>  
<div id="AN_ACCIDENT_INVOLVING_TRELLIS">PLANET</div>  
<div id="ART">HILLS</div>  
<div id="BIG_BIRD">MEMORY</div>  
<div id="BOND_JAMES_BOND">SOMETIMES I FORGET CURL. I NEVER TRUSTED DANIEL STENBERG.</div>  
<div id="DOWN_IN_THE_TUBE_STATION">TRAIN</div>  
<div id="DRACULA">FLOW</div>  
<div id="HAPPY_STORY">MEMORY</div>  
<div id="HAUNTED">ABYSS</div>  
<div id="LOVE_STORY">MEMORY</div>  
<div id="MACHINE">FUTURE</div>  
<div id="MUSEUM">SPIRAL</div>  
<div id="NEARLY_GOT">FINGERS</div>  
<div id="ON_SUNDAYS_RINGROAD_SUPERMARKET">TREES</div>  
<div id="SHEARS">THIS IS IT</div>  
<div id="SHOPPING_IN_THE_EARLY_MORNING">WARM</div>  
<div id="SPACE">HEROES</div>  
<div id="STATUE">EYES</div>  
<div id="ADMIN">username@text/credentials/user.txt password@text/credentials/pass.txt</div>  
</div>  
  
<script>  
document.querySelectorAll('.thoughts a').forEach(link => {  
link.addEventListener('click', function(event) {  
event.preventDefault();  
const targetId = this.getAttribute('href').replace('.html', '');  
const content = document.getElementById(targetId).innerHTML;  
alert(content);  
});  
});  
</script>  
</body>  
</html>  
```

Looking through the webpage we can find a `username` and `password` file.   
  
  
`username` file location:   
  
```  
<http://srv3.martiansonly.net:4444/text/credentials/user.txt>  
```  
Content: `4dm1n`.   
  


`password` file location:   
  
```  
<http://srv3.martiansonly.net:4444/text/credentials/pass.txt>  
```  
Content: `p4ssw0rd1sb0dy5n4tch3r5`.   
  


Using these credentials we can login on the webpage `<http://srv3.martiansonly.net:4444/abit.html>`.   
  
Trying to read the flag from `<http://srv3.martiansonly.net:4444/text/secret/flag.txt>` still returns insufficient permissions.   
  
We can switch to python to send a proper request.   
  
```py  
import requests

baseURL = '<http://srv3.martiansonly.net:4444/'>

sessionToken = '1e6ec9f9c268cd2d7bbc197e3bcc8a5c' # Extracted after manual login

headers = {  
'Authorization': f'Bearer {sessionToken}',  
'Secret': 'mynameisstanley', # Extracted after manual login  
}

res = requests.get(f'{baseURL}text/secret/flag.txt', headers=headers) # URL extracted from sourcecode of /abit.html webpage

print(res.text)  
```

Executing this returns the flag which concludes this writeup.   
  
```sh  
$ python3 .\[req.py](http://req.py)  
shctf{sh0w_m3_th3_w0r1d_a5_id_lov3_t0_s33_1t}  
```
