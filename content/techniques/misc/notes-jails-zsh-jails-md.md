---
title: "Zsh Jails (Jails)"
category: "misc"
type: "technique"
tags: ["my-notes", "personal", "zsh", "jails", "misc"]
summary: "https://ctf.krauq.com/dicectf-2024"
source:
  name: "Personal notes"
origin_path: "Jails/zsh jails.md"
---

### Reference: DiceCTF 2023 `misc/zshfuck`
```bash
#!/bin/zsh
print -n -P "%F{green}Specify your charset: %f"
read -r charset
# get uniq characters in charset
charset=("${(us..)charset}")
banned=('*' '?' '`')

if | ${#charset:|banned} -ne ${#charset} ; then
    print -P "\n%F{red}That's too easy. Sorry.%f\n"
    exit 1
fi
print -P "\n%F{green}OK! Got $charset.%f"
charset+=($'\n')

# start jail via coproc
coproc zsh -s
exec 3>&p 4<&p

# read chars from fd 4 (jail stdout), print to stdout
while IFS= read -u4 -r -k1 char; do
    print -u1 -n -- "$char"
done &
# read chars from stdin, send to jail stdin if valid
while IFS= read -u0 -r -k1 char; do
    if charset} -eq 0 ; then
        print -P "\n%F{red}Nope.%f\n"
        exit 1
    fi
    # send to fd 3 (jail stdin)
    print -u3 -n -- "$char"
done
```
#### Solution 1:
```bash
[^^][^^][^^]/[^^][^^][^^][^^]/[^^][^^][^^][^^][^^][^^][^^][^^][^^]/[^^][^^][^^][^^]/[^^][^^][^^][^^][^^][^^][^^]
```
#### Solution 2:
```bash
[--~][--~][--~]/[--~][--~][--~][--~]/[--~][--~][--~][--~][--~][--~][--~][--~][--~]/[--~][--~][--~][--~]/[--~][--~][--~][--~][--~][--~][--~]
```
#### Solution 3:
```bash
[!][!][!][!][!][!]/[!][!][!][!][!][!][!][!]/[!][!][!][!][!][!][!][!][!][!][!][!][!][!][!][!][!][!]/[!][!][!][!][!][!][!][!]/[!][!][!][!][!][!][!][!][!][!][!][!][!]
```

#### Reference:
https://ctf.krauq.com/dicectf-2024

---

*From your own notes: `Jails/zsh jails.md`*
