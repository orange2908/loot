---
title: "oscilloscope - Nullcon Goa HackIM 2025 CTF"
category: "rev"
subcategory: "deserialization"
type: "writeup"
tags: ["rev", "engineering", "reverse", "deserialization", "oscilloscope", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Another interesting rev chal from nullcon goa."
source:
  name: "CTFtime writeup #39855"
  url: "https://ctftime.org/writeup/39855"
original_source: "https://nikzu.dev/writeups/oscilloscope/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "oscilloscope"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** oscilloscope
- **Author team:** Qu4cks
- **CTFtime tags:** engineering, reverse
- **CTFtime:** <https://ctftime.org/writeup/39855>
- **Original writeup:** <https://nikzu.dev/writeups/oscilloscope/>

---
Table of Contents

Table of Contents

Another interesting rev chal from nullcon goa.  
The premise was to analyze the values from an oscilloscope waveform into the flag.  
Reminded me of **Electronics 1** though. ![cooked](https://nikzu.dev/writeups/oscilloscope/cooked.webp)

## Chal Description

#

I tried to extract some data from an embedded device. Can you help me interpret the data on my oscilloscope?

Files: [`trace.pckl`](https://nikzu.dev/writeups/oscilloscope/trace.pckl)

## Solution

#

The given file is a pickle file which loads into three different arrays of floats.  
Each is 280000 values long.

```
    import pickle
    
    with open("trace.pckl", "rb") as f:
         time, clock, data = np.array(pickle.load(f))
    
    print(len(time))
    print(len(clock))
    print(len(data))
```

```
    280000
    280000
    280000
```

Since we know that this should be a waveform from an oscilloscope, we can plot it with matplotlib.

```
    plt.plot(clock)
    plt.plot(data)
```

This gives the following waveform.![waveforms](https://nikzu.dev/writeups/oscilloscope/waveforms_all_hu_534b4a344a67f37a.png)Zooming in, we can see that the first one (blue), behaves like a clock, and the orange one should be data.![waveforms](https://nikzu.dev/writeups/oscilloscope/show_clock_hu_65cb67c71f6ebadd.png)

The clock can be cleaned up by setting it to 3.3v if it’s above 1.0v.

```
    high = 3.3
    low = 0
    clock = np.where(clock >= 1.0, high, low)
```

![waveforms](https://nikzu.dev/writeups/oscilloscope/clock_clean_hu_d24964b526125ca6.png)

Further inspecting the waveform, we can see that we want to get the indeces where the clock goes from low to high (the positive edges).  
This can be done by looking where the cleaned up clock switches from 0 to 1:

```
    pos_edge = np.where((clock[:-1] == low) & (clock[1:] == high))[0]
```

Getting the bits from the data channel can be done by checking if its above a certain threshold at each pos edge index.

```
    bin = np.array([int(data[int(c)] > 2.8) for c in pos_edge])
```

At first this data might look like garbage, but wheen manually looking at the bits, I was able to see that a character occured every 9 bits, with the first 8 being the byte data (this is how i2c works).  
The first 37 bits have to be ignored (the initial blip of bits at the start).

```
    flag = ""
    for i in range(37, len(bin), 9):
        c = int(''.join(str(bit) for bit in bin[i:i+8]), 2)
        flag += chr(c)
        print(flag)
```

### Flag

#

Now we can get the flag. Flag: `ENO{S0_TH15_15_H0W_Y0U_D3C0D3_I2C}`

Solution script: [`oscilloscope.py`](https://nikzu.dev/writeups/oscilloscope/oscilloscope.py)

[ ](https://www.linkedin.com/shareArticle?mini=true&url=https://nikzu.dev/writeups/oscilloscope/&title=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share on LinkedIn")[ ](https://twitter.com/intent/tweet/?url=https://nikzu.dev/writeups/oscilloscope/&text=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Tweet on Twitter")[ ](https://reddit.com/submit/?url=https://nikzu.dev/writeups/oscilloscope/&resubmit=true&title=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Submit to Reddit")[ ](https://pinterest.com/pin/create/bookmarklet/?url=https://nikzu.dev/writeups/oscilloscope/&description=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Pin on Pinterest")[ ](https://www.facebook.com/sharer/sharer.php?u=https://nikzu.dev/writeups/oscilloscope/&quote=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share on Facebook")[ ](https://nikzu.dev/cdn-cgi/l/email-protection#211e434e45581c49555551521b0e0e4f484a5b540f4544570e56534855445451520e4e5242484d4d4e52424e51440e07404c511a5254434b4442551c5344570e4e5242484d4d4e52424e51440413110c0413116f544d4d424e4f0413116940424a686c041311627567041311664e4004131113111314 "Send via email")[ ](https://api.whatsapp.com/send?text=https://nikzu.dev/writeups/oscilloscope/&resubmit=true&title=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share via WhatsApp")[](https://t.me/share/url?url=https://nikzu.dev/writeups/oscilloscope/&resubmit=true&title=rev/oscilloscope%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share via Telegram")
