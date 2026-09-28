---
title: "1mag1n3-dr4g0nfly-v2 - Midnight Sun CTF 2024 Quals"
category: "crypto"
subcategory: "stack"
type: "writeup"
tags: ["adc", "crypto", "wifi", "off-by-one", "side-channel", "proof-of-work", "quadratic-residue", "wordlists", "stack", "midnight-sun-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "Over the weekend a ctf team I help with, HackingForSoju, hosted the Midnight Sun CTF Qualifiers."
source:
  name: "CTFtime writeup #39105"
  url: "https://ctftime.org/writeup/39105"
original_source: "https://www.supernetworks.org/pages/blog/midnightsun-qualifiers-2024-dragonfly"
ctf:
  name: "Midnight Sun CTF 2024 Quals"
  year: 2024
  challenge: "1mag1n3-dr4g0nfly-v2"
---

## Metadata

- **CTF:** Midnight Sun CTF 2024 Quals
- **Task:** 1mag1n3-dr4g0nfly-v2
- **Author team:** HackingForSoju
- **CTFtime tags:** adc, crypto, wifi
- **CTFtime:** <https://ctftime.org/writeup/39105>
- **Original writeup:** <https://www.supernetworks.org/pages/blog/midnightsun-qualifiers-2024-dragonfly>

---
## Midnight Sun Qualifiers 2024​

Over the weekend a ctf team I help with, [HackingForSoju](https://hackingforsoju.team/), hosted the Midnight Sun CTF Qualifiers. The finals will take place in [Stockholm, Sweden on June 14-16](https://conf.midnightsunctf.com/).

I put together a [challenge](https://gist.github.com/lts-rad/a557f5eb2d4456bbe209d524bdfbfd23) around WPA3's Password Authenticated Key Exchange: [Dragonfly](https://datatracker.ietf.org/doc/html/rfc7664)

WPA3 has quite a few notes during our our wifi training where we discuss the background to the protocol, because it was so very worrisome from the start.

![trouble](https://www.supernetworks.org/pages/assets/images/wpa3trouble-d0ed718a7ac2fb3aa54ae6b7f8c6253c.png)

## A Troubled PAKE​

In 2013, when Dan Harkins first proposed Dragonfly many people pointed out that it was inferior to existing PAKEs. Arguably it did not steer clear of existing patents, its performance was quite bad, and very objectively it suffered terribly from sidechannels. It does not take great skill to spot them.

There's an IETF thread thread sums it up [here](https://mailarchive.ietf.org/arch/msg/tls/A_SfHI4BsdAi4miklBs3TvUbu-Y/). Trevor Perrin, who is behind the Double Ratchet in Signal designed with Moxie Marlinspike, sums up what cryptographers saw.

In response, Dan Harkins goes on the offensive with personal attacks, saying several things of this nature:

```
    >  
    > It makes little sense to use a 1024-bit FFC group in any circumstances  
    > because (pardon me, Kevin) - fuck the NSA.  
      
      That certainly is a fashionable pose to strike these days!  
      
      But I brought up binding a 1024-bit FFC to a password because that's  
    what an RFC with your name on it does. So it makes sense to replace  
    "the NSA" in your sentence with "Trevor Perrin".  
      
    -- Dan Harkins  
```

When the designer of a security algorithm finds it acceptable to behave this way, and the decision makers rubber stamp their actions, we should probably take a step back as a society and ask if irrational people should be the ones solving and creating the math problems that our security relies on.

So when the WiFi consortium used Dragonfly for WPA3 in 2018, many people were actually surprised, since they assumed Dragonfly would never make its way into widespread usage.

## Dragonblood​

As WPA3 entered the ecosystem, security experts started looking. In 2019 the world's leading wifi security expert, Mathy Vanhoef, with Eyal Ronen, demolished Dragonfly [https://wpa3.mathyvanhoef.com](https://wpa3.mathyvanhoef.com/). Many of the attacks were the same as initially outlined by Trevor Perrin as well as many other cryptographers in 2013.

The team also invented some novel mechanisms to attack Brainpool curves in particular. They proved that the hardening attempts with computing random values would provide statistical anomalies detectable by calculating timing variance.

What's even worse, under EAP-PWD (dragonfly with enterprise wifi), they found that implementaitons also accepted invalid curves, bypassing the password altogether.

Hardening was added to eliminate the remaining sidechannels.

## The CTF Challenge​

The qualifier's challenge celebrates these timing failures. Players had to remotely exploit a python implementation of Dragonfly that had the initial hardening only (always running 40 rounds).

The key insight is that the KDF for dragonfly is malleable based on the client's MAC address. Providing different MAC addresses creates unique timing signatures for a given AP MAC address and Password Shared Key.

The timing signature can then be compared offline against a password list to find the real password. With a vulnerable implementation this timing sidechannel is actually a lot more effective to exploit than cracking WPA2 keys which are protected with PBKDF2.

The easiest timing differences to exploit are that lines [2] and [3] only happen sometimes.

```
    def initiate(self, other_mac, k=40):  
        """  
        See algorithm in https://tools.ietf.org/html/rfc7664  
        in section 3.2.1  
        """  
        self.other_mac = other_mac  
        found = 0  
        num_valid_points = 0  
        counter = 1  
        n = self.p.bit_length()  
      
        # Find x  
        while counter <= k:  
            base = self.compute_hashed_password(counter)  
            temp = self.key_derivation_function(n, base, b'Dragonfly Hunting And Pecking')  
            if temp >= self.p:  
                counter = counter + 1 [1]  
                continue  
            seed = temp  
            val = self.curve.secure_curve_equation(seed) [2]  
            if self.curve.secure_is_quadratic_residue(val): [3]  
                if num_valid_points < 5:  
                    x = seed  
                    save = base  
                    found = 1  
                    num_valid_points += 1  
                    logger.debug('Got point after {} iterations'.format(counter))  
      
            counter = counter + 1  
      
        if found == 0:  
            logger.error('No valid point found after {} iterations'.format(k))  
            return False  
        elif found == 1:  
            # https://crypto.stackexchange.com/questions/6777/how-to-calculate-y-value-from-yy-mod-prime-efficiently  
            # https://rosettacode.org/wiki/Tonelli-Shanks_algorithm  
            y = tonelli_shanks(self.curve.curve_equation(x), self.p)  
      
            PE = Point(x, y)  
      
            # check valid point  
            assert self.curve.curve_equation(x) == pow(y, 2, self.p)  
      
            self.PE = PE  
            assert self.curve.valid(self.PE)  
            return True  
```

To expand the timing window, so that players from around the world can exploit this remotely over TCP, many more multiplications were added through a "masking" operation where random values are computed alongside the real one at random, raising their cost to hundreds of milliseconds.

```
    def secure_curve_equation(self, x):  
        """  
        Do not leak hamming weights to power analysis  
        """  
        idx = secrets.randbelow(self.dN)  
        defense = self.defense_masks + []  
        defense[idx] = x  
        for i in range(self.dN):  
            tmp = defense[idx]  
            defense[i] = self.curve_equation(defense[idx])  
        return defense[idx]  
      
      
    def secure_is_quadratic_residue(self, x):  
        """  
        Do not leak hamming weights to power analysis  
        """  
        idx = secrets.randbelow(self.dN)  
        defense = self.defense_masks + []  
        defense[idx] = x  
        for i in range(self.dN):  
            defense[i] = self.is_quadratic_residue(defense[i])  
        return defense[idx]  
```

In practice this is good enough for several teams to attack the service simultaneously.

To effectively precompute passwords, an attacker can create an offline dictionary that only hashes and skips the large number math.

```
    def initiate(self, other_mac, k=40):  
        self.other_mac = other_mac  
        counter = 1  
        counter2 = 1  
        n = self.p.bit_length()  
      
        # Find x  
        while counter <= k:  
            base = self.compute_hashed_password(counter)  
            temp = self.key_derivation_function(n, base, b'Dragonfly Hunting And Pecking')  
            if temp >= self.p:  
                counter = counter + 1  
                continue  
            counter2 += 1  
            counter = counter + 1  
        return counter2  
```

The provided challenge also had a terrible way to convert a binary number which really slowed things down, and also had an off by one error probably.

```
    # Convert returned_bits to the non-negative integer c (see Appendix C.2.1).  
    C = 0  
    for i in range(n):  
        if int(binary_repr[i]) == 1:  
            C += pow(2, n-i)  
```

versus

```
    X = int(binary_repr, 2)<<1  
```

My solution normalized the remote timings to compare them with the offline compute.

```
    def normalize_array(arr):  
        """Normalize an array to be between 0 and 1."""  
        return (arr - arr.min()) / (arr.max() - arr.min())  
      
    def calc_mse(psk, timings, guess_timings):  
        y_actual = normalize_array(np.array(timings))  
        y_predicted = normalize_array(np.array(guess_timings))  
        mse = np.mean((y_actual - y_predicted) ** 2)  
        return mse  
      
    def solve_psk_fast(ap_mac, my_macs, timings):  
        computed = open("compute.txt","rb").readlines()  
        psk = None  
        best_mse = 100  
        for line in computed:  
            p, tmp = line.split(b"|")  
            p = p.strip().decode()  
            guess_timings = json.loads(tmp.strip())  
            mse = calc_mse(p, timings, guess_timings)  
            if mse < best_mse:  
                print("new best",mse,p)  
                best_mse = mse  
                psk = p  
        print(psk)  
        return psk  
```

During the CTF the services were overwhelmed by naive solutions, so we ended up scaling it up, but it was a little bit frustrating for some teams at times. In the future we'll have to put remote timing attempts behind a queue and/or proof of work.

To make the challenge harder, teams were also given a second variant with a larger keyspace. Instead of 60k wordlist, they were asked to attack a random 36-alphabet 5 character password. 7 teams solved it. Hats off to the great work, since you understood something Dan Harkins pretended not to when it was explained to him by so many cryptographers.

## Links​

If you'd like to learn more about these attacks, the [Dragonblood](https://papers.mathyvanhoef.com/dragonblood.pdf) paper is the one you'll want.

The up to date constant time implementation of the password element deriviation in hostapd is located here: <https://w1.fi/cgit/hostap/tree/src/common/sae.c#n283>.
