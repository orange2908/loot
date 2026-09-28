---
title: "Tool - RsaCtfTool"
category: crypto
subcategory: rsa
type: tool
tags: [rsactftool, rsa, attack-all, factordb, wiener, fermat, pollard, hastad, common-modulus, publickey, pem, uncipher, private-key, crypto, automation]
summary: "Throws ~20 classic RSA attacks at a public key or a raw (n, e, c) and recovers the private key or plaintext automatically."
related: [rsa-decision-tree, crypto-triage, factordb, sagemath]
---

## What it is

RsaCtfTool automates the standard RSA attack catalogue: factordb lookup, Fermat, Pollard p-1 and rho, Williams p+1, Wiener, Boneh-Durfee, small-exponent roots, Hastad broadcast, common modulus, common factor, Mersenne primes, ROCA, partial key recovery, and more. It is the right **first** command on any RSA challenge - not because it will always work, but because when it does, it saves twenty minutes.

## Install

```sh
git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool
cd RsaCtfTool
python3 -m pip install -r requirements.txt
python3 RsaCtfTool.py --help
# some attacks need external tools
sudo apt install libgmp3-dev libmpc-dev
# optional, big speedups for factoring
sudo apt install yafu  # or build cado-nfs / msieve
```
There is no reliable distro package; run it from the git checkout.

## The invocations that matter

```sh
R="python3 RsaCtfTool.py"

# 1. the default move: try everything against a public key + ciphertext file
$R --publickey key.pub --uncipherfile cipher.bin --attack all

# 2. the same with raw numbers
$R -n <n> -e <e> --uncipher <c> --attack all

# 3. just recover the private key
$R --publickey key.pub --private

# 4. dump the parameters of a key you were given
$R --dumpkey --publickey key.pub

# 5. create a public key from n and e (many tools want a PEM)
$R --createpub -n <n> -e <e> > key.pub

# 6. common modulus: two ciphertexts, same n, different e
$R -n <n> -e <e1> --uncipher <c1> -e2 <e2> --uncipher2 <c2> --attack common_modulus
# (in practice, easier to do by hand - see ctfbrain search rsa-decision-tree)

# 7. common factor across two keys
$R --publickey "key1.pub,key2.pub" --private --attack common_factor

# 8. Hastad broadcast with several keys and ciphertexts
$R --publickey "k1.pub,k2.pub,k3.pub" --uncipherfile "c1.bin,c2.bin,c3.bin" --attack hastads

# 9. pick one attack (much faster when you already know the weakness)
$R --publickey key.pub --private --attack wiener
$R --publickey key.pub --private --attack fermat
$R --publickey key.pub --private --attack boneh_durfee
$R --publickey key.pub --private --attack pollard_p_1
$R --publickey key.pub --private --attack factordb
$R --publickey key.pub --private --attack smallq
$R --publickey key.pub --private --attack roca

# 10. list what attacks exist in your version
$R --list-attacks   # or: grep -l 'class Attack' attacks/single_key/*.py
```

Once you have a private key:
```sh
openssl rsa -in priv.pem -text -noout                    # inspect it
openssl rsautl -decrypt -inkey priv.pem -in cipher.bin   # decrypt (PKCS#1 padded)
openssl pkeyutl -decrypt -inkey priv.pem -in c.bin -pkeyopt rsa_padding_mode:none  # textbook
```
Inspect a given public key without the tool:
```sh
openssl rsa -pubin -in key.pub -text -noout
openssl asn1parse -in key.pub
python3 -c "
from Crypto.PublicKey import RSA
k = RSA.import_key(open('key.pub','rb').read())
print('n =', k.n); print('e =', k.e); print('bits =', k.n.bit_length())"
```

## Gotchas

- **`--attack all` can hang for a long time** on attacks that do not apply (Fermat and Pollard have no natural stopping point). Use `--timeout 60` or run specific attacks once you have a hypothesis.
- It queries factordb over the network by default. Offline, that attack silently fails - which is often the one that would have worked. Check your connectivity.
- `--uncipher` expects a decimal integer; `--uncipherfile` expects raw bytes. Mixing them up produces nonsense.
- Output can be padded or offset. If the decryption looks like garbage with readable tail bytes, strip leading nulls / PKCS#1 padding yourself.
- Many "n, e, c" challenges are not in a PEM. Use `--createpub` to build one, or just pass `-n`/`-e` directly.
- The tool does not implement every attack, and its Coppersmith support is limited. Partial-information attacks are usually better done in Sage.
- Version churn is high; flags change between commits. `--help` on your checkout is authoritative, not a blog post.
- It will happily report "private key found" for a trivially small `n` that you could have factored in one line - always check `n.bit_length()` first.
- Python dependency conflicts are common; use a venv.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You know which attack applies | implement it yourself - see `ctfbrain search rsa-decision-tree` for runnable code for every case |
| Partial knowledge of p, d, or m | SageMath `small_roots` (`ctfbrain search sagemath`) |
| Just need to factor n | `factordb`, `yafu`, `cado-nfs`, `msieve`, `ecm` |
| An interactive oracle | none of this applies; see `ctfbrain search crypto-triage` section 2 |
| Non-RSA public key crypto | Sage; RsaCtfTool is RSA-only |
| Multi-prime or unusual moduli | factor with yafu, then compute `phi = prod(p_i - 1)` yourself |
| You want to learn | do it by hand once; the tool teaches you nothing |
