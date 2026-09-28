---
title: "Mafia at the end 1 - PwnMe CTF Quals 2025"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "web3", "solidity", "pcap", "wireshark", "foundry", "base64", "smart-contract", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "\\- Read the PCAP file with wireshark and notice the IRC protocol"
source:
  name: "CTFtime writeup #40061"
  url: "https://ctftime.org/writeup/40061"
original_source: "https://wepfen.github.io/writeups/mafia-at-the-end-of-the-block-full/"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "Mafia at the end 1"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** Mafia at the end 1
- **Author team:** the rizzlers
- **CTFtime tags:** web3, solidity, pcap
- **CTFtime:** <https://ctftime.org/writeup/40061>
- **Original writeup:** <https://wepfen.github.io/writeups/mafia-at-the-end-of-the-block-full/>

---
> Difficulty : Easy

> [Source files](<https://github.com/Phreaks-2600/pwnme-2025-quals/tree/main/misc/mafia_at_the_end_of_the_block_1>)

> Description : You're an agent, your unit recently intercepted a mob discussion about an event that's going to take place on August 8, 2024. You already know the location, though. A password for the event was mentioned. Your job is to find it and return it so that an agent can go to the scene and collect evidence.

## TL;DR

\- Read the PCAP file with wireshark and notice the IRC protocol  
\- Find a link in the conversation and also contract addresses  
\- From now you can search for the contract on etherscan or open the link, get the abi and interact with the smart contract to get the flag.

## Introduction

So for the first part of the challenge, we have a network capture in attachment and that's all.  
We are supposed to retrieve essential informations as an URL and a smart contract address.  
Then retrieve the "password" on the smart contract.

## Solving

### Retrieve informations from the PCAP

First, I ended up messing up my network capture and it ended up having to much packet than it was supposed to be.  
Anyway, looking in **statistics -> protocol hierarchy**, we find that there is one interesting protocol which is **Internet Relay Chat** (or IRC)

we can filter with "irc" and read the conversation by **right clicking -> follow -> TCP**

![IRC conversation](<https://wepfen.github.io/images/writeups/mafia/irc-flow.png>)

We can get two informations from this :

\- a link : <https://shorturl.at/2O8nI>  
\- an address : 0xCAB0b02864288a9cFbbd3d004570FEdE2faad8F8

If we continue to read the other IRC conversation, we get another contract which is wrong : 

\- `0x69E881DB5160cc5543b544603b04908cac649D38`   
\- And a rick roll in base64 : `aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1Fa2ZEbXpwcndydw==` -> <https://www.youtube.com/watch?v=EkfDmzprwrw>.

> For this last contract address I just forgot to remove it so my bad.

### Read the flag on Sepolia (was not the intended solution but game is game)

We can search for the contract address on [etherscan](<https://sepolia.etherscan.io/>) 

Inspecting the [first transaction](<https://sepolia.etherscan.io/tx/0x2a1133ebd2476d670b2b1668f7db32774e02533b8ca9f2e1a98a9a67b9dd9165>), we can directly read the input data as UTF-8 and get the flag. `PWNME{1ls_0nt_t0vt_Sh4ke_dz8a4q6}`

> The flag is readable here because, while setting up the contract for the challenge, we sent a transaction to the function `set_secret(string)` and put the flag as argument. So it's readable in plaintext on the blockchain.

### Open the conversation and get the ABI of the contract and the flag

From the shortlink [<https://shorturl.at/2O8nI>](<https://shorturl.at/2O8nI>), we get redirected to <https://www.swisstransfer.com/d/a4947af6-05c6-4011-958e-fd6b604587d1>.  
It's an archived telegram conversation.

> We chose to archive it and not make it a live telegram group chat for the players who don't want to join a telegram or create an account

We can open the html page from the archive and there is another conversation.

They are talking about the "ABI" and "interacting with the smart contract". Also here'is the abi :

```json  
[  
{  
"inputs": [  
{  
"internalType": "string",  
"name": "_secret",  
"type": "string"  
}  
],  
"name": "set_secret",  
"outputs": [],  
"stateMutability": "nonpayable",  
"type": "function"  
},  
{  
"inputs": [],  
"stateMutability": "nonpayable",  
"type": "constructor"  
},  
{  
"inputs": [],  
"name": "ask_secret",  
"outputs": [  
{  
"internalType": "string",  
"name": "",  
"type": "string"  
}  
],  
"stateMutability": "view",  
"type": "function"  
}  
]  
```

> The ABI(Application Binary Interface) is the representation of a contract in JSON. It defines the function, variables, visibility, parameter and all public informations we need to know how to interact with a contract. It gives a nicer representation of a smart contract and makes it easier to use with programming languages. More : <https://docs.soliditylang.org/en/latest/abi-spec.html>

On the ABI we learn about `ask_secret` function so we understand we just have to call it using cast from [foundry](<https://book.getfoundry.sh/>) : 

`cast call 0xCAB0b02864288a9cFbbd3d004570FEdE2faad8F8 -r <https://gateway.tenderly.co/public/sepolia> "ask_secret()(string)"`

`"PWNME{1ls_0nt_t0vt_Sh4ke_dz8a4q6}"`
