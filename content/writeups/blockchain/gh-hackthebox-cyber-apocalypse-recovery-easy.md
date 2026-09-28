---
title: "Recovery [Easy] - cyber apocalypse 2024"
category: "blockchain"
subcategory: "blockchain"
type: "writeup"
tags: ["blockchain", "recovery", "easy", "smart-contract", "recovery-easy", "cyber-apocalypse"]
summary: "blockchain writeup for \"Recovery [Easy]\" from cyber apocalypse - techniques: recovery, easy, smart-contract, recovery-easy, cyber-apocalypse."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20%5BEasy%5D/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "Recovery [Easy]"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** Recovery [Easy]
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20%5BEasy%5D/README.md>

---
![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png)

<img src='https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Recovery</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: perrythepwner

Challenge Author(s): perrythepwner

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- The challenge involves recovering stolen BTC funds given an Electrum seed phrase in a hacked SSH instance.

# Description

- We are The Profits. During a hacking battle our infrastructure was compromised as were the private keys to our Bitcoin wallet that we kept.
We managed to track the hacker and were able to get some SSH credentials into one of his personal cloud instances, can you try to recover my Bitcoins?
- Username: satoshi
- Password: L4mb0Pr0j3ct
- NOTE: Network is regtest, check connection info in the handler first.

# Skills Required

-  Basic research skills.

# Skills Learned

- Bitcoin wallets.
- Bitcoin regtest network.
- Wallet seed phrases.
- Electrum wallet setup & interaction.
- Sending Bitcoins.

# Enumeration

We've been given access to an SSH instance with the credentials `satoshi:L4mb0Pr0j3ct`. Let's establish a connection and investigate the contents of the machine.

![SSH access](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/ssh_access.png)

Once logged in, we'll notice a file named `electrum-wallet-seed.txt` in the home directory. Players can search for "electrum wallet seed" to find useful information:

- [Electrum Seed Version System](https://electrum.readthedocs.io/en/latest/seedphrase.html)
- [Restoring your standard wallet from seed - Bitcoin Electrum](https://bitcoinelectrum.com/restoring-your-standard-wallet-from-seed/)
- [Creating an electrum wallet](https://bitcoinelectrum.com/creating-an-electrum-wallet/)

These resources provide insights into Bitcoin wallets, how to create or load them, and details about BIP39.

# Solution

## Wallet Recovery

Now that we understand the concept of a seed and how Electrum wallets function, let's proceed with setting up the wallet client.

1. Install the Electrum wallet client.

![https://electrum.org/#download](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/electrum_download.png)

2. Begin the client in `regtest` mode as suggested in the description.
   ![new](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/electrum_newwallet.png)

2. Choose the standard wallet option, and then insert the seed found in the SSH instance.
   ![import](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/electrum_importseed.png)

3. Switch the network to the Electrum server provided in order to connect to the blockchain.
   ![server](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/electrum_server.png)

Alternatively, you can start Electrum with the correct server from the command line using the following syntax:
```bash
./electrum-4.4.6-x86_64.AppImage --regtest --oneserver -s 0.0.0.0:50001:t
```

## Sending back the bitcoin

Now it's time to initiate the actual request to retrieve our funds.

1. Connect to the Challenge Handler to obtain the address.
   ![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/challenge_handler.png)

2. Return the Bitcoin to the provided address.
   ![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/sending_btc_back.png)
     ![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/btc_sent.png)

  ## Getting the flag

We can connect to the netcat instance one final time and select the "1) Get flag" option.

  ![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/blockchain/Recovery%20[Easy]/assets/flag.png)
