---
title: "Launchpad 1000 - Grey Cat The Flag 2025"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "launchpad", "smart-contract", "grey-cat-the-flag", "grey-cat-the-flag-2025", "2025", "ctf-writeup"]
summary: "Jun 08, 2025  5947 words 28 minutes"
source:
  name: "CTFtime writeup #40334"
  url: "https://ctftime.org/writeup/40334"
original_source: "https://chovid99.github.io/posts/greyctf-2025/"
ctf:
  name: "Grey Cat The Flag 2025"
  year: 2025
  challenge: "Launchpad 1000"
---

## Metadata

- **CTF:** Grey Cat The Flag 2025
- **Task:** Launchpad 1000
- **Author team:** Cylabus
- **CTFtime:** <https://ctftime.org/writeup/40334>
- **Original writeup:** <https://chovid99.github.io/posts/greyctf-2025/>

---
# GreyCTF 2025

__ Jun 08, 2025  __5947 words __28 minutes

Contents __

[ ![https://i.imgur.com/hNiSqKu.png](https://chovid99.github.io/svg/loading.min.svg) ](https://i.imgur.com/hNiSqKu.png "https://i.imgur.com/hNiSqKu.png")GreyCTF 2025

Hi everyone! It’s been quite a while since my last blog post. Time has flown by, and life has kept me busy, leaving little room for CTFs. Looking back, you can probably notice how the frequency of my writeups has declined since I was actively participating in 2022.

I participated solo in GreyCTF 2025 as `Cylabus`, joining just briefly before the CTF ended, mainly because I missed those weekends of intense CTF grinding. While skimming through the pwn and blockchain challenges, the `launchpad` challenge particularly caught my eye since it involved Uniswap and felt quite close to what a real-life bug looks like. Despite my limited free time on Sunday, I decided to work on this challenge as it seemed like a good exercise for me.

Fortunately, I managed to solve it before the CTF ended. Given that it was an interesting challenge, combined with my nostalgia for writing writeups (remember when I used to be a writeup machine? 😛) and, of course, the prize 😄, I decided to write my first writeup of 2025 🙂.

# Blockchain

## Launchpad

__Description __

Since token launchpads are the new trend nowadays, we decided to write our own! Will grey.fun be the next billion dollar protocol?

nc challs2.nusgreyhats.org 33501

P.S. You can find the challenge files at this [link](https://github.com/NUSGreyhats/greyctf25-challs-public/tree/main/blockchain/launchpad)

### Initial Analysis

In this challenge, we were given a zip file containing the source code. There are three main files: `Setup.sol`, `Token.sol`, and `Factory.sol`. Let’s examine each source file to understand what the challenge does and what we need to do to solve it.

**Token.sol**

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
```

| 

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.20;
    
    import {ERC20} from "./lib/solmate/ERC20.sol";
    
    contract Token is ERC20 {
        error NotFactory();
    
        uint256 public constant INITIAL_AMOUNT = 1000_000e18;
    
        address public immutable factory;
    
        constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol, 18) {
            factory = msg.sender;
    
            _mint(factory, INITIAL_AMOUNT);
        }
    
        function burn(uint256 amount) external {
            if (msg.sender != factory) revert NotFactory();
    
            _burn(msg.sender, amount);
        }
    }
```  
  
---|---  
  
This is a simple ERC20 Token that mints `1_000_000 ether` to the `factory` (the one who creates it) and allows the `factory` to burn any amount it wants. Let’s check the next contract.

**Factory.sol**

```
      1
      2
      3
      4
      5
      6
      7
      8
      9
     10
     11
     12
     13
     14
     15
     16
     17
     18
     19
     20
     21
     22
     23
     24
     25
     26
     27
     28
     29
     30
     31
     32
     33
     34
     35
     36
     37
     38
     39
     40
     41
     42
     43
     44
     45
     46
     47
     48
     49
     50
     51
     52
     53
     54
     55
     56
     57
     58
     59
     60
     61
     62
     63
     64
     65
     66
     67
     68
     69
     70
     71
     72
     73
     74
     75
     76
     77
     78
     79
     80
     81
     82
     83
     84
     85
     86
     87
     88
     89
     90
     91
     92
     93
     94
     95
     96
     97
     98
     99
    100
    101
    102
    103
    104
    105
    106
    107
    108
    109
    110
    111
    112
    113
    114
    115
    116
    117
    118
    119
    120
    121
    122
    123
    124
    125
    126
    127
    128
    129
    130
    131
    132
    133
    134
    135
    136
    137
    138
    139
    140
    141
    142
    143
    144
    145
    146
    147
    148
    149
    150
    151
    152
    153
    154
    155
    156
    157
    158
    159
    160
    161
    162
    163
    164
    165
    166
    167
    168
    169
    170
    171
    172
    173
    174
    175
    176
    177
    178
    179
    180
    181
    182
    183
    184
    185
    186
    187
    188
    189
    190
    191
    192
    193
    194
    195
    196
    197
    198
    199
    200
    201
    202
    203
    204
    205
    206
    207
    208
    209
    210
    211
    212
    213
    214
    215
    216
    217
    218
    219
    220
    221
```

| 

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.20;
    
    import {Owned} from "./lib/solmate/Owned.sol";
    import {FixedPointMathLib} from "./lib/solmate/FixedPointMathLib.sol";
    import {IUniswapV2Factory} from "./lib/v2-core/interfaces/IUniswapV2Factory.sol";
    import {IUniswapV2Pair} from "./lib/v2-core/interfaces/IUniswapV2Pair.sol";
    import {GREY} from "./lib/GREY.sol";
    import {Token} from "./Token.sol";
    
    contract Factory is Owned {
        using FixedPointMathLib for uint256;
    
        error MinimumLiquidityTooSmall();
        error TargetGREYRaisedTooLarge();
        error TargetGREYRaisedReached();
        error TargetGREYRaisedNotReached();
        error InsufficientAmountIn();
        error InsufficientAmountOut();
        error InsufficientLiquidity();
        error InsufficientGREYLiquidity();
        error InvalidToken();
    
        event TokenCreated(address indexed token, address indexed creator);
        event TokenBought(address indexed user, address indexed token, uint256 indexed ethAmount, uint256 tokenAmount);
        event TokenSold(address indexed user, address indexed token, uint256 indexed ethAmount, uint256 tokenAmount);
        event TokenLaunched(address indexed token, address indexed uniswapV2Pair);
    
        struct Pair {
            uint256 virtualLiquidity;
            uint256 reserveGREY;
            uint256 reserveToken;
        }
    
        uint256 public constant MINIMUM_VIRTUAL_LIQUIDITY = 0.01 ether;
    
        GREY public immutable grey;
    
        IUniswapV2Factory public immutable uniswapV2Factory;
    
        // Amount of "fake" GREY liquidity each pair starts with
        uint256 public virtualLiquidity;
    
        // Amount of GREY to be raised for bonding to end
        uint256 public targetGREYRaised;
    
        // Reserves and additional info for each token
        mapping(address => Pair) public pairs;
    
        // ======================================== CONSTRUCTOR ========================================
    
        constructor(address _grey, address _uniswapV2Factory, uint256 _virtualLiquidity, uint256 _targetGREYRaised)
            Owned(msg.sender)
        {
            if (_virtualLiquidity < MINIMUM_VIRTUAL_LIQUIDITY) {
                revert MinimumLiquidityTooSmall();
            }
    
            grey = GREY(_grey);
            uniswapV2Factory = IUniswapV2Factory(_uniswapV2Factory);
    
            virtualLiquidity = _virtualLiquidity;
            targetGREYRaised = _targetGREYRaised;
        }
    
        // ======================================== ADMIN FUNCTIONS ========================================
    
        function setVirtualLiquidity(uint256 _virtualLiquidity) external onlyOwner {
            if (_virtualLiquidity < MINIMUM_VIRTUAL_LIQUIDITY) {
                revert MinimumLiquidityTooSmall();
            }
    
            virtualLiquidity = _virtualLiquidity;
        }
    
        function setTargetGREYRaised(uint256 _targetGREYRaised) external onlyOwner {
            targetGREYRaised = _targetGREYRaised;
        }
    
        // ======================================== USER FUNCTIONS ========================================
    
        function createToken(string memory name, string memory symbol, bytes32 salt, uint256 amountIn)
            external
            returns (address tokenAddress, uint256 amountOut)
        {
            Token token = new Token{salt: salt}(name, symbol);
            tokenAddress = address(token);
    
            pairs[tokenAddress] = Pair({
                virtualLiquidity: virtualLiquidity,
                reserveGREY: virtualLiquidity,
                reserveToken: token.INITIAL_AMOUNT()
            });
    
            // minAmountOut not needed here as token was just created
            if (amountIn != 0) amountOut = _buyTokens(tokenAddress, amountIn, 0);
    
            emit TokenCreated(tokenAddress, msg.sender);
        }
    
        function buyTokens(address token, uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
            Pair memory pair = pairs[token];
            if (pair.virtualLiquidity == 0) revert InvalidToken();
    
            uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
            if (actualLiquidity >= targetGREYRaised) {
                revert TargetGREYRaisedReached();
            }
    
            amountOut = _buyTokens(token, amountIn, minAmountOut);
        }
    
        function sellTokens(address token, uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
            Pair storage pair = pairs[token];
            if (pair.virtualLiquidity == 0) revert InvalidToken();
    
            uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
            if (actualLiquidity >= targetGREYRaised) {
                revert TargetGREYRaisedReached();
            }
    
            amountOut = _getAmountOut(amountIn, pair.reserveToken, pair.reserveGREY);
    
            // In theory, this check should never fail
            if (amountOut > actualLiquidity) revert InsufficientGREYLiquidity();
    
            pair.reserveToken += amountIn;
            pair.reserveGREY -= amountOut;
    
            if (amountOut < minAmountOut) revert InsufficientAmountOut();
    
            Token(token).transferFrom(msg.sender, address(this), amountIn);
            grey.transfer(msg.sender, amountOut);
    
            emit TokenSold(msg.sender, token, amountOut, amountIn);
        }
    
        function launchToken(address token) external returns (address uniswapV2Pair) {
            Pair memory pair = pairs[token];
            if (pair.virtualLiquidity == 0) revert InvalidToken();
    
            uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
            if (actualLiquidity < targetGREYRaised) {
                revert TargetGREYRaisedNotReached();
            }
    
            delete pairs[token];
    
            uint256 greyAmount = actualLiquidity;
            uint256 tokenAmount = pair.reserveToken;
    
            // Burn tokens equal to ratio of reserveGREY removed to maintain constant price
            uint256 burnAmount = (pair.virtualLiquidity * tokenAmount) / pair.reserveGREY;
            tokenAmount -= burnAmount;
            Token(token).burn(burnAmount);
    
            uniswapV2Pair = uniswapV2Factory.getPair(address(grey), address(token));
            if (uniswapV2Pair == address(0)) {
                uniswapV2Pair = uniswapV2Factory.createPair(address(grey), address(token));
            }
    
            grey.transfer(uniswapV2Pair, greyAmount);
            Token(token).transfer(uniswapV2Pair, tokenAmount);
    
            IUniswapV2Pair(uniswapV2Pair).mint(address(0xdEaD));
    
            emit TokenLaunched(token, uniswapV2Pair);
        }
    
        // ======================================== VIEW FUNCTIONS ========================================
    
        function previewBuyTokens(address token, uint256 amountIn) external view returns (uint256 amountOut) {
            Pair memory pair = pairs[token];
            amountOut = _getAmountOut(amountIn, pair.reserveGREY, pair.reserveToken);
        }
    
        function previewSellTokens(address token, uint256 amountIn) external view returns (uint256 amountOut) {
            Pair memory pair = pairs[token];
    
            amountOut = _getAmountOut(amountIn, pair.reserveToken, pair.reserveGREY);
    
            uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
            if (amountOut > actualLiquidity) revert InsufficientGREYLiquidity();
        }
    
        function tokenPrice(address token) external view returns (uint256 price) {
            Pair memory pair = pairs[token];
            price = pair.reserveGREY.divWadDown(pair.reserveToken);
        }
    
        function bondingCurveProgress(address token) external view returns (uint256 progress) {
            Pair memory pair = pairs[token];
            uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
            progress = actualLiquidity.divWadDown(targetGREYRaised);
        }
    
        // ======================================== HELPER FUNCTIONS ========================================
    
        function _buyTokens(address token, uint256 amountIn, uint256 minAmountOut) internal returns (uint256 amountOut) {
            Pair storage pair = pairs[token];
    
            amountOut = _getAmountOut(amountIn, pair.reserveGREY, pair.reserveToken);
    
            pair.reserveGREY += amountIn;
            pair.reserveToken -= amountOut;
    
            if (amountOut < minAmountOut) revert InsufficientAmountOut();
    
            grey.transferFrom(msg.sender, address(this), amountIn);
            Token(token).transfer(msg.sender, amountOut);
    
            emit TokenBought(msg.sender, token, amountIn, amountOut);
        }
    
        function _getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
            if (amountIn == 0) revert InsufficientAmountIn();
            if (reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();
    
            return (amountIn * reserveOut) / (reserveIn + amountIn);
        }
    }
```  
  
---|---  
  
The code is quite long, but it’s fine. Let’s try to break it down one by one.

First, let’s start from the `constructor`. When the contract get deployed, it will initialize the value of `virtualLiquidity` and `targetGREYRaised` passed by the deployer. It is basically just like what the title of the challenge said, is a launchpad for people to launch token to the UniswapV2 to be able traded when the funding target is fulfilled (`targetGREYRaised`).

To understand better, let’s start by checking the `createToken` function.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
```

| 

```
    function createToken(string memory name, string memory symbol, bytes32 salt, uint256 amountIn)
        external
        returns (address tokenAddress, uint256 amountOut)
    {
        Token token = new Token{salt: salt}(name, symbol);
        tokenAddress = address(token);
    
        pairs[tokenAddress] = Pair({
            virtualLiquidity: virtualLiquidity,
            reserveGREY: virtualLiquidity,
            reserveToken: token.INITIAL_AMOUNT()
        });
    
        // minAmountOut not needed here as token was just created
        if (amountIn != 0) amountOut = _buyTokens(tokenAddress, amountIn, 0);
    
        emit TokenCreated(tokenAddress, msg.sender);
    }
```  
  
---|---  
  
It will basically just create a new `Token` with the given param, and then initialize a “virtual” pair, where the initial reserve is `virtualLiquidity` of `GREY` and `INITIAL_AMOUNT` of `Token` that you want to launch.

Now, let’s check the code of `buyToken` function.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
```

| 

```
    function buyTokens(address token, uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
        Pair memory pair = pairs[token];
        if (pair.virtualLiquidity == 0) revert InvalidToken();
    
        uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
        if (actualLiquidity >= targetGREYRaised) {
            revert TargetGREYRaisedReached();
        }
    
        amountOut = _buyTokens(token, amountIn, minAmountOut);
    }
    
    function _buyTokens(address token, uint256 amountIn, uint256 minAmountOut) internal returns (uint256 amountOut) {
        Pair storage pair = pairs[token];
    
        amountOut = _getAmountOut(amountIn, pair.reserveGREY, pair.reserveToken);
    
        pair.reserveGREY += amountIn;
        pair.reserveToken -= amountOut;
    
        if (amountOut < minAmountOut) revert InsufficientAmountOut();
    
        grey.transferFrom(msg.sender, address(this), amountIn);
        Token(token).transfer(msg.sender, amountOut);
    
        emit TokenBought(msg.sender, token, amountIn, amountOut);
    }
    
    function _getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        if (amountIn == 0) revert InsufficientAmountIn();
        if (reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();
    
        return (amountIn * reserveOut) / (reserveIn + amountIn);
    }
```  
  
---|---  
  
The main purpose of this feature is to raise funds to launch the created token. Users can buy the `Token` using `GREY`, and `_buyTokens` will adjust the `reserve` values accordingly. The `_getAmountOut` function contains the formula to calculate how many `Token` tokens a user receives based on the current reserves and their `GREY` input.

Observed that while `buyToken` tries to prevent users from buying more tokens when the `GREY` reserve exceeds the target, it only checks the current state before the trade, not accounting for how much the trade itself will increase the reserves. This means `reserveGREY` can exceed the target, causing `actualLiquidity` (calculated as `reserveGrey - virtualLiquidity`) to go above what was intended.

For example, let’s say:

  * `virtualLiquidity` = 2 ether
  * `targetGREYRaised` = 6 ether
  * Current `reserveGREY` = 4 ether


Then `actualLiquidity` = `reserveGREY` \- `virtualLiquidity` = 2 ether

If a user tries to buy tokens with 5 ether of `GREY`:

  1. `buyTokens` checks if current `actualLiquidity` (2 ether) < `targetGREYRaised` (6 ether)
  2. The check passes since 2 < 6
  3. After `_buyTokens` executes, `reserveGREY` = 9 ether (4 + 5)
  4. This makes the new `actualLiquidity` = 7 ether (9 - 2)


This shows that while the function tries to prevent exceeding the target, **it only checks the current state before the trade** , not accounting for how much the trade itself will increase the reserves. We’ll keep this observation in mind.

Let’s examine the `launchToken` function next.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
```

| 

```
    function launchToken(address token) external returns (address uniswapV2Pair) {
        Pair memory pair = pairs[token];
        if (pair.virtualLiquidity == 0) revert InvalidToken();
    
        uint256 actualLiquidity = pair.reserveGREY - pair.virtualLiquidity;
        if (actualLiquidity < targetGREYRaised) {
            revert TargetGREYRaisedNotReached();
        }
    
        delete pairs[token];
    
        uint256 greyAmount = actualLiquidity;
        uint256 tokenAmount = pair.reserveToken;
    
        // Burn tokens equal to ratio of reserveGREY removed to maintain constant price
        uint256 burnAmount = (pair.virtualLiquidity * tokenAmount) / pair.reserveGREY;
        tokenAmount -= burnAmount;
        Token(token).burn(burnAmount);
    
        uniswapV2Pair = uniswapV2Factory.getPair(address(grey), address(token));
        if (uniswapV2Pair == address(0)) {
            uniswapV2Pair = uniswapV2Factory.createPair(address(grey), address(token));
        }
    
        grey.transfer(uniswapV2Pair, greyAmount);
        Token(token).transfer(uniswapV2Pair, tokenAmount);
    
        IUniswapV2Pair(uniswapV2Pair).mint(address(0xdEaD));
    
        emit TokenLaunched(token, uniswapV2Pair);
    }
```  
  
---|---  
  
This function checks whether the `factory` has enough `actualLiquidity` to be launched. If yes, it will burn some of the `tokenAmount` to maintain the same price ratio of the pair after launching to Uniswap V2 Pair. An unusual behavior exists in how the function handles the Uniswap pairs. Noticed that **it treats new and existing pairs identically when adding liquidity**. We will look further into the effect of this later, but let’s keep it in our mind for now.

Now that we’ve skimmed through the main functions of the `launchpad` contract and identified this key vulnerability, let’s check the challenge setup.

**Setup.sol**

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
```

| 

```
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    
    import {GREY} from "./lib/GREY.sol";
    import {UniswapV2Factory} from "./lib/v2-core/UniswapV2Factory.sol";
    import {Factory} from "./Factory.sol";
    import {Token} from "./Token.sol";
    
    contract Setup {
        bool public claimed;
    
        // GREY token
        GREY public grey;
    
        // Challenge contracts
        UniswapV2Factory public uniswapV2Factory;
        Factory public factory;
        Token public meme;
    
        constructor() {
            // Deploy the GREY token contract
            grey = new GREY();
    
            // Mint 7 GREY for setup
            grey.mint(address(this), 7 ether);
    
            // Deploy challenge contracts
            uniswapV2Factory = new UniswapV2Factory(address(0xdead));
            factory = new Factory(address(grey), address(uniswapV2Factory), 2 ether, 6 ether);
    
            // Create a meme token
            (address _meme,) = factory.createToken("Meme", "MEME", bytes32(0), 0);
            meme = Token(_meme);
    
            // Buy 2 GREY worth of MEME
            grey.approve(address(factory), 2 ether);
            factory.buyTokens(_meme, 2 ether, 0);
        }
    
        // Note: Call this function to claim 5 GREY for the challenge
        function claim() external {
            require(!claimed, "already claimed");
            claimed = true;
    
            grey.transfer(msg.sender, 5 ether);
        }
    
        // Note: Challenge is solved when you have at least 5.965 GREY
        function isSolved() external view returns (bool) {
            return grey.balanceOf(msg.sender) >= 5.965 ether;
        }
    }
```  
  
---|---  
  
Reading through the challenge, in general, the setup of this challenge is related to a contract that wants to launch a `MEME` coin and then initialize a decentralized exchange that allows users to trade the token (pair of `GREY` and `MEME`) via `UniswapV2`.

Then, the challenge will mint `7 ether` of `GREY`, where `2 ether` of `GREY` will be used to buy `MEME` tokens through the `factory` contract, and `5 ether` of `GREY` will be given to the player via the `claim()` function.

The goal is to increase our `GREY` balance from `5 ether` to at least `5.965 ether` of `GREY` (about 19.3% profit).

This information from the challenge specification is enough. We can now start to think about what we can do to exploit the challenge so that we can somehow get guaranteed profit.

### Solution

From the initial analysis, recall an important observation we made while examining the `launchToken` function:

  * The `factory` can launch the trading pair regardless of whether the pair already exists or not.


#### Uniswap V2 Pair 101

Before diving into the solution, let’s understand how Uniswap V2 pairs work, particularly focusing on the relation with the previous observation that we discovered.

In Uniswap V2, the initial setup of a trading pair is actually a critical moment. The first liquidity provider has the unique privilege of establishing the starting price ratio between the two tokens. This ratio becomes the foundation that all subsequent trading and liquidity provision will build upon.

To understand this better, let’s examine the `mint` function defined in the Uniswap V2 pair.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
```

| 

```
    uint public constant MINIMUM_LIQUIDITY = 10**3;
    [...]
     // this low-level function should be called from a contract which performs important safety checks
     function mint(address to) external lock returns (uint liquidity) {
         (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
         uint balance0 = IERC20(token0).balanceOf(address(this));
         uint balance1 = IERC20(token1).balanceOf(address(this));
         uint amount0 = balance0.sub(_reserve0);
         uint amount1 = balance1.sub(_reserve1);
    
         bool feeOn = _mintFee(_reserve0, _reserve1);
         uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
         if (_totalSupply == 0) {
             liquidity = Math.sqrt(amount0.mul(amount1)).sub(MINIMUM_LIQUIDITY);
            _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock the first MINIMUM_LIQUIDITY tokens
         } else {
             liquidity = Math.min(amount0.mul(_totalSupply) / _reserve0, amount1.mul(_totalSupply) / _reserve1);
         }
         require(liquidity > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED');
         _mint(to, liquidity);
    
         _update(balance0, balance1, _reserve0, _reserve1);
         if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
         emit Mint(msg.sender, amount0, amount1);
     }
```  
  
---|---  
  
The first liquidity provider deposits both tokens into the pool, and Uniswap uses these amounts to establish the initial price ratio.

For example, if someone adds $1000$ $\text{token0}$ and $100000$ $\text{token1}$ as initial liquidity, then the provider will get: $$ \begin{align*} \text{lpTokens} &= \sqrt{\text{amountToken0} \cdot \text{amountToken1}} - \text{minLiquidity} \\\ &= \sqrt{1000 \cdot 100000} - 1000 \\\ &= 9000 \end{align*} $$ where the initial price (which is the ratio of the reserves of $token0$ and $tokenB$) will be: $$\text{token0}:\text{token1} = 1:100$$ and the remaining state will be: $$ \begin{align*} &\text{reserve0} = 1000 \\\ &\text{reserve1} = 100000 \\\ &\text{totalSupply} = 10000 \\\ \end{align*} $$

Now, what about subsequent liquidity providers? If you notice in the `mint` code, any provider can actually provide tokens in any ratio of $\text{token0}$ and $\text{token1}$, without being forced to follow the ratio of the current reserves.

However, observing the LP tokens calculation code, the number of LP tokens that the provider gets still follows the current ratio.

Continuing the above example, if the current ratio is 1:100 and a liquidity provider tries to add tokens in a 1:1 ratio (i.e. provide $100000$ $\text{token0}$ and $100000$ $\text{token1}$), the calculation will be: $$ \begin{align*} \text{lpTokens} &= \min\left(\frac{\text{amountToken0} \cdot \text{totalSupply}}{\text{reserve0}}, \frac{\text{amountToken1} \cdot \text{totalSupply}}{\text{reserve1}}\right) \\\ &= \min(\frac{100000 \cdot 10000}{1000}, \frac{100000 \cdot 10000}{100000}) \\\ &= \min(1000000, 10000) \\\ &= 10000 \end{align*} $$ and the new state will be: $$ \begin{align*} &\text{reserve0} = 101000 \\\ &\text{reserve1} = 200000 \\\ &\text{totalSupply} = 20000 \\\ \end{align*} $$

Observe that in this case, even though we provided $100000$ $\text{token0}$, we only received LP tokens proportional to the smaller of the two ratios. We would actually receive the same number of LP tokens even if we had only provided $1000$ $\text{token0}$ (the smaller amount). This is because the `min()` function ensures LP tokens are minted based on whichever token amount maintains the current pool ratio. Any excess $\text{token0}$ we provided gets added to the pool without receiving corresponding LP tokens, effectively **donating** the remaining $\text{token0}$ to the existing LP token holders.

Notice that the effect of donation can be seen when the initial liquidity provider wants to `burn` their $lpTokens$. Let’s examine the `burn` function below:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
```

| 

```
     // this low-level function should be called from a contract which performs important safety checks
     function burn(address to) external lock returns (uint amount0, uint amount1) {
         (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
         address _token0 = token0;                                // gas savings
         address _token1 = token1;                                // gas savings
         uint balance0 = IERC20(_token0).balanceOf(address(this));
         uint balance1 = IERC20(_token1).balanceOf(address(this));
         uint liquidity = balanceOf[address(this)];
    
         bool feeOn = _mintFee(_reserve0, _reserve1);
         uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
         amount0 = liquidity.mul(balance0) / _totalSupply; // using balances ensures pro-rata distribution
         amount1 = liquidity.mul(balance1) / _totalSupply; // using balances ensures pro-rata distribution
         require(amount0 > 0 && amount1 > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED');
         _burn(address(this), liquidity);
         _safeTransfer(_token0, to, amount0);
         _safeTransfer(_token1, to, amount1);
         balance0 = IERC20(_token0).balanceOf(address(this));
         balance1 = IERC20(_token1).balanceOf(address(this));
    
         _update(balance0, balance1, _reserve0, _reserve1);
         if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
         emit Burn(msg.sender, amount0, amount1, to);
     }
```  
  
---|---  
  
Let’s say that we are the initial liquidity provider and want to burn all of our $\text{lpTokens}$ (which is $9000$). The amount that we will receive will be: $$ \begin{align*} \text{amountToken0} &= \frac{\text{lpTokens} \cdot \text{reserve0}}{\text{totalSupply}} \\\ &= \frac{9000 \cdot 101000}{20000} \\\ &= 45450 \end{align*} $$ $$ \begin{align*} \text{amountToken1} &= \frac{\text{lpTokens} \cdot \text{reserve1}}{\text{totalSupply}} \\\ &= \frac{9000 \cdot 200000}{20000} \\\ &= 90000 \end{align*} $$ As we can see above, when we burn the lpTokens, we receive $45450$ of $\text{token0}$ and $90000$ of $\text{token1}$. The initial liquidity provider easily gains a profit of $44550$ $\text{token0}$ due to the donation from the second minter (even though we lose some of the $\text{token1}$ due to the initial provider needing to lock $1000$ of their LP Tokens forever).

#### Crafting the Solution

Now that we understand how liquidity providers work in the Uniswap V2 Pair, let’s return to our previous observation. Remember that in the `launchToken` code, the function will still launch the token even if the pair already exists. This means that when `launchToken` provides liquidity with a different ratio than the existing pair’s ratio, the `factory` contract could lose some of its provided tokens to the initial liquidity provider who created the pair.

Based on our understanding of how Uniswap V2 pair liquidity minting works, we can solve this challenge by creating the `GREY/MEME` pair before triggering `launchToken`. This allows us to control the pair’s initial price ratio, potentially causing the `GREY` tokens that the factory provides during `launchToken` to be donated to our LP token holdings as the initial liquidity provider.

The key is to create the `GREY/MEME` pair with an extreme initial ratio. We want to set up the ratio such that when the `factory` calls `launchToken`, most of its provided `GREY` tokens will be considered “excess” compared to our established ratio. These excess tokens will be donated to our LP token position rather than being properly accounted for in new LP token minting.

We start with `5 ether` worth of `GREY` tokens. To maximize the donation effect, we’ll create an extreme ratio in the `GREY/MEME` pair by using just 1 wei of `GREY` for all our `MEME` tokens. The detailed plan would be:

  1. Use the `buyToken` feature in `factory` to swap almost all our `GREY` tokens (`5 ether - 1 wei`) for `MEME` tokens. 
     * Note that this will work even though the raised `GREY` will exceed the target (`6 ether`) due to our previous observation that the guard only checks the current state instead of the future state.
  2. Create the `GREY/MEME` pair via Uniswap with our extreme ratio (1 wei GREY : all our MEME).
  3. Trigger `launchToken`, which will cause the factory’s `GREY` tokens to be donated to our LP position due to the ratio mismatch.
  4. Burn all our LP tokens to receive both tokens back.
  5. Swap all received `MEME` tokens back to `GREY` through the Uniswap V2 Pair.


If executed correctly, we should end up with significantly more `GREY` tokens than we started with. Let’s try to implement this plan while going through each step in detail.

#### Executing the Solution

To help us execute our plan, I will use a Foundry script.

##### Initial Setup

Let’s start by preparing a new project using the `forge init --no-commit` command.

![](https://i.imgur.com/NeOcarD.png)

Next, let’s copy the challenge folder `lib/` and the contracts (`Setup.sol`, `Factory.sol`, and `Token.sol`) to the `script` folder. We’ll prepare our script inside `Counter.s.sol` (because I’m too lazy to rename and prepare proper folder structures lol 😬). The folder structure will look like this:

![](https://i.imgur.com/rJxirXB.png)

Now we can begin crafting our exploit script in the `Counter.s.sol` file. First, let’s import all the required files and clean up the `run()` function by removing any unused code and variables. Our initial script template will look like this:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
```

| 

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;
    
    import {Script, console} from "forge-std/Script.sol";
    import {Setup} from "./Setup.sol";
    import {GREY} from "./lib/GREY.sol";
    import {UniswapV2Factory} from "./lib/v2-core/UniswapV2Factory.sol";
    import {Factory} from "./Factory.sol";
    import {Token} from "./Token.sol";
    import {IUniswapV2Pair} from "./lib/v2-core/interfaces/IUniswapV2Pair.sol";
    import {IERC20} from "./lib/v2-core/interfaces/IERC20.sol";
    
    
    contract CounterScript is Script {
        function setUp() public {}
    
        function run() public {
    
        }
    }
```  
  
---|---  
  
Now that we’ve prepared the script file, let’s implement our plan by filling in the `run` function. We’ll start by connecting to the given RPC and initializing variables with the contract addresses we have.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
```

| 

```
    function run() public {
        string memory rpc = "http://challs2.nusgreyhats.org:33502/0b3164f8-2adc-465a-9743-61c1517b2e9a";
        uint256 privateKey = 0xd41bcc5d73608ffa85c1bada6c8a7a52fb050f03d17d139c2db146de078d95a5;
        address setupAddress = 0xbE49C81C4D7A188e3C24043556d78C3dC61fc3BE;
        address sender = vm.addr(privateKey);
    
        // Connect to network
        vm.createSelectFork(rpc);
    
        // Set up contracts
        Setup setup = Setup(setupAddress);
        GREY grey = GREY(setup.grey());
        UniswapV2Factory uniswapV2Factory = UniswapV2Factory(setup.uniswapV2Factory());
        Factory factory = Factory(setup.factory());
        Token meme = Token(setup.meme());
    }
```  
  
---|---  
  
##### Claim and Swap

Now, let’s implement our first step: claiming our initial `GREY` tokens and swapping them through the `Factory` contract’s `buyTokens` function.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
```

---

*Truncated at 1200 lines. Full text: <https://chovid99.github.io/posts/greyctf-2025/>*
