---
title: "EVM Solve Templates - Foundry Solve.s.sol and web3.py"
category: blockchain
subcategory: templates
type: script
tags: [blockchain, foundry, forge-script, solidity, web3py, python, template, solve, exploit, rpc, private-key, env, broadcast, issolved, attacker-contract, evm]
summary: "Two drop-in solve templates parameterised by RPC_URL / PRIVATE_KEY / SETUP: a Foundry script plus attacker contract, and a standalone web3.py solver."
tools: [foundry, forge, cast, web3py, python]
related: [setup-and-workflow, attacker-contract-patterns, web3py-cheatsheet, storage-dumper]
---

## Usage

```bash
# 1) environment (everything below reads these three)
export RPC_URL="http://chal.example:8545/your-uuid"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export SETUP="0x5FbDB2315678afecb367f032d93F642f64180aa3"

# 2) foundry route
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" -vvvv            # dry run
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast -vvvv
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast --legacy --slow

# 3) python route
python3 solve.py
```

## Foundry: `script/Solve.s.sol`

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {Attacker} from "../src/Attacker.sol";

interface ISetup {
    function isSolved() external view returns (bool);
}

/// Generic solve driver.
///
///   RPC_URL      - the challenge RPC (passed on the command line, not read here)
///   PRIVATE_KEY  - hex, 0x-prefixed
///   SETUP        - the Setup contract address
///   TARGET       - optional; if unset we ask SETUP for it
///
/// Run with --broadcast to actually send. Without it, everything is simulated
/// against current chain state, which is the fastest way to iterate.
contract Solve is Script {
    ISetup internal setup;
    address internal target;
    address internal me;
    uint256 internal pk;

    function setUp() public {
        pk = vm.envUint("PRIVATE_KEY");
        me = vm.addr(pk);
        setup = ISetup(vm.envAddress("SETUP"));
        target = vm.envOr("TARGET", address(0));
        if (target == address(0)) {
            target = _discoverTarget(address(setup));
        }
    }

    function run() external {
        console2.log("=== before ===");
        _report();
        require(!setup.isSolved(), "already solved");

        vm.startBroadcast(pk);
        _exploit();
        vm.stopBroadcast();

        console2.log("=== after ===");
        _report();
        require(setup.isSolved(), "NOT SOLVED");
        console2.log("SOLVED");
    }

    // -------------------------------------------------------------------
    // Put the actual attack here. Everything between startBroadcast and
    // stopBroadcast is a real transaction when --broadcast is passed.
    // -------------------------------------------------------------------
    function _exploit() internal {
        Attacker attacker = new Attacker{value: 0.1 ether}(target);
        attacker.pwn();
        attacker.sweep(payable(me));
    }

    // -------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------

    /// Try the getter names CTF Setup contracts commonly use.
    function _discoverTarget(address s) internal view returns (address) {
        string[6] memory names =
            ["TARGET()", "target()", "challenge()", "instance()", "CHALLENGE()", "chall()"];
        for (uint256 i = 0; i < names.length; i++) {
            (bool ok, bytes memory ret) = s.staticcall(abi.encodeWithSignature(names[i]));
            if (ok && ret.length == 32) {
                address a = abi.decode(ret, (address));
                if (a != address(0)) {
                    console2.log("target getter:", names[i]);
                    return a;
                }
            }
        }
        revert("could not discover target; set TARGET explicitly");
    }

    function _report() internal view {
        console2.log("me      :", me);
        console2.log("setup   :", address(setup));
        console2.log("target  :", target);
        console2.log("my ETH  :", me.balance);
        console2.log("tgt ETH :", target.balance);
        console2.log("solved  :", setup.isSolved());
    }

    /// Dump the first n storage slots of an address (debug aid).
    function _dumpStorage(address a, uint256 n) internal view {
        for (uint256 i = 0; i < n; i++) {
            bytes32 v = vm.load(a, bytes32(i));
            if (v != bytes32(0)) {
                console2.log("slot", i);
                console2.logBytes32(v);
            }
        }
    }
}
```

## Foundry: `src/Attacker.sol`

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 id) external;
}

/// A reusable attacker skeleton.
/// - funded at construction so constructor-only attacks work
/// - onlyOwner on every mutator so nobody front-runs your exploit
/// - accepts every asset type so token hooks never revert
/// - raw `exec` escape hatch for anything the typed helpers miss
contract Attacker {
    address public immutable owner;
    address public immutable target;

    uint256 public depth;
    uint256 public maxDepth = 10;

    event Step(string what, uint256 value);

    constructor(address _target) payable {
        owner = msg.sender;
        target = _target;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ------------------------------------------------------------------
    // main exploit body
    // ------------------------------------------------------------------
    function pwn() external payable onlyOwner {
        // EXAMPLE: deposit then re-enter on the refund
        // IVictim(target).deposit{value: address(this).balance}();
        // IVictim(target).withdraw();
        emit Step("pwn", address(this).balance);
    }

    /// Reentrancy hook. Guarded by a depth counter so the final inner call
    /// does not revert and unwind the whole transaction.
    receive() external payable {
        if (depth < maxDepth && address(target).balance >= msg.value) {
            depth++;
            // IVictim(target).withdraw();
        }
    }

    function setMaxDepth(uint256 n) external onlyOwner {
        maxDepth = n;
    }

    // ------------------------------------------------------------------
    // generic primitives
    // ------------------------------------------------------------------

    /// Arbitrary call, bubbling the original revert reason.
    function exec(address to, uint256 value, bytes calldata data)
        external
        payable
        onlyOwner
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }

    /// Repeat one call n times in a single transaction.
    function repeat(address to, uint256 value, bytes calldata data, uint256 n)
        external
        payable
        onlyOwner
    {
        for (uint256 i = 0; i < n; i++) {
            (bool ok, ) = to.call{value: value}(data);
            require(ok, "iteration failed");
        }
    }

    /// Arbitrary delegatecall (runs `to`'s code against THIS contract's storage).
    function delegate(address to, bytes calldata data) external onlyOwner returns (bytes memory) {
        require(to.code.length > 0, "no code at target");
        (bool ok, bytes memory ret) = to.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    // ------------------------------------------------------------------
    // sweeps -- always run these at the end
    // ------------------------------------------------------------------
    function sweep(address payable to) public onlyOwner {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "eth sweep failed");
    }

    function sweepToken(address token, address to) external onlyOwner {
        IERC20 t = IERC20(token);
        require(t.transfer(to, t.balanceOf(address(this))), "token sweep failed");
    }

    function sweepNft(address nft, address to, uint256 id) external onlyOwner {
        IERC721(nft).transferFrom(address(this), to, id);
    }

    // ------------------------------------------------------------------
    // receiver hooks: without these, safeTransfer into us reverts
    // ------------------------------------------------------------------
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        returns (bytes4)
    {
        // re-entrancy point for _safeMint-based challenges
        if (depth < maxDepth) {
            depth++;
            // IMintable(target).mint();
        }
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /// ERC777 hook
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata)
        external
        pure
    {}

    /// Uniswap V2 flash-swap callback
    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        // repay inside here
    }

    /// ERC-3156 flash-loan callback
    function onFlashLoan(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes32)
    {
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}
```

## Foundry: `foundry.toml`

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
evm_version = "cancun"        # switch to "shanghai"/"paris" if the challenge chain is older
optimizer = true
optimizer_runs = 200
ffi = false

[rpc_endpoints]
chal = "${RPC_URL}"
```

## Python: `solve.py`

```python
#!/usr/bin/env python3
"""Standalone web3.py solve template for an EVM CTF challenge.

Environment:
    RPC_URL      required, the challenge RPC endpoint
    PRIVATE_KEY  required, 0x-prefixed hex
    SETUP        optional, the Setup contract address
    TARGET       optional, overrides the address discovered from SETUP
    LEGACY       optional, "1" to force legacy (type 0) transactions

Install:
    pip install "web3>=6.15" eth-account eth-abi eth-utils

Run:
    RPC_URL=... PRIVATE_KEY=... SETUP=... python3 solve.py
"""
from __future__ import annotations

import os
import sys
from typing import Any, Optional, Sequence

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import function_signature_to_4byte_selector, keccak
from web3 import Web3

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY", "0x" + "11" * 32)
SETUP = os.environ.get("SETUP") or None
TARGET_ENV = os.environ.get("TARGET") or None
LEGACY = os.environ.get("LEGACY", "1") == "1"

TARGET_GETTERS = (
    "TARGET()",
    "target()",
    "challenge()",
    "instance()",
    "CHALLENGE()",
    "chall()",
)


# --------------------------------------------------------------------------
# low-level helpers (no ABI required)
# --------------------------------------------------------------------------
def selector(signature: str) -> bytes:
    """4-byte selector of a canonical function signature."""
    return function_signature_to_4byte_selector(signature)


def calldata(signature: str, arg_types: Sequence[str] = (), args: Sequence[Any] = ()) -> bytes:
    """Build calldata from a signature plus ABI types and values."""
    return selector(signature) + (abi_encode(list(arg_types), list(args)) if arg_types else b"")


def eth_call(
    w3: Web3,
    to: str,
    data: bytes,
    out_types: Sequence[str] = (),
    frm: Optional[str] = None,
    value: int = 0,
    block: Any = "latest",
):
    """Simulate a call; decode the return value if out_types is given."""
    tx: dict[str, Any] = {"to": Web3.to_checksum_address(to), "data": data, "value": value}
    if frm:
        tx["from"] = Web3.to_checksum_address(frm)
    raw = w3.eth.call(tx, block_identifier=block)
    if not out_types:
        return raw
    return abi_decode(list(out_types), bytes(raw))


def send_tx(
    w3: Web3,
    acct,
    to: Optional[str],
    data: bytes = b"",
    value: int = 0,
    gas: Optional[int] = None,
) -> dict:
    """Build, sign and broadcast a transaction; wait for the receipt.

    `to=None` performs a contract creation with `data` as the init code.
    """
    tx: dict[str, Any] = {
        "from": acct.address,
        "data": data,
        "value": value,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": w3.eth.chain_id,
    }
    if to is not None:
        tx["to"] = Web3.to_checksum_address(to)

    if LEGACY:
        tx["gasPrice"] = max(w3.eth.gas_price, 1)
    else:
        base = w3.eth.get_block("latest").get("baseFeePerGas", 0) or 0
        tip = w3.to_wei(1, "gwei")
        tx["maxPriorityFeePerGas"] = tip
        tx["maxFeePerGas"] = base * 2 + tip
        tx["type"] = 2

    if gas is not None:
        tx["gas"] = gas
    else:
        try:
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.5)
        except Exception as exc:  # estimation reverts on purpose-built traps
            print(f"[!] gas estimation failed ({exc}); falling back to 3,000,000")
            tx["gas"] = 3_000_000

    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    txhash = w3.eth.send_raw_transaction(raw)
    rcpt = w3.eth.wait_for_transaction_receipt(txhash, timeout=300)
    status = "ok" if rcpt["status"] == 1 else "REVERTED"
    print(f"    tx {txhash.hex()}  {status}  gas={rcpt['gasUsed']}")
    if rcpt["status"] != 1:
        raise RuntimeError(f"transaction reverted: {txhash.hex()}")
    return rcpt


def deploy(w3: Web3, acct, init_code_hex: str, value: int = 0) -> str:
    """Deploy raw init code (e.g. `forge inspect X bytecode` output) and return the address."""
    init = bytes.fromhex(init_code_hex.removeprefix("0x"))
    rcpt = send_tx(w3, acct, None, data=init, value=value)
    addr = rcpt["contractAddress"]
    print(f"    deployed at {addr}")
    return addr


def read_slot(w3: Web3, address: str, slot: int, block: Any = "latest") -> bytes:
    return bytes(w3.eth.get_storage_at(Web3.to_checksum_address(address), slot, block_identifier=block))


def mapping_slot(key: Any, declared_slot: int) -> int:
    """Slot of mapping[key] for a mapping declared at `declared_slot`."""
    if isinstance(key, int):
        kb = key.to_bytes(32, "big")
    else:
        kb = bytes.fromhex(str(key).removeprefix("0x")).rjust(32, b"\x00")
    return int.from_bytes(keccak(kb + declared_slot.to_bytes(32, "big")), "big")


def discover_target(w3: Web3, setup: str) -> Optional[str]:
    """Ask a Setup contract for the challenge address using the usual getter names."""
    for name in TARGET_GETTERS:
        try:
            (addr,) = eth_call(w3, setup, selector(name), ["address"])
        except Exception:
            continue
        if int(addr, 16) != 0:
            print(f"[+] target getter: {name}")
            return Web3.to_checksum_address(addr)
    return None


def is_solved(w3: Web3, setup: str) -> bool:
    (flag,) = eth_call(w3, setup, selector("isSolved()"), ["bool"])
    return bool(flag)


# --------------------------------------------------------------------------
# the exploit
# --------------------------------------------------------------------------
def exploit(w3: Web3, acct, target: str) -> None:
    """Replace the body with the actual attack.

    Useful primitives, all defined above:
        send_tx(w3, acct, target, calldata("withdraw(uint256)", ["uint256"], [10**18]))
        send_tx(w3, acct, target, b"", value=w3.to_wei(1, "ether"))
        deploy(w3, acct, open("Attacker.bin").read(), value=w3.to_wei(1, "ether"))
        eth_call(w3, target, selector("owner()"), ["address"])
        read_slot(w3, target, 0)
        read_slot(w3, target, mapping_slot(acct.address, 2))
    """
    print("[*] exploit() is a stub -- fill it in")
    # example: a plain deposit
    # send_tx(w3, acct, target, calldata("deposit()"), value=w3.to_wei(1, "ether"))


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def main() -> int:
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        print(f"[-] cannot reach {RPC_URL}")
        return 1

    acct = Account.from_key(PRIVATE_KEY)
    bal = w3.eth.get_balance(acct.address)
    print(f"[+] rpc      {RPC_URL}")
    print(f"[+] chain id {w3.eth.chain_id}   block {w3.eth.block_number}")
    print(f"[+] me       {acct.address}   {w3.from_wei(bal, 'ether')} ETH")

    target = TARGET_ENV
    if SETUP:
        print(f"[+] setup    {SETUP}")
        if target is None:
            target = discover_target(w3, SETUP)
        try:
            print(f"[+] solved?  {is_solved(w3, SETUP)}")
        except Exception as exc:
            print(f"[!] isSolved() unavailable: {exc}")

    if target is None:
        print("[-] no target; set TARGET or SETUP")
        return 1
    target = Web3.to_checksum_address(target)
    print(f"[+] target   {target}   {w3.from_wei(w3.eth.get_balance(target), 'ether')} ETH")
    print(f"[+] code     {len(w3.eth.get_code(target))} bytes")

    exploit(w3, acct, target)

    if SETUP:
        solved = is_solved(w3, SETUP)
        print(f"[{'+' if solved else '-'}] isSolved() = {solved}")
        return 0 if solved else 2
    return 0


def _self_test() -> None:
    """Offline checks of the pure helpers -- no RPC needed."""
    assert selector("transfer(address,uint256)").hex() == "a9059cbb"
    assert selector("balanceOf(address)").hex() == "70a08231"
    assert selector("isSolved()").hex() == keccak(text="isSolved()")[:4].hex()

    cd = calldata("transfer(address,uint256)", ["address", "uint256"],
                  ["0x000000000000000000000000000000000000dEaD", 10**18])
    assert len(cd) == 4 + 64
    assert cd[:4].hex() == "a9059cbb"

    # mapping slot math matches keccak(pad32(key) || pad32(slot))
    expected = int.from_bytes(keccak(b"\x00" * 32 + (2).to_bytes(32, "big")), "big")
    assert mapping_slot(0, 2) == expected
    assert mapping_slot("0x" + "00" * 20, 2) == expected
    print("[+] self-test ok")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
        sys.exit(0)
    sys.exit(main())
```

## Notes

- `forge script` steps are **not atomic** across `vm.startBroadcast` boundaries; anything that must
  happen in one transaction belongs inside a single contract call.
- Add `--legacy` whenever the chain rejects type-2 transactions, and `--slow` when the challenge
  enforces one action per block.
- `python3 solve.py --self-test` verifies the helper maths without touching the network.
- Always finish with a sweep; a solved challenge with funds stranded in the attacker contract still
  fails `isSolved()` on balance-based checks.
