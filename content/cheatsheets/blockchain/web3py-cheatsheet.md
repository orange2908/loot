---
title: "web3.py Cheatsheet - Connect, Sign, Send, Decode"
category: blockchain
subcategory: web3py
type: cheatsheet
tags: [blockchain, web3py, python, ethereum, evm, rpc, transaction, signing, eth-account, abi, calldata, event-logs, storage, gas-estimation, eth-abi, keccak, middleware, poa, contract]
summary: "The web3.py idioms you actually need in a CTF: connect, read storage, build/sign/send raw transactions, encode calldata, decode logs."
tools: [web3py, eth-account, eth-abi, eth-utils, python]
related: [setup-and-workflow, storage-slot-reading, solve-template, storage-dumper, foundry-cast-cheatsheet]
---

## Install

```bash
# web3 v6/v7 plus the pieces you will import directly
pip install "web3>=6.15" eth-account eth-abi eth-utils rlp
# check the version -- the v5 -> v6 rename broke snake_case/camelCase APIs
python3 -c "import web3; print(web3.__version__)"
```

## Connect

```python
from web3 import Web3

# HTTP (the usual CTF case)
w3 = Web3(Web3.HTTPProvider("http://chal.example:8545/uuid"))

# with a timeout and custom headers
w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30, "headers": {"X-Api-Key": "k"}}))

# websocket
from web3 import WebSocketProvider          # v7;  v6: Web3.WebsocketProvider
# IPC
# w3 = Web3(Web3.IPCProvider("/tmp/geth.ipc"))

assert w3.is_connected()                     # v6/v7;  v5: w3.isConnected()
print(w3.eth.chain_id, w3.eth.block_number)
```

```python
# proof-of-authority chains (many dev/CTF chains) need the extradata middleware
from web3.middleware import ExtraDataToPOAMiddleware      # v7
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
# v6 name: from web3.middleware import geth_poa_middleware
#          w3.middleware_onion.inject(geth_poa_middleware, layer=0)
```

```python
# auto-sign every transaction from one key (saves a lot of boilerplate)
from eth_account import Account
from web3.middleware import SignAndSendRawMiddlewareBuilder   # v7

acct = Account.from_key(PRIVATE_KEY)
w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(acct), layer=0)
w3.eth.default_account = acct.address
# now w3.eth.send_transaction({...}) signs locally and sends raw
```

## Accounts and balances

```python
from eth_account import Account

acct = Account.from_key("0xac09...ff80")
me = acct.address

w3.eth.get_balance(me)                       # wei
w3.from_wei(w3.eth.get_balance(me), "ether")
w3.to_wei(1.5, "ether")
w3.eth.get_transaction_count(me)             # nonce (confirmed)
w3.eth.get_transaction_count(me, "pending")  # nonce including the mempool
w3.to_checksum_address("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
w3.is_address(x), w3.is_checksum_address(x)

# a brand new random key
new = Account.create()
print(new.address, new.key.hex())
# from a mnemonic (needs Account.enable_unaudited_hdwallet_features())
Account.enable_unaudited_hdwallet_features()
Account.from_mnemonic("test test test test test test test test test test test junk")
```

## Contract objects

```python
import json

ABI = json.loads('[{"inputs":[],"name":"isSolved","outputs":[{"type":"bool"}],'
                 '"stateMutability":"view","type":"function"}]')
c = w3.eth.contract(address=w3.to_checksum_address(TARGET), abi=ABI)

# read
c.functions.isSolved().call()
c.functions.balanceOf(me).call()
c.functions.owner().call(block_identifier=1234)          # historical
c.functions.adminOnly().call({"from": VICTIM})           # simulate as someone else
c.functions.deposit().call({"value": w3.to_wei(1, "ether")})

# a minimal hand-written ABI is usually faster than finding the real one
MIN_ABI = [
    {"name": "owner", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"type": "address"}]},
    {"name": "withdraw", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
]
```

## Build, sign and send a transaction

```python
# --- explicit, fully manual (works everywhere, including legacy chains) ---
tx = {
    "from": me,
    "to": w3.to_checksum_address(TARGET),
    "value": w3.to_wei(1, "ether"),
    "data": b"",                      # or calldata bytes
    "nonce": w3.eth.get_transaction_count(me),
    "chainId": w3.eth.chain_id,
    "gas": 300_000,
    "gasPrice": w3.eth.gas_price,     # legacy (type 0)
}
signed = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
h = w3.eth.send_raw_transaction(signed.raw_transaction)   # v7; v6: signed.rawTransaction
rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=120)
print(rcpt.status, rcpt.gasUsed)      # status == 1 means success
```

```python
# --- EIP-1559 (type 2) ---
base = w3.eth.get_block("latest")["baseFeePerGas"]
tip = w3.to_wei(2, "gwei")
tx = {
    "from": me, "to": TARGET, "value": 0, "nonce": w3.eth.get_transaction_count(me),
    "chainId": w3.eth.chain_id, "gas": 300_000,
    "maxFeePerGas": base * 2 + tip, "maxPriorityFeePerGas": tip, "type": 2,
}
```

```python
# --- from a contract function (web3 fills data/to for you) ---
tx = c.functions.withdraw(10**18).build_transaction({
    "from": me,
    "nonce": w3.eth.get_transaction_count(me),
    "gas": 500_000,
    "gasPrice": w3.eth.gas_price,
    "chainId": w3.eth.chain_id,
})
signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
w3.eth.send_raw_transaction(signed.raw_transaction)
```

```python
# --- deploy a contract from compiled bytecode ---
Factory = w3.eth.contract(abi=ABI, bytecode=BYTECODE)
tx = Factory.constructor(TARGET, 42).build_transaction({
    "from": me, "nonce": w3.eth.get_transaction_count(me),
    "gas": 3_000_000, "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id,
    "value": w3.to_wei(1, "ether"),      # constructor-funded attacks
})
signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
rcpt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction))
deployed = rcpt.contractAddress
```

```python
# --- raw create: deploy hand-written init code ---
tx = {"from": me, "data": bytes.fromhex("6080604052..."),
      "nonce": w3.eth.get_transaction_count(me), "gas": 1_000_000,
      "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id}
# note: no "to" key at all
```

## Gas

```python
w3.eth.gas_price
w3.eth.max_priority_fee
w3.eth.estimate_gas({"from": me, "to": TARGET, "data": data, "value": 0})
c.functions.withdraw(1).estimate_gas({"from": me})
# estimation reverts if the call reverts -> catch it to learn WHY
from web3.exceptions import ContractLogicError
try:
    c.functions.withdraw(10**30).call({"from": me})
except ContractLogicError as e:
    print("revert reason:", e)          # includes the require string when present
# pad the estimate; some CTF chains mis-estimate on reentrancy
gas = int(w3.eth.estimate_gas(tx) * 1.5)
```

## Raw JSON-RPC and storage

```python
# read a storage slot
w3.eth.get_storage_at(TARGET, 0)                       # -> HexBytes(32)
w3.eth.get_storage_at(TARGET, 0, block_identifier=500) # historical
int.from_bytes(w3.eth.get_storage_at(TARGET, 0), "big")

# EIP-1967 implementation slot
IMPL_SLOT = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
w3.to_checksum_address(w3.eth.get_storage_at(TARGET, IMPL_SLOT)[-20:])

# code
w3.eth.get_code(TARGET).hex()
len(w3.eth.get_code(TARGET))          # 0 -> EOA or destroyed

# any RPC method, including node-specific ones
w3.provider.make_request("anvil_setBalance", [me, hex(10**20)])
w3.provider.make_request("anvil_impersonateAccount", [VICTIM])
w3.provider.make_request("evm_increaseTime", [86400])
w3.provider.make_request("anvil_mine", [])
w3.provider.make_request("debug_traceTransaction", [txhash, {"tracer": "callTracer"}])
```

## Encoding / decoding

```python
from eth_abi import encode, decode
from eth_abi.packed import encode_packed
from eth_utils import keccak, function_signature_to_4byte_selector

# selector
sel = function_signature_to_4byte_selector("transfer(address,uint256)")   # b'\xa9\x05\x9c\xbb'
# full calldata, by hand
calldata = sel + encode(["address", "uint256"], [TO, 10**18])
# the same with a contract object
calldata = c.encode_abi(abi_element_identifier="transfer", args=[TO, 10**18])  # v7
# v6: c.encodeABI(fn_name="transfer", args=[TO, 10**18])

# decode a return value
decode(["uint256"], bytes.fromhex(raw[2:]))
# abi.encodePacked equivalent
encode_packed(["address", "uint256"], [TO, 10**18])
# keccak
keccak(text="Transfer(address,address,uint256)").hex()
keccak(hexstr="0xdeadbeef").hex()
keccak(b"raw bytes").hex()

# decode calldata you captured
fn, params = c.decode_function_input("0xa9059cbb0000...")
```

## Events and logs

```python
# via the contract object (needs the event in the ABI)
ev = c.events.Transfer()
logs = ev.get_logs(from_block=0, to_block="latest")
for lg in logs:
    print(lg["args"], lg["blockNumber"], lg["transactionHash"].hex())

# filter on an indexed argument
logs = c.events.Transfer().get_logs(from_block=0, argument_filters={"from": me})

# raw eth_getLogs with topics you build yourself
topic0 = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
logs = w3.eth.get_logs({
    "address": w3.to_checksum_address(TARGET),
    "fromBlock": 0, "toBlock": "latest",
    "topics": [topic0, None, "0x" + me[2:].rjust(64, "0")],
})

# decode a raw log after the fact
decoded = c.events.Transfer().process_log(logs[0])

# events from one receipt
rcpt = w3.eth.get_transaction_receipt(txhash)
for lg in c.events.Transfer().process_receipt(rcpt):
    print(lg["args"])
```

## Blocks, transactions, tracing

```python
w3.eth.get_block("latest")
w3.eth.get_block("latest", full_transactions=True)
w3.eth.get_block(1234)["timestamp"]
w3.eth.get_transaction(txhash)
w3.eth.get_transaction_receipt(txhash)
w3.eth.get_transaction_receipt(txhash)["contractAddress"]     # for deployments
# raw replay of a transaction's input
tx = w3.eth.get_transaction(txhash)
w3.eth.call({"to": tx["to"], "from": tx["from"], "data": tx["input"], "value": tx["value"]},
            block_identifier=tx["blockNumber"] - 1)
```

## CREATE / CREATE2 addresses

```python
import rlp
from eth_utils import keccak, to_checksum_address

def create_address(sender: str, nonce: int) -> str:
    return to_checksum_address(keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:])

def create2_address(deployer: str, salt: bytes, init_code: bytes) -> str:
    pre = b"\xff" + bytes.fromhex(deployer[2:]) + salt.rjust(32, b"\x00") + keccak(init_code)
    return to_checksum_address(keccak(pre)[12:])
```

## Signing messages

```python
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

# EIP-191 personal_sign
msg = encode_defunct(text="hello")
sig = Account.sign_message(msg, private_key=PRIVATE_KEY)
sig.signature.hex(), sig.v, hex(sig.r), hex(sig.s)
Account.recover_message(msg, signature=sig.signature)

# raw 32-byte digest (what a bare ecrecover expects) -- name differs by version
signer = getattr(Account, "unsafe_sign_hash", None) or Account._sign_hash
raw = signer(digest32, PRIVATE_KEY)

# EIP-712 typed data
typed = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Permit": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
        ],
    },
    "primaryType": "Permit",
    "domain": {"name": "Token", "version": "1", "chainId": 1, "verifyingContract": TOKEN},
    "message": {"owner": me, "spender": SPENDER, "value": 2**256 - 1,
                "nonce": 0, "deadline": 2**256 - 1},
}
signed = Account.sign_typed_data(PRIVATE_KEY, full_message=typed)
v, r, s = signed.v, signed.r, signed.s
```

## Common failure modes

```python
# "only replay-protected (EIP-155) transactions allowed" -> include chainId
# "invalid transaction type" / tx hangs -> use gasPrice (legacy) instead of maxFeePerGas
# "nonce too low" -> get_transaction_count(me, "pending"), or bump manually in a loop
# "intrinsic gas too low" -> raise `gas`
# "execution reverted" with no reason -> the revert had no string; use w3.eth.call to get data
# HexBytes vs str -> .hex() everywhere, and to_checksum_address every address you build
# v5 vs v6 API: isConnected/toWei/getBalance   ->  is_connected/to_wei/get_balance
# signed.rawTransaction (v6) -> signed.raw_transaction (v7)
```

## A complete minimal solve skeleton

```python
#!/usr/bin/env python3
"""Minimal web3.py solve loop: read state, send one transaction, verify."""
import os
import sys

from eth_account import Account
from web3 import Web3

RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
PK = os.environ.get("PRIVATE_KEY", "0x" + "11" * 32)
SETUP = os.environ.get("SETUP")

SETUP_ABI = [
    {"name": "isSolved", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"type": "bool"}]},
    {"name": "TARGET", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"type": "address"}]},
]


def send(w3: Web3, acct, to: str, data: bytes = b"", value: int = 0, gas: int = 500_000):
    tx = {
        "from": acct.address,
        "to": Web3.to_checksum_address(to),
        "data": data,
        "value": value,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": gas,
        "gasPrice": w3.eth.gas_price or 1,
    }
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    return w3.eth.wait_for_transaction_receipt(h, timeout=180)


def main() -> int:
    w3 = Web3(Web3.HTTPProvider(RPC))
    if not w3.is_connected():
        print(f"[-] cannot reach {RPC}")
        return 1
    acct = Account.from_key(PK)
    print(f"[+] chain {w3.eth.chain_id}  me {acct.address}  "
          f"balance {w3.from_wei(w3.eth.get_balance(acct.address), 'ether')} ETH")

    if not SETUP:
        print("[!] set SETUP to run the full flow")
        return 0

    setup = w3.eth.contract(address=Web3.to_checksum_address(SETUP), abi=SETUP_ABI)
    target = setup.functions.TARGET().call()
    print(f"[+] target {target}  solved={setup.functions.isSolved().call()}")

    # ---- exploit transactions go here ----
    # send(w3, acct, target, data=..., value=...)

    solved = setup.functions.isSolved().call()
    print(f"[{'+' if solved else '-'}] isSolved() = {solved}")
    return 0 if solved else 2


if __name__ == "__main__":
    sys.exit(main())
```
