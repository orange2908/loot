---
title: "Random Notes (Blockchain)"
category: "blockchain"
subcategory: "smart-contract"
type: "technique"
tags: ["my-notes", "personal", "solidity", "random", "notes", "blockchain"]
summary: "https://www.aon.com/cyber-solutions/aoncyberlabs/breaking-randomness-in-the-ethereum-universe-part-1/"
source:
  name: "Personal notes"
origin_path: "Blockchain/Random Notes.md"
---

- Within the blockchain, even private variables are readable by everyone, even if the contract does not directly expose them
## block.timestamp
- Breaking Randomness In The Ethereum Universe : 
https://www.aon.com/cyber-solutions/aon_cyber_labs/breaking-randomness-in-the-ethereum-universe-part-1/

- https://www.youtube.com/watch?v=8FF3IBTMeK0&ab_channel=SmartContractProgrammer

- https://github.com/ethereumbook/ethereumbook/blob/develop/09smart-contracts-security.asciidoc
### access private data
- https://solidity-by-example.org/hacks/accessing-private-data/
### get passphrase
```python
>>> from web3 import Web3
>>> w3 = Web3(Web3.HTTPProvider("http://157.245.37.125:32572/rpc"))
>>> w3
<web3.main.Web3 object at 0x7f64822cd120>
>>> w3.is_connected()
True
>>> passphrase = w3.eth.get_storage_at("0x0AaA216D48d49391B04EE72ccfCfDEf832d39122",2)
>>> passphrase
HexBytes('0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563')
```
### general resources
- https://solidity-by-example.org/
- https://consensys.github.io/smart-contract-best-practices/security-tools/
- https://kbaiiitmk.medium.com/code-analysis-tools-for-solidity-smart-contracts-an-overview-b3642939c195

---

*From your own notes: `Blockchain/Random Notes.md`*
