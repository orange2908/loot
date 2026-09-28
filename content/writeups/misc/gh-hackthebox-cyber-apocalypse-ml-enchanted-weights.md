---
title: "ml enchanted weights - cyber apocalypse 2025"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "enchanted", "weights", "miscellaneous", "ml-enchanted-weights", "cyber-apocalypse"]
summary: "misc writeup for \"ml enchanted weights\" from cyber apocalypse - techniques: enchanted, weights, miscellaneous, ml-enchanted-weights, cyber-apocalypse."
source:
  name: "hackthebox/cyber-apocalypse-2025"
  url: "https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/machine_learning/ml_enchanted_weights/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2025
  challenge: "ml enchanted weights"
---

## Source

- **CTF:** cyber apocalypse 2025
- **Challenge:** ml enchanted weights
- **Repository:** [hackthebox/cyber-apocalypse-2025](https://github.com/hackthebox/cyber-apocalypse-2025)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/machine_learning/ml_enchanted_weights/README.md>

---
# Runebound Secret

## Description
* In the depths of Eldoria's Crystal Archives, you've discovered a mystical artifact—an enchanted neural crystal named eldorian_artifact.pth. Legends speak of a hidden incantation—an ancient secret flag—imbued directly within its crystalline structure.

## Objective
* Participants must inspect the given neural model artifact (eldorian_artifact.pth) to uncover and decode a hidden message embedded within its weights. The task is to load and analyze the model to retrieve the secret incantation (flag).

## Difficulty
`Easy`

## Flag
`HTB{Cry5t4l_RuN3s_0f_Eld0r1a}`

## Challenge
* Participants are provided with a PyTorch neural network model file named eldorian_artifact.pth. The model has been specifically constructed with weights encoding a secret message in ASCII format. Participants must inspect and decode these weights to obtain the hidden flag.

## Solver

### Step 1: Loading the Artifact
First, you need to load the model artifact using PyTorch to inspect its structure and weights.

```
import torch

model = SecretModel()
model.load_state_dict(torch.load("eldorian_artifact.pth"))
```

### Step 2: Inspecting and Decoding the Weights
After loading, you should inspect the weights of the model's hidden layer to decode the secret ASCII-encoded message.
The decoded output reveals the flag: `Flag: HTB{Cry5t4l_RuN3s_0f_Eld0r1a}`

```
# Extract the diagonal weights
weights = model.hidden.weight.detach().numpy()
print(weights)
ascii_values = weights.diagonal().astype(int)

# Decode ASCII to characters
flag = ''.join(chr(x) for x in ascii_values)
print("Flag:", flag)
```
