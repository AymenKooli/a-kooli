---
title: FwordCTF 2020 | Sign it!
subtitle: ECDSA nonce bias exploitation
date: 2020-09-10T16:32:40.283Z
draft: false
featured: false
tags:
  - Cryptography
  - ECDSA
  - Signatures
  - Private Key Recovery
  - Nonce
  - Biais
image:
  filename: signit-1.png
  focal_point: Smart
  preview_only: false
---
# Description
## 500 points (6 solves)
## nc signit.fword.wtf 1337
**Author:** `KOOLI`

# Overview

 ![](signit-1.png)
 
 Connecting to the provided nc service we can see we have two possibilities:
 1. See available commands:
  - ls
  - cat run.py
2. Execute command:
  - ls :
    - `flag.txt` `run.py`
