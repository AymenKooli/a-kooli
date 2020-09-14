---
title: CSAW CTF 2020 QUALS | Crypto
subtitle: All Crypto tasks for CSAW 2020 QUALS
date: 2020-09-13T23:56:00.000Z
draft: false
featured: false
tags:
  - Cryptography
  - CSAW
  - AES CTR
  - hash length extension
  - Shamir Secret Sharing
image:
  filename: c.png
  focal_point: Smart
  preview_only: false
---

I played with Fword Team in CSAW CTF Qualification Round 2020 and managed to solve all the crypto tasks :partying_face:
![](c.png)

To be honnest, I think the tasks were poorly designed and guessy. In this article, I'll provide writeups for:

  - [x] difib
  - [x] modus_operandi
  - [x] authy
  - [x] adversarial
  - [x] smallsurp

# difib
![](difib.png)

> Hints 
>  1. Length of keys is 25, which (cleaned-up) ramblings would fit that?
>  2. If near-perfect ramblings are used to encrypt in order, how should it be decrypted?
>  3. The guard want's a legible message they can read in!
  
From the challenge's title we can guess that this is going to be about **[bifid cipher]**(https://en.wikipedia.org/wiki/Bifid_cipher). We will need to decode the message give: `snbwmuotwodwvcywfgmruotoozaiwghlabvuzmfobhtywftopmtawyhifqgtsiowetrksrzgrztkfctxnrswnhxshylyehtatssukfvsnztyzlopsv` using a key from the ramblings given:
```
Mr. Jock, TV quiz PhD., bags few lynx
Two driven jocks help fax my big quiz.
Jock nymphs waqf drug vex blitz
Fickle jinx bog dwarves spy math quiz.
Crwth vox zaps qi gym fjeld bunk
Public junk dwarves hug my quartz fox.
Quick fox jumps nightly above wizard.
Hm, fjord waltz, cinq busk, pyx veg
phav fyx bugs tonq milk JZD CREW
Woven silk pyjamas exchanged for blue quartz.
The quick onyx goblin jumps over the lazy dwarf.
Foxy diva Jennifer Lopez wasn’t baking my quiche.
he said 'bcfgjklmnopqrtuvwxyz'
Jen Q. Vahl: bidgum@krw.cfpost.xyz
Brawny gods just flocked up to quiz and vex him.
Emily Q Jung-Schwarzkopf XTV, B.D.
My girl wove six dozen plaid jackets before she quit.
John 'Fez' Camrws Putyx. IG: @kqBlvd
Q-Tip for SUV + NZ Xylem + DC Bag + HW?....JK!
Jumbling vext frowzy hacks pdq
Jim quickly realized that the beautiful gowns are expensive.
J.Q. Vandz struck my big fox whelp
How razorback-jumping frogs can level six piqued gymnasts!
Lumpy Dr. AbcGQVZ jinks fox thew
Fake bugs put in wax jonquils drive him crazy.
The jay, pig, fox, zebra, and my wolves quack!
hey i am nopqrstuvwxzbcdfgjkl
Quiz JV BMW lynx stock derp. Agh! F.
Pled big czar junks my VW Fox THQ
The big plump jowls of zany Dick Nixon quiver.
Waltz GB quick fjords vex nymph
qwertyuioplkjhgfdsazxcvbnm
Cozy lummox gives smart squid who asks for job pen.
zyxwvutsrqponmlkjihgfedcba
Few black taxis drive up major roads on quiet hazy nights.
a quick brown fx jmps ve th lzy dg
Bored? Craving a pub quiz fix? Why, just come to the Royal Oak!```

