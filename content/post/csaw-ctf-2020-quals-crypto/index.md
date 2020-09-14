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
Bored? Craving a pub quiz fix? Why, just come to the Royal Oak!
```
For bifid cipher, they key needs to be a perfect pangram with 25 chars long. A perfect pangram is a sentence that uses each letter of the alphabet only one time. 
We can see in our encrypted message that the letter '***j***'  isn't used. That will help us deduce that key doesn't have the letter '***j***' . From the first hint, we have clean up the ramblings, so first of all we will remove every non-alphabetic char and the letter j. With every thing cleaned-up we will have 20 possible keys: 
```
mrocktvquizphdbagsfewlynx
ocknymphswaqfdrugvexblitz
crwthvoxzapsqigymfeldbunk
hmfordwaltzcinqbuskpyxveg
phavfyxbugstonqmilkzdcrew
hesaidbcfgklmnopqrtuvwxyz
enqvahlbidgumkrwcfpostxyz
emilyqungschwarzkopfxtvbd
ohnfezcamrwsputyxigkqblvd
qtipforsuvnzxylemdcbaghwk
umblingvextfrowzyhackspdq
qvandzstruckmybigfoxwhelp
lumpydrabcgqvzinksfoxthew
heyiamnopqrstuvwxzbcdfgkl
quizvbmwlynxstockderpaghf
pledbigczarunksmyvwfoxthq
waltzgbquickfordsvexnymph
qwertyuioplkhgfdsazxcvbnm
zyxwvutsrqponmlkihgfedcba
aquickbrownfxmpsvethlzydg
```
I've tried using each one of them but none worked. Then, I tried using all the keys inverted and successively and got the message.

`xustxsomexunnecessaryxtextxthatxholdsxabsolutelyxnoxmeaningxwhatsoeverxandxbearsxnoxsignificancextoxyouxinxanyxway`

Cleaning up that message we will have: 

`just some unnecessary text that holds absolutely no meaning whatsoever and bears no significance to you in any way`

Sending that to the server gives us the flag.

![](bifid-0.png)

```python
from secretpy import Bifid
from secretpy import CryptMachine

def encdec(machine, enc):
    dec = machine.decrypt(enc)
    print (dec)
    print("----------------------------------")
    return dec

encrypted = "snbwmuotwodwvcywfgmruotoozaiwghlabvuzmfobhtywftopmtawyhifqgtsiowetrksrzgrztkfctxnrswnhxshylyehtatssukfvsnztyzlopsv"
dict = open("plz","r").readlines()[::-1]
for k in dict:
	k = k.strip()
	cipher = Bifid()
	alphabet = []
	for i in k:		
		alphabet.append(i)
	cm = CryptMachine(Bifid(), 5)
	cm.set_alphabet(alphabet)
	encrypted = encdec(cm,encrypted)
```

### Flag: flag{t0ld_y4_1t_w4s_3z}

# modus_operandi
![](modus.png)

> Hint
> <200

Connecting to the nc service we are asked to find out if the block cipher used is ECB or CBC. 

![](modus-0.png)

It's easy to determine if the block cipher used is ECB or CBC from the ciphertext since we control the plaintext. Since ECB mode encrypts every 16 bytes block independently, two equal plaintext blocks shall result in two equal ciphertext blocks. The problem here is when all queries answered correctly the server doesn't send the flag :frowning_face: . So we have to store our answers and convert them to binary with ECB standing for 0 and CBC standing for 1.

![](modus-1.png)

```python
from pwn import remote
from Crypto.Util.number import long_to_bytes

p = remote("crypto.chal.csaw.io",5001)
flag = ""
p.recvline()
for _ in range(176):
	line = p.recvline()
	p.sendline("A"*32)
	data = p.recvline().strip()
	if "Ciphertext" not in data:
		p.interactive()

	print p.recvline()
	data=data.replace("Ciphertext is:  ","")
	if data[:32] == data[32:64]:
		print data, "ecb"
		flag += "0"
		p.sendline('ECB')
	else:
		print data ," cbc"
		p.sendline('CBC')
		flag += "1"
print long_to_bytes(int(flag,2))
p.close()
```

### FLAG: flag{ECB_re@lly_sUck$}

# authy
![](authy.png)

***handout.py*** 
```python
#!/usr/bin/env python3
import struct
import hashlib
import base64
import flask

# flag that is to be returned once authenticated
FLAG = ":p"

# secret used to generate HMAC with
SECRET = ":p".encode()

app = flask.Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    return """
This is a secure and private note-taking app sponsored by your favorite Nation-State.
For citizens' convenience, we offer to encrypt your notes with OUR own password! How awesome is that?
Just give us the ID that we generate for you, and we'll happily decrypt it back for you!

Unfortunately we have prohibited the use of frontend design in our intranet, so the only way you can interact with it is our API.

/new

    DESCRIPTION:
        Adds a new note and uses our Super Secure Cryptography to encrypt it.

    POST PARAMS:
        :author: your full government-issued legal name
        :note: the message body you want to include. We won't read it :)

    RETURN PARAMS:
        :id: an ID protected by password  that you can use to retrieve and decrypt the note.
        :integrity: make sure you give this to validate your ID, Fraud is a high-level offense!


/view
    DESCRIPTION:
        View and decrypt the contents of a note stored on our government-sponsored servers.

    POST PARAMS:
        :id: an ID that you can use to retrieve and decrypt the note.
        :integrity: make sure you give this to validate your ID, Fraud is a high-level offense!

    RETURN PARAMS:
        :message: the original unadultered message you stored on our service.
"""

@app.route("/new", methods=["POST"])
def new():
    if flask.request.method == "POST":

        payload = flask.request.form.to_dict()
        if "author" not in payload.keys():
            return ">:(\n"
        if "note" not in payload.keys():
            return ">:(\n"

        if "admin" in payload.keys():
            return ">:(\n>:(\n"
        if "access_sensitive" in payload.keys():
            return ">:(\n>:(\n"

        info = {"admin": "False", "access_sensitive": "False" }
        info.update(payload)
        info["entrynum"] = 783

        infostr = ""
        for pos, (key, val) in enumerate(info.items()):
            infostr += "{}={}".format(key, val)
            if pos != (len(info) - 1):
                infostr += "&"

        infostr = infostr.encode()

        identifier = base64.b64encode(infostr).decode()

        hasher = hashlib.sha1()
        hasher.update(SECRET + infostr)
        return "Successfully added {}:{}\n".format(identifier, hasher.hexdigest())


@app.route("/view", methods=["POST"])
def view():

    info = flask.request.form.to_dict()
    if "id" not in info.keys():
        return ">:(\n"
    if "integrity" not in info.keys():
        return ">:(\n"

    identifier = base64.b64decode(info["id"]).decode()
    checksum = info["integrity"]

    params = identifier.replace('&', ' ').split(" ")
    note_dict = { param.split("=")[0]: param.split("=")[1]  for param in params }

    encode = base64.b64decode(info["id"]).decode('unicode-escape').encode('ISO-8859-1')
    hasher = hashlib.sha1()
    print (encode)
    hasher.update(SECRET + encode)
    gen_checksum = hasher.hexdigest()

    print (checksum)
    print (gen_checksum)
    print (note_dict["entrynum"])

    if checksum != gen_checksum:
        return ">:(\n>:(\n>:(\n"

    try:
        entrynum = int(note_dict["entrynum"])
        if 0 <= entrynum <= 10:

            if (note_dict["admin"] not in [True, "True"]):
                return ">:(\n"
            if (note_dict["access_sensitive"] not in [True, "True"]):
                return ">:(\n"

            if (entrynum == 7):
                return "\nAuthor: admin\nNote: You disobeyed our rules, but here's the note: " + FLAG + "\n\n"
            else:
                return "Hmmmmm...."

        else:
            return """\nAuthor: {}
Note: {}\n\n""".format(note_dict["author"], note_dict["note"])

    except Exception:
        return ">:(\n"

if __name__ == "__main__":
    app.run()
```

![](authy-0.png)

In order to access the flag, we need turn admin=True & access_sensitive=True & entrynum=7.

The first two parameters can be easily exploited with url encoding:

![](authy-1.png)

The entrynum is set after the info update so we will use [hash_extender](https://github.com/iagox86/hash_extender) to append entrynum=7 in our payload.
```python
info = {"admin": "False", "access_sensitive": "False" }
        info.update(payload)
        info["entrynum"] = 783
```
Since we don't know the secret length the server is using we need to brute force that until we get our flag! We will get a valid signature for secret length = 13 !

![](authy-2.png)

### FLAG: flag{h4ck_th3_h4sh}

# adversarial
