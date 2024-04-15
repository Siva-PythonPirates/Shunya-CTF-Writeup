# Shunya-CTF-Writeup ~ Team Access Denied

## Medium Challenges

### 1. Rivest Salted Adleman
#### Approach :
1) This is a RSA problem. There'll be p,q and e given. But here, p was given and q was XOR-ed with some value which resulted in salted_q.Generally p*q = n ,but in this case it was p*salted_q which was salted_n and then e value was the standard value (65537). <br>
2) Now we need to find 'q'. The description hinted that 'q' was XOR-ed with and number anywhere between 1-9 or it was XOR-ed with 123456789. Therefore I tried both the combination and found out it was 123456789. XOR-ing salted_q with that would give the actual 'q'. Now we have all the values required to calculate the 'n', 'phi' and 'd'. 
#### CODE
```
from pwn import *
from Crypto.Util.number import inverse,long_to_bytes
p = "95224848836921243754124073456831190902097637702298493988505946669357481749059"
salted_q = "62480590829144807189161429469255353976579455660965599518063804867866301233320"
c = "332390996033761218977578960091058900061139210257883065481008023465866203213646838419152404854307189904898248026722555965488045307811040694129009535565921"
e = 65537

c = int(c)
p = int(p)
salted_q = int(salted_q)
for i in range(0,1):
        q = salted_q ^ 123456789
        try:
                n = p * q
        except Exception:
                continue
        phi = (p-1) * (q-1)
        d = inverse(e,phi)
        new = pow(c,d,n)
        print(long_to_bytes(new),end="\n")
```

### 2. Echoes of Encryption
#### Approach
1) Required : A seed value <br>
2) The description hinted about the Nvidia SMC vulnerability (2022). 2CVE's resulted in the google search of the vulnerability and the seed value was one of the CVE numbers '202242269' <br>
#### CODE for reference
```
import string
import random

def decrypt_string(encrypted_hex_string, seed):
    random.seed(seed)
    allowed_chars = string.ascii_letters + string.digits
    encrypted_bytes = bytes.fromhex(encrypted_hex_string)
    encrypted_string = encrypted_bytes.decode()
    key = ''.join(random.choices(allowed_chars, k=len(encrypted_string)))
    decrypted_string = ''
    for i in range(len(encrypted_string)):
        decrypted_char = chr(ord(encrypted_string[i]) ^ ord(key[i]))
        decrypted_string += decrypted_char
    return decrypted_string
for i in range(1,100000000000):
        d = decrypt_string("5e04610a22042638723c571e1a5436142764061f39176b4414204636251072220a35583a60234d2d28082b",202242269)
        if '0CTF{' in d or 1==1:
                print(d)
        break
```


### 3. AESthetic
#### Approach
1) 2 .wav files were give. Uploading them in https://morsecode.world/international/decoder/audio-decoder-adaptive.html to extract us the message from the hidden beeps, we would be getting the IV and key. The key is 'YOUGOTHTEKEYNJOY'. The IV extracted is 0X000102030405060708090A0B0C0D0E0F and the cipher text is 69d5deb91a001151db5d98231574a51779acd1a84b9338a6750697c0af7e4591.We could simply use online decoders to decode it futhter.

#### Screenshot - AESthetic
![image](https://github.com/Siva-PythonPirates/Shunya-CTF-Writeup/blob/main/ss1.png)

### 4. Uncover the Tea
#### Approach
1) By googling "rap stars whose fight started from tweets and now has a massive bump on forehead", fetched some articles. <br>
2) https://heatworld.com/celebrity/news/cardi-b-nicki-minaj-fight-nyfw-party/ this article was about Cardi B's and Nicki Minaj's fight at the NYFW. Hence the flag turned out to be 0CTF{NYFW_2018_Cardi_Minaj}.

### 5.The Vanishing of Doctor Kumar
#### Approach
1) An mp4 file was given. <br>
2) Loading it in Sonic visualizer and adding the spectogram from the pane menu would show us the flag.

#### Screenshot - Dr.Kumar
![image](https://github.com/Siva-PythonPirates/Shunya-CTF-Writeup/blob/main/ss2.png)

### 6.BIBBA Part 3

1) 23.23, 89.04 were the coords required which were found by simple googling, but this was the final flag.

### 7. Check Recheck and Check

1) Just edited the corrupted headers using hexeditor and got the flag

#### Screenshot - Check Recheck and Check
![image](https://github.com/Siva-PythonPirates/Shunya-CTF-Writeup/blob/main/ss3.jpeg)

## HARD CHALLENGE

### DRUG INJECTION
#### Approach
1) This website is prone to sql injection in the '/login.php' endpoint. <br>
2) Captured the '/login.php' POST request with burpsuite and saved it to a txt file. Found 2 injectable endpoints (username and password). Ran an SQLMAP scan sqlmap -r drug_injection.txt --dump <br>
3) This dumped all the tables contents and found that the password for the admin user was the flag.
