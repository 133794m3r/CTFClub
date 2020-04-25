# The challenges are below.
The challenge below is similar to one that appeared at the NCL this season in the individual game.
## Challenge #1
You were able to intercept the following information from your contact. The message was encrypted using the RSA system.

n = 803

e = 97

You need to decrypt the message below by applying RSA to it.
Each item below needs to be decrypted seperately(as a free hint).

520, 448, 65, 329, 767, 498, 329, 498, 767, 142, 744, 499, 517, 329, 142, 389, 481, 597, 264

Your contact tells you to remember Euler's Method to calculate the modular implicative inverses. 
aka x = [a]**-1 (mod n). Where x is the modular multplicative inverse of a and n.
Euler found that you're able to find it by doing the following.

** means raised to the power of. And mod is of course the modulus operator.

x = a ** TOTIENT(N) (mod TOTIENT(N))

Where TOTIENT is either euler's totient function(euler's Phi) or 
carmichael's totient (My paper used carmichael's totient function)
Use the paper below if you need extra help.

https://github.com/133794m3r/Papers/blob/master/crypto/RSA_LAB_1.pdf

### Hashes 
#### sha1
a59c83fb11bc27ab38c8d9d662edfb54d6d30d02

#### md5
1d6d19c8136fd65277c5ddb18e3a3206

## Challenge #2
104, 524, 41, 417, 109, 182, 451, 524, 417, 175, 260, 417, 260, 175, 109, 267, 108, 41, 417, 175, 260, 110, 384, 451, 417, 175, 451, 33

e=41

n=545

The hash for the flag this time is.
### Hashes

#### md5
fc242b7781d3dea335ca1e406a687522

#### sha1
30494620547ac778063612de2b3b9c6b7b3cc631

## Code Checkers
### Bash
```BASH
hash_flag(){ [ $(echo -n "$1" | sha1sum | cut -d' ' -f1) = "$2" ] && echo "You got the flag!" || echo "You didn't get the flag.";}
```
Use it like so.
```BASH
hash_flag "{THE_FLAG_YOU_GOT}" "a59c83fb11bc27ab38c8d9d662edfb54d6d30d02"
```
### PowerShell
For those of you with the misfortune to have to deal with powershell here's that function.
```PowerShell
function check-flag{
param($flag,$test_hash,$hash_type='SHA1');
if($hash_type.toLower() -eq 'md5'){$hasher=New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider}
else{$hasher=New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider};
$utf8 = New-Object -TypeName System.Text.UTF8Encoding;
("Sorry that's not the right answer.","That's the correct flag!")[$test_hash -eq ([System.BitConverter]::ToString($hasher.ComputeHash($utf8.GetBytes($flag))) -replace '-','')  ]
}
```
Use it like so
```PowerShell
check-flag "{THE_FLAG}" "{THE_HASH}" #optional the type of hash sha1 or md5.
```

###Python
For those of you who have python installed.
```Python
import hashlib;
def check_hash(flag,test_hash,hash_type='md5'): hasher=( hashlib.md5 if hash_type == 'md5' else hashlib.sha1); return 'You got the flag' if hasher(flag.encode('utf-8')).hexdigest() == test_hash else "You didn't get the flag"
```

To use it you'd simply
```Python
check_hash("THE_FLAG","HASH_TO_TEST","OPTIONAL_CHOSEN_HASH_DEFAULTS_TO_MD5")
```

And if they give back to you "You got the flag then it's working.


### Math Divisibility Rules
[Math Tricks GCD/LCM and Divisbility Rules](https://github.com/133794m3r/Papers/blob/master/education/Math%20Tricks.pdf)
The paper linked to includes divisibility rules along with how to calculate LCM and GCD w/o having to do it the hard way as you learned in school By using some basic math as laid out in te papers above you can do both challenges w/o having to write any real code. It's entirely doable by hand as I intended.
