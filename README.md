# BTC MNEMONIC 
## BTC Mnemonic For Hack and Cracking Private Key and Address Bitcoin Wallet From Mnemonic [Words - Passphrase]
---

### BTC Mnemonic
support Different Types of Bitcoin Addresses

example Types of Bitcoin Addresses:
```
Legacy (P2PKH)
(m/44'/0'/0'/0/0)
(m/49'/0'/0'/0/0)
(m/84'/0'/0'/0/0)
(m/86'/0'/0'/0/0)

compress   : 1HczCh7xqPZ6MwEKZSD3uJaqxkQSNQrN1j
uncompress : 1LK1ABYsodjKDwfXEYp7MGcntpjdnLWV57


SegWit (P2SH)
3EVhW3mJy8yVu5LNSiDxrJx2tQx7eV7aft

Bech32 (Native SegWit)
bc1qnycfpww07mjadmraawyeptvkzt0a0qqqakcxeh
```

python3 install modules
```
pip3 install bip32utils
pip3 install argparse
pip3 install mnemonic
pip3 install bit
```
in line 158, change "length = 12" for how many words you want.

Download letest bitcon address with balance
here : http://addresses.loyce.club/

gunzip Bitcoin_addresses_LATEST.txt.gz

```
$ python3 btc-mnemonic.py -r Bitcoin_addresses_LATEST.txt -o win.txt -t 4
- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
[662] HD wallet (m/44'/0'/0'/0/0) | Compressed : 1Bh7s4S4RNNWGhE384PeNS49Xvzmo2XMHF | Uncompressed  : 1Q3Cd9PqRLJkWV4aJkkweHiRpeqBsw3vme
[662] HD wallet (m/44'/0'/0'/0/0) | P2SH       : 33pFvpMTikDYn4wF7TEHLdAgb6U6biZ5vt | Bech32/Segwit : bc1qw4r6q9te6y8zz6yydm0yvp68m8de98xnu0q20e
[662] PrivateKey    : 669d353e6eb3f68bbfcd6996185f50fd0b3f74a6861bddf61dcc710d39c8c358
[662] HD wallet (m/49'/0'/0'/0/0) | Compressed : 1FnQSTPMkEDyHkLiesqvdpVHWmcG7Y9pRg | Uncompressed  : 12eEuWq9aBtdF37LzM4TjPdoK7mupiyp1m
[662] HD wallet (m/49'/0'/0'/0/0) | P2SH       : 33pFvpMTikDYn4wF7TEHLdAgb6U6biZ5vt | Bech32/Segwit : bc1q5g5qhplkazdwqf0j4sx3tlrtshmtaj6nl2nfy5
[662] PrivateKey    : 2d1adc872ed47f72e52747808e7e7c747f5bcc78e091e3c59d9700c5d11025bc
[662] HD wallet (m/84'/0'/0'/0/0) | Compressed : 1EY2sDoJhemvjCejgBWuoXQrVNyRcSMyEq | Uncompressed  : 14iDzvaq1TAfiBe1UERZnttMihdvbhjyNQ
[662] HD wallet (m/84'/0'/0'/0/0) | P2SH       : 33pFvpMTikDYn4wF7TEHLdAgb6U6biZ5vt | Bech32/Segwit : bc1qj3upv638l8rmy0f83frv30achftw809qqkatrg
[662] PrivateKey    : ab15d8b72b0381f0dbdfb684ffb3e92796a00faf893cef6c4be14b03427aa5a0
[662] HD wallet (m/89'/0'/0'/0/0) | Compressed : 1C1DtXED1uMJ4XELktfxPKkxCvxF8CrHUj | Uncompressed  : 1DQWYaTj2DFrdzgvcU1xq67YDatzHTT6zW
[662] HD wallet (m/89'/0'/0'/0/0) | P2SH       : 33pFvpMTikDYn4wF7TEHLdAgb6U6biZ5vt | Bech32/Segwit : bc1q0z6zg6fze8ktw52jyxjumqa0p0yysx5dxmxy07
[662] PrivateKey    : fee7b281f130f96eaf390edf8161fac3e448d52dd53d58753d7029878ddb1d6d
[662] Mnemonic      : true aware ceiling decrease unique boost birth space armor loop twenty spatial
- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -

[664] HD wallet (m/44'/0'/0'/0/0) | Compressed : 16ngNU9eV5nvkw4mt4zXRTEPhc7YroDq9h | Uncompressed  : 19khHZKcuY5cKT47K54C1X77btMRkzePFx
[664] HD wallet (m/44'/0'/0'/0/0) | P2SH       : 347wxWnWYvPhAXdKU2W3tCF4LGxPb1Z39t | Bech32/Segwit : bc1q8a7rvdrpvm54jgz3gc9qrfpm5pyg3xxqhyfgmr
[664] PrivateKey    : 50fda63f121ff449eb1bb599f1de5a9cb0aea6ddd404ccdb757508718db46642
[664] HD wallet (m/49'/0'/0'/0/0) | Compressed : 1FLjoa28bN9zxbQ9GUK9ier4LQU2fem35Z | Uncompressed  : 13ayWaZHVNmbZd5wW82SoTJMUF4Zfempo4
[664] HD wallet (m/49'/0'/0'/0/0) | P2SH       : 347wxWnWYvPhAXdKU2W3tCF4LGxPb1Z39t | Bech32/Segwit : bc1qn4xkfunsp3zzg2q8tuzjy6hyh2ww57nz5nhutu
[664] PrivateKey    : 5f57660dc38a31af15cb0d0d1120dfb0a68db6d3e8d853fe52a7035560746b70
[664] HD wallet (m/84'/0'/0'/0/0) | Compressed : 1CHL5CrDQrWSKdd91G4th25wJGJ95LkqdV | Uncompressed  : 17gKvjnxiBFipFTNT45aRvnr1Qu2NuwRvK
[664] HD wallet (m/84'/0'/0'/0/0) | P2SH       : 347wxWnWYvPhAXdKU2W3tCF4LGxPb1Z39t | Bech32/Segwit : bc1q0wllt0trax244rs2xewgcymmgxrcnd2a9w8mus
[664] PrivateKey    : 22a100ef155735f7ac5fd4fc7d87bae283a1402e59a46930cd7654f611a14509
[664] HD wallet (m/89'/0'/0'/0/0) | Compressed : 1CS9tbeR46mH6UCPrwdyZYs4bFXCnH6qBp | Uncompressed  : 1FMrLGAhcwbDdsUPGE3mtpHgidvtRyumXo
[664] HD wallet (m/89'/0'/0'/0/0) | P2SH       : 347wxWnWYvPhAXdKU2W3tCF4LGxPb1Z39t | Bech32/Segwit : bc1q044ngr06x9y6jn2j8m4eeep728n2d34ruc6klr
[664] PrivateKey    : dc12a8b5f91ca9c651f886a7949b243c1028adb52e571ed8f80b81a950a0f542
[664] Mnemonic      : cross estate rule thing bind bid oppose spoon arena place disorder ripple
```

if have problem with "ValueError: unsupported hash type ripemd160" (just for python3)
check here : https://stackoverflow.com/questions/72409563/unsupported-hash-type-ripemd160-with-hashlib-in-python


