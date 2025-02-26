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
Download letest bitcon address with balance
here : http://addresses.loyce.club/

gunzip Bitcoin_addresses_LATEST.txt.gz

```
$ python3 btc-mnemonic.py -r Bitcoin_addresses_LATEST.txt -o win.txt -t 4
- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
[4] Compressed    : 1AZq6BRbEis7RkSXWMZTgHG9uH818ixUv7
[4] UnCompressed  : 15y9jUUFjbL4pj33N8GB3UxeJ1FRAWsUmS 
[4] P2SH          : 33WWG6dKrVLpcAws1yzb1wrc7L1Yzd3pnA
[4] Bech32/Segwit : bc1qdrhftarlzhxqgfuekd6fysskv0ntz62wrk8d7e
[4] PrivateKey    : 5bcddecec4abbd91713b63666ba1c9452928b6a7167ab50f68c600a11d0b8ee0
[4] Mnemonic      : tone coyote august cruise speak mechanic industry lunch stone joy regular ugly
- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
[8] Compressed    : 1Bi5iSCnYDxbr3QBb7V7Xq1eo7vX41Scuf
[8] UnCompressed  : 1NkNGKSjqzYWTKfLSkj5UX1QcQjsgi1pJm 
[8] P2SH          : 3Ev9DuBmkWvtDQZRmxUJTgYzqLdXiNurpH
[8] Bech32/Segwit : bc1qw4mr7edp7nysv3y8flf8kwq2kmr90lj0ta2n9l
[8] PrivateKey    : f1e614fa1424ed7a262b812142ccf44a717c3c4fd5e4401b091485fda52f19b4
[8] Mnemonic      : accuse depend aerobic canal hedgehog brass satoshi valve off room explain country
```

if have problem with "ValueError: unsupported hash type ripemd160" (just for python3)
check here : https://stackoverflow.com/questions/72409563/unsupported-hash-type-ripemd160-with-hashlib-in-python


