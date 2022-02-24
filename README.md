# HashCrack

A dictionary-based password hash cracker and substitution cipher analysis toolkit written in Python.

## Tools

| Script | Description |
|--------|-------------|
| `hashcrack.py` | Crack password hashes from a shadow file using a wordlist |
| `cipher_analysis.py` | Frequency analysis assistant for breaking substitution ciphers |

---

## `hashcrack.py`

Automatically detects the hash algorithm (MD5, SHA1, SHA256, SHA512) by hash length and attempts to recover the plaintext password using:

- **Plain dictionary** lookup
- **Leetspeak** encoding (`a→4`, `e→3`, `o→0`, etc.)
- **Caesar cipher** shifts (1–57)
- **Substitution cipher** (provide your own key with `--sub-encode` / `--sub-decode`)
- **Salted SHA256** (5-digit zero-padded numeric salt, opt-in with `--salt`)

### Shadow file format

```
alice:5f4dcc3b5aa765d61d8327deb882cf99
bob:e10adc3949ba59abbe56e057f20f883e
```

### Dictionary file format

One password candidate per line.

### Usage

```bash
# Auto-detect hash type, try all transforms
python3 hashcrack.py alice

# Use custom file paths
python3 hashcrack.py bob --shadow /etc/shadow.bak --dict rockyou.txt
# Enable salted SHA256 brute-force (slow)
python3 hashcrack.py charlie --salt

# Supply a substitution cipher key
python3 hashcrack.py dave \
    --sub-encode "atofhervwisdmclnbgypuxk" \
    --sub-decode "scztvnywxdfurqjogikhlme"
```

---

## `cipher_analysis.py`

An interactive frequency-analysis tool for breaking monoalphabetic substitution ciphers.

1. Prints letter frequency distribution of the ciphertext.
2. Lets you incrementally build a substitution key in the `analysis()` function and preview the partially decrypted text until it reads naturally.

### Usage

```bash
python cipher_analysis.py secret.txt
```

Then open `cipher_analysis.py` and uncomment/extend the key blocks inside `analysis()` as you discover mappings.

### Useful reference

English letter frequency order: `e t a o i n s h r d l c u m w f g y p b v k j x q z`

---

## Requirements

Python 3.8+ — no external dependencies.

---

## Notes

- The cracker assumes password lengths between 5 and 12 characters.
- Salted SHA256 mode generates all 5-digit zero-padded salts (0–999999) per dictionary word — this can be slow on large wordlists.
- Use only on hashes you are authorised to test.

## License

MIT
