"""
hashcrack.py - Dictionary-based password hash cracker.

Supports MD5, SHA1, SHA256, and SHA512 hashes (including salted SHA256/SHA512).
Applies common pre-hash encoding transforms: leetspeak, Caesar cipher, and
substitution ciphers.

Usage:
    python hashcrack.py <username> [options]

    The script expects a 'shadow' file and a 'dictionary.txt' in the same
    directory (or pass paths via --shadow / --dict flags).

Shadow file format:
    username:hash

Dictionary file format:
    one_password_per_line
"""

import sys
import os
import hashlib
import argparse
from collections import OrderedDict


# ---------------------------------------------------------------------------
# File loading helpers
# ---------------------------------------------------------------------------

def load_file_lines(path: str, label: str) -> list:
    if not os.path.isfile(path):
        print(f"[!] Error: {label} not found at '{path}'")
        sys.exit(1)
    with open(path) as f:
        return f.read().splitlines()


def load_shadow(path: str) -> dict:
    lines = load_file_lines(path, "shadow file")
    return dict(item.split(":", 1) for item in lines if ":" in item)


# ---------------------------------------------------------------------------
# Hash detection
# ---------------------------------------------------------------------------

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def detect_hash_type(hash_str: str) -> str:
    return HASH_LENGTHS.get(len(hash_str), "unknown")


# ---------------------------------------------------------------------------
# Hash comparison functions
# ---------------------------------------------------------------------------

def _try_hash(password: str, target: str, algorithm: str) -> bool:
    h = hashlib.new(algorithm, password.encode()).hexdigest()
    return h == target


def crack_plain(pass_list: list, target: str, algorithm: str) -> str:
    for pw in pass_list:
        if 5 <= len(pw) <= 12 and _try_hash(pw, target, algorithm):
            return pw
    return None


def crack_salted_sha256(pass_list: list, target: str) -> str:
    """Try salted SHA256: password + zero-padded 5-digit numeric salt."""
    for pw in pass_list:
        if not (5 <= len(pw) <= 12):
            continue
        for s in range(10 ** 6):
            salt = str(s).zfill(5)
            h = hashlib.sha256((pw + salt).encode()).hexdigest()
            if h == target:
                return pw
    return None


# ---------------------------------------------------------------------------
# Encoding transform functions
# ---------------------------------------------------------------------------

def leetspeak_encode(pass_list: list) -> list:
    key_map = {
        "a": "4", "b": "8", "e": "3", "g": "6", "i": "1",
        "o": "0", "s": "5", "t": "7",
        "A": "4", "B": "8", "E": "3", "G": "6", "I": "1",
        "O": "0", "S": "5", "T": "7",
    }
    result = []
    for w in pass_list:
        result.append("".join(key_map.get(c, c) for c in w))
    return result


def caesar_encode(pass_list: list, shift: int) -> list:
    result = []
    for w in pass_list:
        encoded = ""
        for c in w:
            if not c.isdigit():
                encoded += chr((ord(c) + shift - 65) % 58 + 65)
            else:
                encoded += chr((ord(c) + shift - 48) % 10 + 48)
        result.append(encoded)
    return result


def substitution_encode(pass_list: list, encode_key: str, decode_key: str) -> list:
    key_map = {}
    for e, d in zip(encode_key, decode_key):
        key_map[e] = d
    for e, d in zip(encode_key.upper(), decode_key.upper()):
        key_map[e] = d

    result = []
    for w in pass_list:
        if not (5 <= len(w) <= 12):
            continue
        decoded = "".join(key_map.get(c, c) for c in w)
        result.append(decoded)
    return result


# ---------------------------------------------------------------------------
# Main cracking logic
# ---------------------------------------------------------------------------

def crack(username: str, hash_dic: dict, pass_list: list, salt: bool, sub_key: dict) -> str:
    target = hash_dic.get(username)
    if not target:
        print(f"[!] Username '{username}' not found in shadow file.")
        sys.exit(1)

    algorithm = detect_hash_type(target)
    if algorithm == "unknown":
        print(f"[!] Unrecognised hash length ({len(target)} chars) for '{username}'.")
        sys.exit(1)

    print(f"[*] Detected algorithm : {algorithm.upper()}")
    print(f"[*] Starting crack for : {username}")

    # 1. Plain dictionary
    found = crack_plain(pass_list, target, algorithm)
    if found:
        return found

    # 2. Leetspeak transform
    leet_list = leetspeak_encode(pass_list)
    found = crack_plain(leet_list, target, algorithm)
    if found:
        return found

    # 3. Caesar cipher (shifts 1–57)
    for shift in range(1, 58):
        shifted = caesar_encode(pass_list, shift)
        found = crack_plain(shifted, target, algorithm)
        if found:
            return found

    # 4. Substitution cipher (if key provided)
    if sub_key:
        sub_list = substitution_encode(pass_list, sub_key["encode"], sub_key["decode"])
        found = crack_plain(sub_list, target, algorithm)
        if found:
            return found

    # 5. Salted SHA256 (numeric 5-digit salt)
    if salt and algorithm == "sha256":
        found = crack_salted_sha256(pass_list, target)
        if found:
            return found

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Dictionary-based password hash cracker (MD5/SHA1/SHA256/SHA512)."
    )
    parser.add_argument("username", help="Target username to crack")
    parser.add_argument("--shadow", default="shadow", help="Path to shadow file (default: ./shadow)")
    parser.add_argument("--dict", dest="dictionary", default="dictionary.txt",
                        help="Path to dictionary file (default: ./dictionary.txt)")
    parser.add_argument("--salt", action="store_true",
                        help="Attempt salted SHA256 cracking (numeric 5-digit salt, slow)")
    parser.add_argument("--sub-encode", dest="sub_encode", default=None,
                        help="Substitution cipher encode key (use with --sub-decode)")
    parser.add_argument("--sub-decode", dest="sub_decode", default=None,
                        help="Substitution cipher decode key (use with --sub-encode)")
    args = parser.parse_args()

    hash_dic = load_shadow(args.shadow)
    pass_list = load_file_lines(args.dictionary, "dictionary file")

    sub_key = None
    if args.sub_encode and args.sub_decode:
        sub_key = {"encode": args.sub_encode, "decode": args.sub_decode}

    result = crack(args.username, hash_dic, pass_list, args.salt, sub_key)

    if result:
        print(f"[+] Found password for '{args.username}': {result}")
    else:
        print(f"[-] Password not found for '{args.username}'.")


if __name__ == "__main__":
    main()
