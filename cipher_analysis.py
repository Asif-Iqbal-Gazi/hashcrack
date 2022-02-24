"""
cipher_analysis.py - Frequency analysis toolkit for breaking substitution ciphers.

Reads an encrypted text file and provides utilities to:
  - Analyse letter and word frequency distributions
  - Incrementally substitute cipher letters with guessed plaintext equivalents
  - Print the current key mapping

Usage:
    python cipher_analysis.py <encrypted_file>

    Edit the `analysis()` function to build your substitution key step by step
    as you identify more letter mappings.
"""

import sys
import os
import argparse


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

PUNCTUATION = '''!()-[]{};:'"\,<>./?@#$%^&*_~'''


def remove_punctuation(text: str) -> str:
    for c in PUNCTUATION:
        text = text.replace(c, "")
    return text


def letter_frequency(text: str) -> dict:
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: x[1]))


def word_frequency(text: str, length=None) -> dict:
    freq = {}
    for w in text.split():
        if length is not None and len(w) != length:
            continue
        freq[w] = freq.get(w, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: x[1]))


def substitute(text: str, key: dict) -> str:
    mapping = {}
    for f, t in zip(key["from"], key["to"]):
        mapping[f] = t
    return "".join(mapping.get(c, c) for c in text)


def print_key(key: dict):
    print("Key mapping:")
    for f, t in zip(key["from"], key["to"]):
        print(f"  {f} --> {t}")


# ---------------------------------------------------------------------------
# Interactive analysis session
# ---------------------------------------------------------------------------

def analysis(cipher_text: str):
    """
    Step-by-step substitution cipher analysis.

    Uncomment / extend each block as you discover new letter mappings.
    Reference for English letter frequencies:
        https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    """
    clean = remove_punctuation(cipher_text)

    # Step 1: inspect letter frequency
    print("=== Letter frequency (ascending) ===")
    for letter, count in letter_frequency(clean).items():
        print(f"  {count:>4}  {letter}")

    # Step 2: inspect all-word frequency
    # print("\n=== Word frequency ===")
    # for word, count in word_frequency(clean).items():
    #     print(f"  {count:>4}  {word}")

    # Step 3: incrementally build key and preview substitution
    # Uncomment and extend the key as you identify mappings:
    #
    # key = {"from": "n", "to": "e"}
    # print(substitute(cipher_text, key))
    #
    # key = {"from": "ns", "to": "ea"}
    # print(substitute(cipher_text, key))
    #
    # ... keep adding letters until the text reads naturally ...

    # Final key (example — replace with your discovered mapping):
    # key = {"from": "scztvnywxdfurqjogikhlme", "to": "atofhervwisdmclnbgypuxk"}
    # print(substitute(cipher_text, key))
    # print_key(key)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Frequency analysis toolkit for substitution cipher breaking."
    )
    parser.add_argument("encrypted_file", help="Path to the encrypted text file")
    args = parser.parse_args()

    if not os.path.isfile(args.encrypted_file):
        print(f"[!] File not found: {args.encrypted_file}")
        sys.exit(1)

    with open(args.encrypted_file) as f:
        cipher_text = f.read()

    analysis(cipher_text)


if __name__ == "__main__":
    main()
