#!/usr/bin/env python3
"""Writes channel-vectors.json, the filter channel test vectors (W9, spec v1).

It uses only Python's standard library, independently of the Go code it
tests (txfeed/channel.go):

    python3 txfeed/testdata/channel-vectors.py > txfeed/testdata/channel-vectors.json
"""
import hashlib
import ipaddress
import json

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DOMAIN = "blockcast/txfeed/channel/v1"
KINDS = {"program": 1, "account": 2}


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def group(kind, key):
    k = b58decode(key)
    assert len(k) == 32, key
    g = b"\xff\x3e\0\0" + hashlib.sha256(DOMAIN.encode() + bytes([KINDS[kind]]) + k).digest()[:12]
    return ipaddress.IPv6Address(g).compressed, g.hex()


# The first key in this series whose hash starts with two zero bytes, so the
# group has two zero words in a row, which RFC 5952 writes as ::.
i = 0
while True:
    zero_key = hashlib.sha256(b"w9 channel vector %d" % i).digest()
    if hashlib.sha256(DOMAIN.encode() + bytes([2]) + zero_key).digest()[:2] == b"\0\0":
        break
    i += 1

vectors = [
    ("System program, as a program", "program", "11111111111111111111111111111111"),
    ("System program, as an account: the same key under the other kind is another channel", "account", "11111111111111111111111111111111"),
    ("Token program, as a program", "program", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    ("Token program, as an account", "account", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    ("Jupiter v6, as a program", "program", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),
    ("Jupiter v6, as an account", "account", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),
    ("USDC mint, an account that is not a program", "account", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
    ("A key whose hash starts with two zero bytes: with the prefix's zero word that makes two zero 16-bit words, which RFC 5952 compresses to ff3e::", "account", b58encode(zero_key)),
]

doc = {
    "spec": [
        "Test vectors for Blockcast txfeed filter channel addresses, spec v1 (go-amt txfeed/channel.go). channel-vectors.py, which uses only Python's standard library, writes this file. Implementations in other languages assert it.",
        "A channel is a kind and a 32-byte key. Kind program (1) carries the transactions that invoke the program in a top-level instruction; a program called by CPI is not visible in shreds. Kind account (2) carries the transactions that list the account among their message's static account keys; accounts reached through address lookup tables are not matched.",
        "The channel's IPv6 SSM group is ff3e:0000: followed by the first 12 bytes of SHA-256(domain || kind || key). domain is the 27 ASCII bytes below, with no length prefix or terminator; kind is one byte; key is the 32 bytes that the base58 key decodes to.",
        "group is the RFC 5952 text form: lowercase, no leading zeros, the longest run of two or more zero 16-bit words as ::, and a single zero word as 0. Go's net/netip, Rust's std::net::Ipv6Addr and the WHATWG URL serializer print it so. Subscriptions are keyed by this text, so print it exactly. group_hex is the same group's 16 bytes.",
        "refused lists the keys that can have no channel, of either kind: nearly every transaction carries them, so the channel would be the whole feed.",
    ],
    "domain": DOMAIN,
    "kinds": KINDS,
    "refused": [
        {"name": "vote", "key": "Vote111111111111111111111111111111111111111"},
        {"name": "compute-budget", "key": "ComputeBudget111111111111111111111111111111"},
    ],
    "vectors": [dict(zip(("name", "kind", "key", "group", "group_hex"), (n, k, key) + group(k, key))) for n, k, key in vectors],
}
print(json.dumps(doc, indent=2))
