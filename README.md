# S.E.G.R.E.T.O.

![Status](https://img.shields.io/badge/Status-Under%20Construction-orange)
![crypto_core](https://img.shields.io/badge/crypto_core-Rust-DEA584?logo=rust)
![client](https://img.shields.io/badge/client-Python-3776AB?logo=python)
![Version](https://img.shields.io/badge/version-0.1.0--dev-blue)

**S.E.G.R.E.T.O.** means *Secure Encrypted Gateway for Real-time Encrypted Text Operations* I don't even know some of this terms but I think it makes it cooler (in reality I created a name I liked in italian and asked to a friend to give me an acronim, as I'm writing I just realized he may has used AI)

A peer-to-peer encrypted chat where **there is no server**. Not "the server is
encrypted too", not "we trust our server", there is literally no server. Every
peer is both a client and a server, which sounds fancy but mostly means your
laptop does all the work and has nobody else to blame.  
(PLS don't blame me if it becames an airplane with the sound of the cooler fans).

This is an **experimental, learning project** built by "me". If you use it
to plan a heist, the threat model has a section about why that's a bad idea (even I wouldn't trust myself).

## What it does (hopefully)

- Direct peer-to-peer messaging over the Internet
- End-to-end encryption: messages are encrypted before they leave your device
- Sender authentication and tamper detection: forged or modified messages get rejected (I told you with wireshark to stay put now I cannot see the meaningful "are we hitting chest today?" from my Bro)
- Private keys never leave your device and are encrypted at rest with a key derived from your password
- Contact verification via key fingerprints, so you know you're talking to your friend and not to the guy who hijacked the café Wi-fi (sooooo cool)

## Why?

Because "just use a central server" felt too easy, and I wanted to understand
what it actually takes to do encryption, key exchange and identity without
anyone's infrastructure. The honest answer so far: *quite a lot* and I haven't even written a line of code :( 

## Status

Very much work in progress. The repo currently contains an architectural
decision, a stub, and optimism in that order.

## Disclaimer

This isn't a professional app, use it at your own risk
