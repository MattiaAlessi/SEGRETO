# S.E.G.R.E.T.O. Threat Model

## Principles to protect:

- Message content: That's the whole point, if a network observer can read chats why are we even using encryption
- Private keys (X25519, Ed25519): The private keys are the only way to protect your messages, defend them by encrypting them with a password
- Sender identity: You must be able to prove who sent a message (for example you should be able to prove your friend sent that instead of some MITM)
- Message integrity: Why do I even want to see a modified message??

## What is a danger to the principles:

- **The network observer:** Someone on the same LAN (café Wi-fi, school network,
that roommate with Wireshark and too much free time. P.S. if that's you just give up the messages are encrypted :)) ) sniffing traffic. Sees
encrypted blobs (or strange symbols that seems coming out of a Satanic rite) and metadata, sees nothing readable. This is adversary #1
because it's the easiest to become.

- **The man in the middle:** An active attacker who doesn't just listen but
relays and rewrites traffic (it could use Wi-fi Pineapple or a simple Flipper 0), trying to impersonate your friend or swap keys
during the exchange.   
How to defend: authenticate the key exchange (signatures + fingerprint verification through a side channel, a.k.a. "read it out loud over
WhatsApp because this is not my problem").

**The person with physical access:** Someone with your (locked or off) laptop (I hate when my friends steal me for fun :/ )
Defense: private keys are encrypted at rest with a key derived from your
password. This buys time against opportunistic snooping, not against someone
with infinite time and a GPU farm.

## What I cannot bother protecting (real vulnerability)

- **Malware:** If there's a keylogger on your machine, encryption
  is decorative (they know each key you type so it's worthless encrypting messages)
- **Metadata / traffic analysis:** Even encrypted, observers can see *who*
  talks to *whom*, *when*, and *how much*. If the fact that you communicate is
  itself sensitive, this is not your app (you should use something like Briar).
- **Anonymity:** S.E.G.R.E.T.O. hides *what* you say, not *who* you are. IPs
  and nicknames are visible to peers. This is not Tor, and it doesn't want to be.
- **Availability:** No servers also means nobody guarantees delivery. If the
  peer is offline, the message waits on a mailbox (simply a poor friend that's always on pc 24/24h 7/7 day is your free server) or doesn't arrive. 
- **Forensic deletion:** Deleting a file on a modern filesystem is more of a
  polite suggestion than a guarantee, real professional can still recreate them somehow.
- **Human beings:** The best crypto in the world is defeated by screenshotting
  the conversation and forwarding it. No protocol fixes trust between people (better not write something you'll regret to your friend or they'll use it against you).
- **My own code:** This project uses standard, widely reviewed primitives
  (X25519, XChaCha20-Poly1305, Ed25519, Argon2id). The primitives are the
  trustworthy part. The glue around them is written by... "me", so it's your own choice if trust me, it can be questionable but at least it's yours... I hope.

## Design consequences (rules that follow from all this mega long file)

Every feature in the roadmap must respect these, or it needs a very good excuse:

1. **Encryption is not optional.** Every message is end-to-end encrypted.
   **Always**. There is no "plaintext mode".
2. **Verify before decrypt.** Signatures (Ed25519) are checked *before* any
   ciphertext is touched. Unauthenticated decryption is where subtle
   vulnerabilities hide, and we don't invite them in.
3. **Keys are born, live and die on the device.** Private keys never leave the
   machine except inside the encrypted profile file, protected by a password
   via Argon2id key derivation.
4. **Trust is explicit, never automatic.** Peers are Unverified until a
   fingerprint is confirmed through a side channel. The UI must make
   this state impossible to miss.
5. **No servers, no exceptions.** If a feature requires a central server to
   work, it's not a feature of this project. The mailbox is *just another
   peer* that stores only ciphertext it cannot read (free servers are always the best).
6. **Standard crypto or nothing.** No home made ciphers (even thought I think a Caesar Cypher will do the work for me), no "slightly
   improved" AES.

---

*Last updated: before any crypto code exists (I haven't started yet I wish I'll re-read this). Which is the only moment
writing this is cheap.*

P.S. this markdowm will probably be untouched until the end of the project or if I have really, but really a lot of time to waste... 
