# asymcrypt

`asymcrypt`: encrypt anything offline with a key that cannot decrypt what it just wrote.

It works like [`encpipe`](https://github.com/jedisct1/encpipe): input defaults to `stdin`, output defaults to `stdout`, can process arbitrary large inputs ; file paths are optional.

Encryption is authenticated, fast, post-quantum resistant, etc. The underlying cipher is [AEGIS-128X](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/), a parallel AES-based AEAD that runs at memory speed on anything with hardware AES support.

Key encapsulation uses [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) (ML-KEM-768 + X25519), a hybrid post-quantum KEM. Each encryption generates a fresh shared secret via KEM encapsulation against the public key, so the device key (a public encapsulation key) can never decrypt what it produced.

Decryption requires the offline decapsulation seed (or a password) that was set aside when the keys were generated. It never has to live on the encrypting host.

This shape fits a lot of situations: backups on a host that might later be stolen or compromised, log shipping from a machine you don't fully trust to read its own history, append-only archives written by a service that should not be able to look back at what it wrote, drop boxes where one party encrypts to another, and so on.

Anywhere you want a writer that cannot also be a reader, this tool applies.

The whole thing runs offline. There is no handshake, no server, no per-message coordination with anyone.

You generate a keypair once, in a single local command, and from then on the encrypting host can produce as many ciphertexts as it likes without ever talking to the holder of the recovery key. The recovery key sits alone, wherever you decided to put it, and is only consulted when something actually needs to be decrypted.

## Installing

Build from source with a recent Zig toolchain (0.16 or later):

```sh
zig build -Doptimize=ReleaseFast
```

The resulting binary lands in `zig-out/bin/asymcrypt`. Drop it somewhere on your `PATH`, or run `zig build run -- ...` to invoke it through the build system.

## Setting up

You start by creating a fresh X-Wing keypair. Both keys are produced locally in one shot, with no network involved and no exchange between machines.

The recovery key (decapsulation seed) is the one you need to keep offline. Print it, write it to a USB stick, store it in a password manager, whatever fits your threat model. It is the only thing that can ever decrypt the ciphertexts, and it never has to leave the place you stored it until you actually need to recover something.

The device key (encapsulation key) lives on the encrypting host. It is a public key that can encrypt an unbounded number of inputs on its own.

```sh
asymcrypt init -o device.key -r recovery.key
```

Move `recovery.key` somewhere the encrypting host cannot reach, and keep `device.key` on the host.

If you ever lose `recovery.key`, every ciphertext ever produced becomes unrecoverable, so treat it accordingly.

## Encrypting

Point `encrypt` at the device key and feed it any stream:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
```

Each encryption generates a fresh KEM shared secret. The device key is never modified and the host cannot decrypt what it just produced.

The encrypted output can sit on the same machine, on a NAS, or be uploaded somewhere shared; the host has already lost the ability to read it (it never had it in the first place).

## Recovering

Anywhere with the offline recovery key:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

Decapsulation with the recovery seed recovers the per-file shared secret directly. No chain walking or key search is needed.

## Password mode

If you would rather remember a passphrase than store a recovery key, set things up with `--password`:

```sh
asymcrypt init --password -o device.key
```

You will be prompted for a password and then for a confirmation. The device key file contains the public encapsulation key alongside the password-encrypted decapsulation seed. Recovery only needs the password and the ciphertext:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

The password is the recovery secret in this mode, so there is no separate recovery key to store.

If you forget the password, the ciphertexts are gone.

If you want to script things, set `ASYMCRYPT_PASSWORD` in the environment and `asymcrypt` will use that instead of prompting.

Be careful: anything in the environment is generally readable by other processes running as the same user.

## Input and output

- `-i PATH` reads from `PATH`. Without `-i`, or with `-i -`, `asymcrypt` reads `stdin`. This is the usual case — encryption is meant to sit in a pipe.
- `-o PATH` writes to `PATH`. Without `-o`, or with `-o -`, output goes to `stdout`.
- File output never overwrites an existing path. Pass `--force` if you really mean to clobber it.

File output is staged in a temporary file in the destination directory and renamed into place only after the whole stream has been written and flushed. A crash mid-write leaves no partial file behind.
