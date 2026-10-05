# asymcrypt

Encrypt stuff offline, with a key that can't decrypt it afterwards.

If you've used [`encpipe`](https://github.com/jedisct1/encpipe), you already know how it works. It reads from `stdin`, writes to `stdout`, and doesn't care how big the input is. You can pass file names too, but you don't have to.

The cipher is [AEGIS-128X](https://www.rfc-editor.org/rfc/rfc10032.html). It's fast (on any CPU with AES instructions, it basically goes as fast as your memory), and it also catches any tampering with the data.

For the keys, it uses [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), a mix of ML-KEM-768 and X25519. So it's ready for quantum computers, while still relying on good old elliptic curves.

## But why?

With regular encryption, the key that encrypts your data can also decrypt it. Here, that's not the case.

The machine doing the encryption only gets a public key. Every time it encrypts something, a brand new secret is created for that file. And since the machine never has the private key, it simply can't read back what it wrote.

To decrypt, you need the recovery key (or a password) that you put aside when you created the keys. That key never needs to be on the machine doing the encryption.

Where is this handy? A few examples:

- Backups on a server that might get stolen or hacked one day.
- Logs coming from a machine you don't really trust to read its own history.
- Archives written by a service that shouldn't be able to look back at what it wrote.
- Drop boxes, where someone encrypts files for someone else.

Basically, anytime you want something that can write but not read.

And it's all offline. No handshake, no server, nobody to talk to.

You create the keys once, with a single command. After that, the machine can encrypt as much as it wants without ever contacting whoever has the recovery key. The recovery key just sits wherever you put it, until you actually need to decrypt something.

## Installing

You'll need Zig 0.16 or later. Then:

```sh
zig build -Doptimize=ReleaseFast
```

The binary ends up in `zig-out/bin/asymcrypt`. Copy it somewhere in your `PATH`, or just use `zig build run -- ...`.

## Setting up

First, create a key pair. Everything happens locally, in one step. No network, nothing sent anywhere.

```sh
asymcrypt init -o device.key -r recovery.key
```

You now have two files.

`recovery.key` is the one to keep offline. Print it, put it on a USB stick, save it in your password manager, whatever works for you. It's the only thing that can decrypt your files, so it can stay there until you need it.

`device.key` goes on the machine that encrypts. It's a public key, and it can encrypt as much data as you want.

So, move `recovery.key` somewhere the encrypting machine can't get to, and leave `device.key` where it is.

One warning, though: lose `recovery.key`, and everything encrypted with it is gone. Forever. So don't lose it.

## Encrypting

Give `encrypt` the device key, and pipe whatever you want into it:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
```

Each time, a new one-time secret is created, and the device key doesn't change. And right after that, the machine can't read what it just encrypted.

So you can keep the encrypted file on the same machine, copy it to a NAS, or upload it somewhere. It doesn't matter: the machine can't read it, and it never could.

## Decrypting

On any machine that has the recovery key:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

The recovery key gets each file's secret back directly. No searching, no extra steps.

## Password mode

Would you rather remember a password than keep a recovery key around? Then use `--password` when setting up:

```sh
asymcrypt init --password -o device.key
```

You'll be asked for a password, and then asked to type it again.

This time, `device.key` contains the public key, plus the private key encrypted with your password. To decrypt, all you need is the password and the encrypted file:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

In other words, the password is your recovery key now. There's nothing else to keep.

But if you forget the password, your files are gone.

For scripts, you can set the `ASYMCRYPT_PASSWORD` environment variable, and `asymcrypt` will use it instead of asking.

Just keep in mind that other programs running as the same user can usually read your environment variables.

## Input and output

- `-i PATH` reads from `PATH`. Without `-i` (or with `-i -`), it reads from `stdin`. That's how you'd normally use it anyway, in a pipe.
- `-o PATH` writes to `PATH`. Without `-o` (or with `-o -`), it writes to `stdout`.
- It never overwrites an existing file. If that's really what you want, add `--force`.

When writing to a file, `asymcrypt` first writes everything to a temporary file in the same folder, and only renames it once it's all written and saved. So if something crashes halfway, you won't be left with a half-written file.
