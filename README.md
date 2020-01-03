# Conceal

A file encryption tool that leverage [noise protocol](https://noiseprotocol.org/) to provide best-in-class security to your private files. With conceal, you can send encrypted files through insecure channel, and only the receiver who have the right private key could calculate the encryption key and decrypt the file. The receiver could optionally authenticate the sender.

## Usage

First of all, generate your id (private key). It will be stored in your `~/.conceal/identity`.

```bash
$ conceal generate
Keypair generated at: "/Users/tchen/.conceal/identity"
```

If you want to see your id (this could be given to others so they could encrypt file for you):

```bash
$ conceal show-id
Id: 7mVtUDwqKuCkM7CQxZ6BZ7i4uvmTLB7RF7HsozVV9UH7
```

To encrypt a file for a recipient (here I encrypt the file for myself):

```bash
$ conceal encrypt /tmp/road.jpg /tmp/road1.jpg --recipient 7mVtUDwqKuCkM7CQxZ6BZ7i4uvmTLB7RF7HsozVV9UH7
encrypted 1807958 bytes for "/tmp/road1.jpg"
```

To decrypt a received file:

```bash
$ conceal decrypt /tmp/road1.jpg /tmp/road2.jpg
decrypted 1807410 bytes for "/tmp/road2.jpg"
```

Files (original, encrypted, decrypted):

```bash
$ ls -l /tmp/road*
-rw-r--r--@ 1 tchen  wheel  1807354 Jan  2 20:47 /tmp/road.jpg
-rw-r--r--  1 tchen  wheel  1807958 Jan  2 20:48 /tmp/road1.jpg
-rw-r--r--  1 tchen  wheel  1807354 Jan  2 20:48 /tmp/road2.jpg
```
