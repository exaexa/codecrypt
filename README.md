
# Codecrypt

The post-quantum cryptography tool.

#### About

This is a GnuPG-like unix program for encryption and signing that uses only
quantum-computer-resistant algorithms:

 - McEliece cryptosystem (compact QC-MDPC variant) for encryption
 - Hash-based Merkle tree algorithm (FMTSeq variant) for digital signatures

Codecrypt is free software. The code is licensed under terms of LGPL3 in a good
hope that it will make combinations with other tools easier.

#### Why this?

Go read http://pqcrypto.org/

#### Links

 - infopage: http://e-x-a.org/codecrypt/
 - *package downloads*: http://e-x-a.org/codecrypt/files/

#### Distro packages

 - Gentoo packages: https://packages.gentoo.org/packages/app-crypt/codecrypt
   with current ebuild usually available at http://e-x-a.org/codecrypt/files
 - Debian packages: `apt-get install codecrypt`
 - Arch linux: see https://aur.archlinux.org/packages/codecrypt/

#### Documentation

There is a complete, UNIXy manual page supplied with the package. You can view
it online here: http://e-x-a.org/codecrypt/ccr.1.html

##### Used cryptography overview

To achieve the stated goal, codecrypt uses a lot of (traditional, but
"quantum-secure") cryptographic primitives. Choices of primitives were based on
easy auditability of design, simplicity and provided security.

The git repo of codecrypt contains `doc/papers` with an unsorted heap of
academic papers and slides about relevant topics.

Stream ciphers used:

- ChaCha20, the recommended choice from djb
- XSynd stream cipher as an interesting and nontraditional candidate also based
  on assumptions from coding theory; used NUMS (it requires lot of NUMS) are
  explained in `doc/nums` directory in the repo.
- Arcfour for initial simplicity of implementation. After recent statistical
  attacks I cannot recommend using any RC4 variant anymore, but provided
  padding and the "offline-only" usage of codecrypt keeps the usage mostly
  secure.

CRHFs used:

- Cubehash variants where selected for implementation ease, really clean
  design, quite good speed and flexibility of parameter choices. This is also
  the only hash possibility when Crypto++ library is not linked to codecrypt.
  KeyID's are CUBE256 hashes of serialized public key.
- ripemd128 for small hashes
- tiger192 is used as an alternative for Cubehash for 192bit hashes
- There's always a variant with SHA-256, SHA-384 or SHA-512.

Signature algorithms:

- FMTSeq with many possibilities and combinations of aforementioned CRHFs
- SPHINCS256 support is scheduled for next release

Encryption algorithms:

- MDPC McEliece on quasi-cyclic matrices. The implementation uses some tricks
  to speedup the (pretty slow) cyclic matrix multiplication (most notably
  libfftm3 in this version). For padding using the Fujisaki-Okamoto scheme, the
  cipher requires a stream cipher and a CRHF, used ciphers and CRHFs are
  specified in the algorithm name -- e.g. MCEQCMDPC128FO-CUBE256-CHACHA20 means
  that the parameters are tuned to provide 128bit security, uses CUBE256 hash,
  and ChaCha20 stream cipher.
- Quasi-dyadic McEliece was included in codecrypt as an original algorithm, but
  is now broken and prints a warning message on any usage.

Caveats:

Cryptography is **not intended for "online" use**, because some algorithms
(especially the MDPC decoding) are (slightly) vulnerable to timing attacks.

## Quick How-To

Everything is meant to work mostly like GnuPG, but with some good simplicity
margin. Let's play with random data!


	ccr -g help
	ccr -g sig --name "John Doe"    # your signature key
	ccr -g enc --name "John Doe"    # your encryption key

	ccr -K  #watch the generated keys
	ccr -k

	ccr -p -a -o my_pubkeys.asc -F Doe  # export your pubkeys for friends

	#(now you should exchange the pubkeys with friends)

	#see what people sent us, possibly check the fingerprints
	ccr -inaf < friends_pubkeys.asc

	#import Frank's key and rename it
	ccr -ia -R friends_pubkeys.asc --name "Friendly Frank"

	#send a nice message to Frank (you can also specify him by @12345 keyid)
	ccr -se -r Frank < Document.doc > Message_to_frank.ccr

	#receive a reply
	ccr -dv -o Decrypted_verified_reply.doc <Reply_from_frank.ccr

	#rename other's keys
	ccr -m Frank -N "Unfriendly Frank"

	#and delete pukeys of everyone who's Unfriendly
	ccr -x Unfri

	#create hashfile from a large file
	ccr -sS hashfile.ccr < big_data.iso

	#verify the hashfile
	ccr -vS hashfile.ccr < the_same_big_data.iso

	#create (ascii-armored) symmetric key and encrypt a large file
	ccr -g sha256,chacha20 -aS symkey.asc
	ccr -eaS symkey.asc -R big_data.iso -o big_data_encrypted.iso

	#decrypt a large file
	ccr -daS symkey.asc <big_data_encrypted.iso >big_data.iso

## Option reference

For completeness I add listing of all options here (also available from
`ccr --help`)

	Usage: ./ccr [options]

	Common options:
	 -h, --help     display this help
	 -V, --version  display version information
	 -T, --test     perform (probably nonexistent) testing/debugging stuff

	Global options:
	 -R, --in      input file, default is stdin
	 -o, --out     output file, default is stdout
	 -E, --err     the same for stderr
	 -a, --armor   use ascii-armored I/O
	 -y, --yes     assume that answer is `yes' everytime

	Actions:
	 -s, --sign     sign a message
	 -v, --verify   verify a signed message
	 -e, --encrypt  encrypt a message
	 -d, --decrypt  decrypt an encrypted message

	Action options:
	 -r, --recipient    encrypt for given user
	 -u, --user         use specified secret key
	 -C, --clearsign    work with cleartext signatures
	 -b, --detach-sign  specify file with detached signature
	 -S, --symmetric    enable symmetric mode of operation where encryption
	                    is done using symmetric cipher and signatures are
	                    hashes, and specify a filename of symmetric key or hashes

	Key management:
	 -g, --gen-key        generate keys for specified algorithm
	 -g help              list available cryptographic algorithms
	 -k, --list           list contents of keyring
	 -K, --list-secret
	 -i, --import         import keys
	 -I, --import-secret
	 -p, --export         export keys
	 -P, --export-secret
	 -x, --delete         delete matching keys
	 -X, --delete-secret
	 -m, --rename         rename matching keys
	 -M, --rename-secret

	Key management options:
	 -n, --no-action    on import, only show what would be imported
	 -N, --name         specify a new name for renaming or importing
	 -F, --filter       only work with keys with matching names
	 -f, --fingerprint  format full key IDs nicely for human eyes


## Disclaimer

Codecrypt eats data. Use it with caution. Read the F manual.

Author is a self-taught cryptographer.

