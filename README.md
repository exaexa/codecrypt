
# Codecrypt

The post-quantum cryptography tool.

#### About

This is a GnuPG-like unix program for encryption and signing that uses only
quantum-computer-resistant algorithms:

 - McEliece cryptosystem (compact quasi-dyadic variant) for encryption
 - Hash-based Merkle tree algorithm (FMTSeq variant) for digital signatures

#### Why this?

Go read http://pqcrypto.org/

#### Links

 - infopage: http://e-x-a.org/codecrypt/
 - *package downloads*: http://e-x-a.org/codecrypt/files/

#### Documentation

There is a complete, UNIXy manual page supplied with the package. You can view it online here: http://e-x-a.org/codecrypt/ccr.1.html

## Quick How-To

Everything is meant to work mostly like GnuPG, but with some good simplicity
margin. Let's play with random data!

	ccr -g help
	ccr -g fmtseq128-sha --name "John Doe"    # your signature key
	ccr -g mceqd128 --name "John Doe"     # your encryption key

	ccr -K  #watch the generated keys
	ccr -k

	ccr -p -a -o my_pubkeys.asc -F Doe  # export your pubkeys for friends

	#see what people sent us
	ccr -ina < friends_pubkeys.asc

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

	Key management:
	 -g, --gen-key        generate specified keypair, `help' lists algorithms
	 -k, --list           list keys
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

Codecrypt eats data. Use it with caution.

Author is a self-taught cryptographer.

