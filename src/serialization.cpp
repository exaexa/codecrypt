
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2016 Mirek Kratochvil <exa.exa@gmail.com>
 *
 * Codecrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Codecrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Codecrypt. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sencode.h"
#include "types.h"
#include "bvector.h"
#include "matrix.h"
#include "gf2m.h"
#include "polynomial.h"
#include "permutation.h"
#include "mce_qd.h"
#include "mce_qcmdpc.h"
#include "fmtseq.h"
#include "message.h"
#include "hashfile.h"
#include "symkey.h"

#define CAST(IN,OUT,TYPE) \
	OUT=dynamic_cast<TYPE>(IN); \
	if(!OUT) return false;

#define CAST_LIST(IN,OUT) CAST(IN,OUT,sencode_list*)
#define CAST_BYTES(IN,OUT) CAST(IN,OUT,sencode_bytes*)
#define CAST_INT(IN,OUT) CAST(IN,OUT,sencode_int*)

static sencode* serialize_uint_vector (std::vector<uint>*v)
{
	sencode_list*l = new sencode_list;
	l->items.resize (v->size());
	for (uint i = 0; i < v->size(); ++i)
		l->items[i] = new sencode_int ( (*v) [i]);
	return l;
}

static bool unserialize_uint_vector (std::vector<uint>*v, sencode*s)
{
	sencode_list* CAST_LIST (s, l);

	v->clear();
	v->resize (l->items.size());
	for (uint i = 0; i < v->size(); ++i) {
		sencode_int*CAST_INT (l->items[i], x);
		(*v) [i] = x->i;
	}
	return true;
}

sencode* bvector::serialize()
{
	std::string bytes;
	//the padding of each vector is zero, we can stuff the bytes right in. Just make it sure here:
	fix_padding();
	to_string (bytes);

	sencode_list*l = new sencode_list;
	l->items.push_back (new sencode_int (size()));
	l->items.push_back (new sencode_bytes (bytes));
	return l;
}

bool bvector::unserialize (sencode* s)
{
	uint i;
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 2) return false;
	sencode_int*CAST_INT (l->items[0], size);
	sencode_bytes*CAST_BYTES (l->items[1], bytes);
	if (bytes->b.size() != ( (size->i + 7) / 8)) return false;

	/*
	 * the important part. verify that padding is always zero, because
	 * sencode serialization must be bijective
	 */
	for (i = size->i; i < 8 * bytes->b.size(); ++i)
		if ( (bytes->b[i / 8] >> (i % 8)) & 1)
			return false;

	from_string (bytes->b, size->i);

	return true;
}

sencode* matrix::serialize()
{
	uint bits = width() * height();
	uint ss = (bits + 7) / 8;
	std::string bytes;
	bytes.resize (ss, '\0');
	for (uint i = 0; i < bits; ++i)
		if (item (i / height(), i % height())) bytes[i / 8] |= 1 << (i % 8);
	sencode_list*l = new sencode_list;
	l->items.push_back (new sencode_int (width()));
	l->items.push_back (new sencode_int (height()));
	l->items.push_back (new sencode_bytes (bytes));
	return l;
}

bool matrix::unserialize (sencode* s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 3) return false;
	sencode_int*CAST_INT (l->items[0], w);
	sencode_int*CAST_INT (l->items[1], h);
	sencode_bytes*CAST_BYTES (l->items[2], bytes);
	if (bytes->b.size() != ( ( (h->i * w->i) + 7) / 8)) return false;
	clear();
	resize2 (w->i, h->i, 0);
	for (uint i = 0; i < w->i * h->i; ++i)
		if ( (bytes->b[i / 8] >> (i % 8)) & 1)
			item (i / h->i, i % h->i) = 1;
	return true;
}

sencode* permutation::serialize()
{
	return serialize_uint_vector (this);
}

bool permutation::unserialize (sencode* s)
{
	if (!unserialize_uint_vector (this, s)) return false;

	//small sanity check
	for (uint i = 0; i < size(); ++i) if (item (i) >= size()) return false;

	return true;
}

sencode* gf2m::serialize()
{
	return new sencode_int (m);
}

bool gf2m::unserialize (sencode* s)
{
	sencode_int*CAST_INT (s, p);
	return create (p->i);
}

sencode* polynomial::serialize()
{
	return serialize_uint_vector (this);
}

bool polynomial::unserialize (sencode* s)
{
	return unserialize_uint_vector (this, s);
}

#define PUBKEY_IDENT "CCR-PUBLIC-KEY-"
#define PRIVKEY_IDENT "CCR-PRIVATE-KEY-"

sencode* mce_qd::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (7);
	l->items[0] = new sencode_bytes (PRIVKEY_IDENT "QD-MCE");
	l->items[1] = fld.serialize();
	l->items[2] = new sencode_int (T);
	l->items[3] = serialize_uint_vector (&essence);
	l->items[4] = block_perm.serialize();
	l->items[5] = serialize_uint_vector (&block_perms);
	l->items[6] = hperm.serialize();
	return l;
}

bool mce_qd::privkey::unserialize (sencode* s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 7) return false;

	sencode_bytes*CAST_BYTES (l->items[0], ident);
	if (ident->b.compare (PRIVKEY_IDENT "QD-MCE")) return false;

	sencode_int*CAST_INT (l->items[2], p);
	T = p->i;

	if (! (fld.unserialize (l->items[1]) &&
	       unserialize_uint_vector (&essence, l->items[3]) &&
	       block_perm.unserialize (l->items[4]) &&
	       unserialize_uint_vector (&block_perms, l->items[5]) &&
	       hperm.unserialize (l->items[6]))) return false;

	return true;
}

sencode* mce_qd::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (3);
	l->items[0] = new sencode_bytes (PUBKEY_IDENT "QD-MCE");
	l->items[1] = new sencode_int (T);
	l->items[2] = qd_sigs.serialize();
	return l;
}

bool mce_qd::pubkey::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 3) return false;

	sencode_bytes*CAST_BYTES (l->items[0], ident);
	if (ident->b.compare (PUBKEY_IDENT "QD-MCE")) return false;

	sencode_int*CAST_INT (l->items[1], p);
	T = p->i;

	if (!qd_sigs.unserialize (l->items[2])) return false;

	return true;
}

sencode* fmtseq::privkey::tree_stk_item::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (3);
	l->items[0] = new sencode_int (level);
	l->items[1] = new sencode_int (pos);
	l->items[2] = new sencode_bytes (item);
	return l;
}

bool fmtseq::privkey::tree_stk_item::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 3) return false;

	sencode_int*p;
	CAST_INT (l->items[0], p);
	level = p->i;

	CAST_INT (l->items[1], p);
	pos = p->i;

	sencode_bytes* CAST_BYTES (l->items[2], a);
	item = std::vector<byte> (a->b.begin(), a->b.end());

	return true;

}

sencode* mce_qcmdpc::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (3);
	l->items[0] = new sencode_bytes (PUBKEY_IDENT "QCMDPC-MCE");
	l->items[1] = new sencode_int (t);
	l->items[2] = G.serialize();
	return l;
}

bool mce_qcmdpc::pubkey::unserialize (sencode* s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 3) return false;

	sencode_bytes*CAST_BYTES (l->items[0], ident);
	if (ident->b.compare (PUBKEY_IDENT "QCMDPC-MCE")) return false;

	sencode_int*CAST_INT (l->items[1], p);
	t = p->i;

	if (!G.unserialize (l->items[2])) return false;

	return true;
}

sencode* mce_qcmdpc::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (5);
	l->items[0] = new sencode_bytes (PRIVKEY_IDENT "QCMDPC-MCE");
	l->items[1] = new sencode_int (t);
	l->items[2] = new sencode_int (rounds);
	l->items[3] = new sencode_int (delta);
	l->items[4] = H.serialize();
	return l;
}

bool mce_qcmdpc::privkey::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 5) return false;

	sencode_bytes*CAST_BYTES (l->items[0], ident);
	if (ident->b.compare (PRIVKEY_IDENT "QCMDPC-MCE")) return false;

	sencode_int*CAST_INT (l->items[1], p);
	t = p->i;

	CAST_INT (l->items[2], p);
	rounds = p->i;

	CAST_INT (l->items[3], p);
	delta = p->i;

	if (!H.unserialize (l->items[4])) return false;

	return true;
}


sencode* fmtseq::privkey::serialize()
{
	/*
	 * fmtseq privkey structure
	 *
	 * ( SK h l hs sigs_used
	 *   ( (exist1 exist exist ...)
	 *     (exist2 exist exist ...)
	 *     ...)
	 *   ( (desired1 ...)
	 *     ...)
	 *   ( (stack1 ...)
	 *     (stack2 ...)
	 *     ...)
	 *   ( progress1 progress2 ...)
	 * )
	 */

	uint i, j;

	sencode_list*L = new sencode_list;
	L->items.resize (10);
	L->items[0] = new sencode_bytes (PRIVKEY_IDENT "FMTSEQ");
	L->items[1] = new sencode_bytes (SK);
	L->items[2] = new sencode_int (h);
	L->items[3] = new sencode_int (l);
	L->items[4] = new sencode_int (hs);
	L->items[5] = new sencode_int (sigs_used);

	sencode_list *E, *D, *S, *P;
	L->items[6] = E = new sencode_list;
	L->items[7] = D = new sencode_list;
	L->items[8] = S = new sencode_list;
	L->items[9] = P = new sencode_list;

	E->items.resize (exist.size());
	for (i = 0; i < exist.size(); ++i) {
		sencode_list *t = new sencode_list;
		E->items[i] = t;
		t->items.resize (exist[i].size());
		for (j = 0; j < exist[i].size(); ++j)
			t->items[j] = new sencode_bytes (exist[i][j]);
	}

	D->items.resize (desired.size());
	for (i = 0; i < desired.size(); ++i) {
		sencode_list *t = new sencode_list;
		D->items[i] = t;
		t->items.resize (desired[i].size());
		for (j = 0; j < desired[i].size(); ++j)
			t->items[j] = new sencode_bytes (desired[i][j]);
	}

	S->items.resize (desired_stack.size());
	for (i = 0; i < desired_stack.size(); ++i) {
		sencode_list *t = new sencode_list;
		S->items[i] = t;
		t->items.resize (desired_stack[i].size());
		for (j = 0; j < desired_stack[i].size(); ++j)
			t->items[j] = desired_stack[i][j].serialize();
	}

	P->items.resize (desired_progress.size());
	for (i = 0; i < desired_progress.size(); ++i)
		P->items[i] = new sencode_int (desired_progress[i]);

	return L;
}

bool fmtseq::privkey::unserialize (sencode*s)
{
	uint i, j;
	sencode_list*CAST_LIST (s, L);
	if (L->items.size() != 10) return false;

	sencode_bytes*CAST_BYTES (L->items[0], ident);
	if (ident->b.compare (PRIVKEY_IDENT "FMTSEQ")) return false;

	sencode_bytes*B;
	sencode_int*I;

	CAST_BYTES (L->items[1], B);
	SK = std::vector<byte> (B->b.begin(), B->b.end());

	CAST_INT (L->items[2], I);
	h = I->i;

	CAST_INT (L->items[3], I);
	l = I->i;

	CAST_INT (L->items[4], I);
	hs = I->i;

	CAST_INT (L->items[5], I);
	sigs_used = I->i;

	sencode_list*A;

	//exist subtrees
	CAST_LIST (L->items[6], A);
	exist.clear();
	exist.resize (A->items.size());
	for (i = 0; i < exist.size(); ++i) {
		sencode_list*CAST_LIST (A->items[i], e);
		exist[i].resize (e->items.size());
		for (j = 0; j < exist[i].size(); ++j) {
			sencode_bytes*CAST_BYTES (e->items[j], item);
			exist[i][j] = std::vector<byte>
			              (item->b.begin(),
			               item->b.end());
		}
	}

	//desired subtrees
	CAST_LIST (L->items[7], A);
	desired.clear();
	desired.resize (A->items.size());
	for (i = 0; i < desired.size(); ++i) {
		sencode_list*CAST_LIST (A->items[i], d);
		desired[i].resize (d->items.size());
		for (j = 0; j < desired[i].size(); ++j) {
			sencode_bytes*CAST_BYTES (d->items[j], item);
			desired[i][j] = std::vector<byte>
			                (item->b.begin(),
			                 item->b.end());
		}
	}

	//desired stacks
	CAST_LIST (L->items[8], A);
	desired_stack.clear();
	desired_stack.resize (A->items.size());
	for (i = 0; i < desired_stack.size(); ++i) {
		sencode_list*CAST_LIST (A->items[i], d);
		desired_stack[i].resize (d->items.size());
		for (j = 0; j < desired_stack[i].size(); ++j)
			if (!desired_stack[i][j].unserialize (d->items[j]))
				return false;
	}

	//desired progress
	CAST_LIST (L->items[9], A);
	desired_progress.clear();
	desired_progress.resize (A->items.size());
	for (i = 0; i < desired_progress.size(); ++i) {
		CAST_INT (A->items[i], I);
		desired_progress[i] = I->i;
	}

	//checking the sizes and correctness of everything is a job of FMTSeq
	//implementation that has some insight into how it works :]
	return true;
}

sencode* fmtseq::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (4);
	l->items[0] = new sencode_bytes (PUBKEY_IDENT "FMTSEQ");
	l->items[1] = new sencode_int (H);
	l->items[2] = new sencode_int (hs);
	l->items[3] = new sencode_bytes (check);
	return l;
}

bool fmtseq::pubkey::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, l);
	if (l->items.size() != 4) return false;

	sencode_bytes*CAST_BYTES (l->items[0], ident);
	if (ident->b.compare (PUBKEY_IDENT "FMTSEQ")) return false;

	sencode_int*p;
	CAST_INT (l->items[1], p);
	H = p->i;

	CAST_INT (l->items[2], p);
	hs = p->i;

	sencode_bytes* CAST_BYTES (l->items[3], a);
	check = std::vector<byte> (a->b.begin(), a->b.end());

	return true;
}

#define ENC_MSG_IDENT "CCR-ENCRYPTED-MSG-v2"
#define SIG_MSG_IDENT "CCR-SIGNED-MSG-v2"

sencode* encrypted_msg::serialize()
{
	sencode_list*L = new sencode_list();
	L->items.resize (4);
	L->items[0] = new sencode_bytes (ENC_MSG_IDENT);
	L->items[1] = new sencode_bytes (alg_id);
	L->items[2] = new sencode_bytes (key_id);
	L->items[3] = ciphertext.serialize();
	return L;
}

bool encrypted_msg::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, L);
	if (L->items.size() != 4) return false;

	sencode_bytes*B;

	CAST_BYTES (L->items[0], B);
	if (B->b != ENC_MSG_IDENT) return false;

	CAST_BYTES (L->items[1], B);
	alg_id = B->b;

	CAST_BYTES (L->items[2], B);
	key_id = B->b;

	return ciphertext.unserialize (L->items[3]);
}

sencode* signed_msg::serialize()
{
	sencode_list*L = new sencode_list();
	L->items.resize (5);
	L->items[0] = new sencode_bytes (SIG_MSG_IDENT);
	L->items[1] = new sencode_bytes (alg_id);
	L->items[2] = new sencode_bytes (key_id);
	L->items[3] = message.serialize();
	L->items[4] = signature.serialize();
	return L;
}

bool signed_msg::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, L);
	if (L->items.size() != 5) return false;

	sencode_bytes*B;

	CAST_BYTES (L->items[0], B);
	if (B->b != SIG_MSG_IDENT) return false;

	CAST_BYTES (L->items[1], B);
	alg_id = B->b;

	CAST_BYTES (L->items[2], B);
	key_id = B->b;

	return message.unserialize (L->items[3]) &&
	       signature.unserialize (L->items[4]);
}

/*
 * hashfiles are stored as
 *
 * ( CCR-HASHFILE
 *   ( HASH1NAME HASH1DATA )
 *   ( HASH2NAME HASH2DATA )
 *   ...
 * )
 */

#define HASHFILE_IDENT "CCR-HASHFILE"

sencode* hashfile::serialize()
{
	sencode_list*L = new sencode_list();
	L->items.resize (1 + hashes.size());
	L->items[0] = new sencode_bytes (HASHFILE_IDENT);
	uint pos = 1;
	for (hashes_t::iterator i = hashes.begin(), e = hashes.end(); i != e; ++i, ++pos) {
		sencode_list*hash = new sencode_list();
		hash->items.resize (2);
		hash->items[0] = new sencode_bytes (i->first);
		hash->items[1] = new sencode_bytes (i->second);
		L->items[pos] = hash;
	}

	return L;
}

bool hashfile::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, L);
	if (L->items.size() < 1) return false;

	sencode_bytes*ID;

	CAST_BYTES (L->items[0], ID);
	if (ID->b != HASHFILE_IDENT) return false;

	for (uint pos = 1; pos < L->items.size(); ++pos) {
		sencode_list*CAST_LIST (L->items[pos], hash);
		if (hash->items.size() != 2) return false;

		sencode_bytes*CAST_BYTES (hash->items[0], name);
		sencode_bytes*CAST_BYTES (hash->items[1], value);

		//prevent multiple hash entries of same hash
		if (hashes.count (name->b)) return false;

		hashes[name->b] = std::vector<byte> (value->b.begin(), value->b.end());
	}

	return true;
}

/*
 * Symmetric key structure:
 *
 * ( CCR-SYMKEY
 *   ( streamcipher1 streamcipher2 )
 *   ( hash1 hash2 hash3 )
 *   int_blocksize
 *   key_data
 * )
 */

#define SYMKEY_IDENT "CCR-SYMKEY"

sencode* symkey::serialize()
{
	int k;

	sencode_list*L = new sencode_list(), *LL;
	L->items.resize (5);
	L->items[0] = new sencode_bytes (SYMKEY_IDENT);
	L->items[3] = new sencode_int (blocksize);
	L->items[4] = new sencode_bytes (key);

	std::set<std::string>::iterator i, e;
	LL = new sencode_list();
	LL->items.resize (ciphers.size());
	k = 0;
	for (i = ciphers.begin(), e = ciphers.end();
	     i != e; ++i)
		LL->items[k++] = new sencode_bytes (*i);
	L->items[1] = LL;

	LL = new sencode_list();
	LL->items.resize (hashes.size());
	k = 0;
	for (i = hashes.begin(), e = hashes.end();
	     i != e; ++i)
		LL->items[k++] = new sencode_bytes (*i);
	L->items[2] = LL;

	return L;
}

bool symkey::unserialize (sencode*s)
{
	sencode_list*CAST_LIST (s, L);
	if (L->items.size() != 5) return false;

	sencode_bytes*ID;

	CAST_BYTES (L->items[0], ID);
	if (ID->b != SYMKEY_IDENT) return false;

	sencode_int*CAST_INT (L->items[3], bs);
	blocksize = bs->i;

	sencode_bytes*B;

	CAST_BYTES (L->items[4], B);
	key.clear();
	key.insert (key.begin(), B->b.begin(), B->b.end());

	sencode_list*LL;
	uint i;

	CAST_LIST (L->items[1], LL);
	ciphers.clear();
	for (i = 0; i < LL->items.size(); ++i) {
		CAST_BYTES (LL->items[i], B);
		if (ciphers.count (B->b)) return false;
		ciphers.insert (B->b);
	}

	CAST_LIST (L->items[2], LL);
	hashes.clear();
	for (i = 0; i < LL->items.size(); ++i) {
		CAST_BYTES (LL->items[i], B);
		if (hashes.count (B->b)) return false;
		hashes.insert (B->b);
	}

	return true;
}
