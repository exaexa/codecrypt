
/*
 * This file is part of Codecrypt.
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
#include "mce.h"
#include "nd.h"
#include "mce_qd.h"
#include "fmtseq.h"

static sencode* serialize_uint_vector (std::vector<uint>*v)
{
	sencode_list*l = new sencode_list;
	l->items.resize (v->size() );
	for (uint i = 0; i < v->size(); ++i)
		l->items[i] = new sencode_int ( (*v) [i]);
	return l;
}

static bool unserialize_uint_vector (std::vector<uint>*v, sencode*s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	v->clear();
	v->resize (l->items.size() );
	for (uint i = 0; i < v->size(); ++i) {
		sencode_int*x = dynamic_cast<sencode_int*> (l->items[i]);
		if (!x) return false;
		(*v) [i] = x->i;
	}
	return true;
}

sencode* bvector::serialize()
{
	uint ss = (size() + 7) / 8;
	std::string bytes;
	bytes.resize (ss, '\0');
	for (uint i = 0; i < size(); ++i)
		if (item (i) ) bytes[i / 8] |= 1 << (i % 8);
	sencode_list*l = new sencode_list;
	l->items.push_back (new sencode_int (size() ) );
	l->items.push_back (new sencode_bytes (bytes) );
	return l;
}

bool bvector::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 2) return false;
	sencode_int*size = dynamic_cast<sencode_int*> (l->items[0]);
	sencode_bytes*bytes = dynamic_cast<sencode_bytes*> (l->items[1]);
	if (! (size && bytes) ) return false;
	if (bytes->b.size() != ( (size->i + 7) / 8) ) return false;
	clear();
	resize (size->i, 0);
	for (uint i = 0; i < size->i; ++i)
		if ( (bytes->b[i / 8] >> (i % 8) ) & 1)
			item (i) = 1;
	return true;
}

sencode* matrix::serialize()
{
	uint bits = width() * height();
	uint ss = (bits + 7) / 8;
	std::string bytes;
	bytes.resize (ss, '\0');
	for (uint i = 0; i < bits; ++i)
		if (item (i / height(), i % height() ) ) bytes[i / 8] |= 1 << (i % 8);
	sencode_list*l = new sencode_list;
	l->items.push_back (new sencode_int (width() ) );
	l->items.push_back (new sencode_int (height() ) );
	l->items.push_back (new sencode_bytes (bytes) );
	return l;
}

bool matrix::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 3) return false;
	sencode_int*w = dynamic_cast<sencode_int*> (l->items[0]);
	sencode_int*h = dynamic_cast<sencode_int*> (l->items[1]);
	sencode_bytes*bytes = dynamic_cast<sencode_bytes*> (l->items[2]);
	if (! (h && w && bytes) ) return false;
	if (bytes->b.size() != ( ( (h->i * w->i) + 7) / 8) ) return false;
	clear();
	resize2 (w->i, h->i, 0);
	for (uint i = 0; i < w->i * h->i; ++i)
		if ( (bytes->b[i / 8] >> (i % 8) ) & 1)
			item (i / h->i, i % h->i) = 1;
	return true;
}

sencode* permutation::serialize()
{
	return serialize_uint_vector (this);
}

bool permutation::unserialize (sencode* s)
{
	if (!unserialize_uint_vector (this, s) ) return false;

	//small sanity check
	for (uint i = 0; i < size(); ++i) if (item (i) >= size() ) return false;

	return true;
}

sencode* gf2m::serialize()
{
	return new sencode_int (m);
}

bool gf2m::unserialize (sencode* s)
{
	sencode_int*p = dynamic_cast<sencode_int*> (s);
	if (!p) return false;
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

sencode* mce::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (6);
	l->items[0] = new sencode_bytes (PRIVKEY_IDENT "MCE");
	l->items[1] = fld.serialize();
	l->items[2] = g.serialize();
	l->items[3] = hperm.serialize();
	l->items[4] = Pinv.serialize();
	l->items[5] = Sinv.serialize();
	return l;
}

bool mce::privkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 6) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PRIVKEY_IDENT "MCE") ) return false;

	if (! (fld.unserialize (l->items[1]) &&
	       g.unserialize (l->items[2]) &&
	       hperm.unserialize (l->items[3]) &&
	       Pinv.unserialize (l->items[4]) &&
	       Sinv.unserialize (l->items[5]) ) ) return false;

	return true;
}

sencode* mce::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (3);
	l->items[0] = new sencode_bytes (PUBKEY_IDENT "MCE");
	l->items[1] = new sencode_int (t);
	l->items[2] = G.serialize();
	return l;
}

bool mce::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 3) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PUBKEY_IDENT "MCE") ) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[0]);
	if (!p) return false;
	t = p->i;

	if (!G.unserialize (l->items[1]) ) return false;

	return true;
}

sencode* nd::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (5);
	l->items[0] = new sencode_bytes (PRIVKEY_IDENT "ND");
	l->items[1] = fld.serialize();
	l->items[2] = g.serialize();
	l->items[3] = Pinv.serialize();
	l->items[4] = Sinv.serialize();
	return l;
}

bool nd::privkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 5) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PRIVKEY_IDENT "ND") ) return false;

	if (! (fld.unserialize (l->items[1]) &&
	       g.unserialize (l->items[2]) &&
	       Pinv.unserialize (l->items[3]) &&
	       Sinv.unserialize (l->items[4]) ) ) return false;

	return true;
}

sencode* nd::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (3);
	l->items[0] = new sencode_bytes (PRIVKEY_IDENT "ND");
	l->items[1] = new sencode_int (t);
	l->items[2] = H.serialize();
	return l;
}

bool nd::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 3) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PRIVKEY_IDENT "ND") ) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[1]);
	if (!p) return false;
	t = p->i;

	if (!H.unserialize (l->items[2]) ) return false;

	return true;
}

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
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 7) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PRIVKEY_IDENT "QD-MCE") ) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[2]);
	if (!p) return false;
	T = p->i;

	if (! (fld.unserialize (l->items[1]) &&
	       unserialize_uint_vector (&essence, l->items[3]) &&
	       block_perm.unserialize (l->items[4]) &&
	       unserialize_uint_vector (&block_perms, l->items[5]) &&
	       hperm.unserialize (l->items[6]) ) ) return false;

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

bool mce_qd::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 3) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PUBKEY_IDENT "QD-MCE") ) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[1]);
	if (!p) return false;
	T = p->i;

	if (!qd_sigs.unserialize (l->items[2]) ) return false;

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
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 3) return false;

	sencode_int*p;
	p = dynamic_cast<sencode_int*> (l->items[0]);
	if (!p) return false;
	level = p->i;

	p = dynamic_cast<sencode_int*> (l->items[1]);
	if (!p) return false;
	pos = p->i;

	sencode_bytes* a = dynamic_cast<sencode_bytes*> (l->items[2]);
	if (!a) return false;
	item = std::vector<byte> (a->b.begin(), a->b.end() );

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

	E->items.resize (exist.size() );
	for (i = 0; i < exist.size(); ++i) {
		sencode_list *t = new sencode_list;
		E->items[i] = t;
		t->items.resize (exist[i].size() );
		for (j = 0; j < exist[i].size(); ++j)
			t->items[j] = new sencode_bytes (exist[i][j]);
	}

	D->items.resize (desired.size() );
	for (i = 0; i < desired.size(); ++i) {
		sencode_list *t = new sencode_list;
		D->items[i] = t;
		t->items.resize (desired[i].size() );
		for (j = 0; j < desired[i].size(); ++j)
			t->items[j] = new sencode_bytes (desired[i][j]);
	}

	S->items.resize (desired_stack.size() );
	for (i = 0; i < desired_stack.size(); ++i) {
		sencode_list *t = new sencode_list;
		S->items[i] = t;
		t->items.resize (desired_stack[i].size() );
		for (j = 0; j < desired_stack[i].size(); ++j)
			t->items[j] = desired_stack[i][j].serialize();
	}

	P->items.resize (desired_progress.size() );
	for (i = 0; i < desired_progress.size(); ++i)
		P->items[i] = new sencode_int (desired_progress[i]);

	return L;
}

bool fmtseq::privkey::unserialize (sencode*s)
{
	uint i, j;
	sencode_list*L = dynamic_cast<sencode_list*> (s);
	if (!L) return false;
	if (L->items.size() != 10) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (L->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PRIVKEY_IDENT "FMTSEQ") ) return false;

	sencode_bytes*B;
	sencode_int*I;

	B = dynamic_cast<sencode_bytes*> (L->items[1]);
	if (!B) return false;
	SK = std::vector<byte> (B->b.begin(), B->b.end() );

	I = dynamic_cast<sencode_int*> (L->items[2]);
	if (!I) return false;
	h = I->i;

	I = dynamic_cast<sencode_int*> (L->items[3]);
	if (!I) return false;
	l = I->i;

	I = dynamic_cast<sencode_int*> (L->items[4]);
	if (!I) return false;
	hs = I->i;

	I = dynamic_cast<sencode_int*> (L->items[5]);
	if (!I) return false;
	sigs_used = I->i;

	sencode_list*A;

	//exist subtrees
	A = dynamic_cast<sencode_list*> (L->items[6]);
	if (!A) return false;
	exist.clear();
	exist.resize (A->items.size() );
	for (i = 0; i < exist.size(); ++i) {
		sencode_list*e = dynamic_cast<sencode_list*> (A->items[i]);
		if (!e) return false;
		exist[i].resize (e->items.size() );
		for (j = 0; j < exist[i].size(); ++j) {
			sencode_bytes*item = dynamic_cast<sencode_bytes*>
			                     (e->items[j]);
			if (!item) return false;
			exist[i][j] = std::vector<byte>
			              (item->b.begin(),
			               item->b.end() );
		}
	}

	//desired subtrees
	A = dynamic_cast<sencode_list*> (L->items[7]);
	if (!A) return false;
	desired.clear();
	desired.resize (A->items.size() );
	for (i = 0; i < desired.size(); ++i) {
		sencode_list*d = dynamic_cast<sencode_list*> (A->items[i]);
		if (!d) return false;
		desired[i].resize (d->items.size() );
		for (j = 0; j < desired[i].size(); ++j) {
			sencode_bytes*item = dynamic_cast<sencode_bytes*>
			                     (d->items[j]);
			if (!item) return false;
			desired[i][j] = std::vector<byte>
			                (item->b.begin(),
			                 item->b.end() );
		}
	}

	//desired stacks
	A = dynamic_cast<sencode_list*> (L->items[8]);
	if (!A) return false;
	desired_stack.clear();
	desired_stack.resize (A->items.size() );
	for (i = 0; i < desired_stack.size(); ++i) {
		sencode_list*d = dynamic_cast<sencode_list*> (A->items[i]);
		if (!d) return false;
		desired_stack[i].resize (d->items.size() );
		for (j = 0; j < desired_stack[i].size(); ++j)
			if (!desired_stack[i][j].unserialize (d->items[j]) )
				return false;
	}

	//desired progress
	A = dynamic_cast<sencode_list*> (L->items[9]);
	if (!A) return false;
	desired_progress.clear();
	desired_progress.resize (A->items.size() );
	for (i = 0; i < desired_progress.size(); ++i) {
		I = dynamic_cast<sencode_int*> (A->items[i]);
		if (!I) return false;
		desired_progress[i] = I->i;
	}

	//TODO check the sizes of everything
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
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 4) return false;

	sencode_bytes*ident = dynamic_cast<sencode_bytes*> (l->items[0]);
	if (!ident) return false;
	if (ident->b.compare (PUBKEY_IDENT "FMTSEQ") ) return false;

	sencode_int*p;
	p = dynamic_cast<sencode_int*> (l->items[1]);
	if (!p) return false;
	H = p->i;

	p = dynamic_cast<sencode_int*> (l->items[2]);
	if (!p) return false;
	hs = p->i;

	sencode_bytes* a = dynamic_cast<sencode_bytes*> (l->items[3]);
	if (!a) return false;
	check = std::vector<byte> (a->b.begin(), a->b.end() );

	return true;
}

