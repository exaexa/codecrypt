
#include "codecrypt.h"

using namespace ccr;

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

sencode* mce::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (5);
	l->items[0] = fld.serialize();
	l->items[1] = g.serialize();
	l->items[2] = hperm.serialize();
	l->items[3] = Pinv.serialize();
	l->items[4] = Sinv.serialize();
	return l;
}

bool mce::privkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 5) return false;

	if (! (fld.unserialize (l->items[0]) &&
	       g.unserialize (l->items[1]) &&
	       hperm.unserialize (l->items[2]) &&
	       Pinv.unserialize (l->items[3]) &&
	       Sinv.unserialize (l->items[4]) ) ) return false;

	return true;
}

sencode* mce::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (2);
	l->items[0] = new sencode_int (t);
	l->items[1] = G.serialize();
	return l;
}

bool mce::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 2) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[0]);
	if (!p) return false;
	t = p->i;

	if (!G.unserialize (l->items[1]) ) return false;

	return true;
}

sencode* nd::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (4);
	l->items[0] = fld.serialize();
	l->items[1] = g.serialize();
	l->items[2] = Pinv.serialize();
	l->items[3] = Sinv.serialize();
	return l;
}

bool nd::privkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 4) return false;

	if (! (fld.unserialize (l->items[0]) &&
	       g.unserialize (l->items[1]) &&
	       Pinv.unserialize (l->items[2]) &&
	       Sinv.unserialize (l->items[3]) ) ) return false;

	return true;
}

sencode* nd::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (2);
	l->items[0] = new sencode_int (t);
	l->items[1] = H.serialize();
	return l;
}

bool nd::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 2) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[0]);
	if (!p) return false;
	t = p->i;

	if (!H.unserialize (l->items[1]) ) return false;

	return true;
}

sencode* mce_qd::privkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (6);
	l->items[0] = fld.serialize();
	l->items[1] = new sencode_int (T);
	l->items[2] = serialize_uint_vector (&essence);
	l->items[3] = block_perm.serialize();
	l->items[4] = serialize_uint_vector (&block_perms);
	l->items[5] = hperm.serialize();
	return l;
}

bool mce_qd::privkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 6) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[1]);
	if (!p) return false;
	T = p->i;

	if (! (fld.unserialize (l->items[0]) &&
	       unserialize_uint_vector (&essence, l->items[2]) &&
	       block_perm.unserialize (l->items[3]) &&
	       unserialize_uint_vector (&block_perms, l->items[4]) &&
	       hperm.unserialize (l->items[5]) ) ) return false;

	return true;
}

sencode* mce_qd::pubkey::serialize()
{
	sencode_list*l = new sencode_list;
	l->items.resize (2);
	l->items[0] = new sencode_int (T);
	l->items[1] = qd_sigs.serialize();
	return l;
}

bool mce_qd::pubkey::unserialize (sencode* s)
{
	sencode_list*l = dynamic_cast<sencode_list*> (s);
	if (!l) return false;
	if (l->items.size() != 2) return false;

	sencode_int*p = dynamic_cast<sencode_int*> (l->items[0]);
	if (!p) return false;
	T = p->i;

	if (!qd_sigs.unserialize (l->items[1]) ) return false;

	return true;
}

sencode* cfs_qd::privkey::serialize()
{

}

bool cfs_qd::privkey::unserialize (sencode* s)
{

}

sencode* cfs_qd::pubkey::serialize()
{

}

bool cfs_qd::pubkey::unserialize (sencode* s)
{

}

sencode* mce_oc::privkey::serialize()
{

}

bool mce_oc::privkey::unserialize (sencode* s)
{

}

sencode* mce_oc::pubkey::serialize()
{

}

bool mce_oc::pubkey::unserialize (sencode* s)
{

}

