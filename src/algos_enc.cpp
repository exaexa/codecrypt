
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

#include "algos_enc.h"

#include "mce_qd.h"

int algo_mceqd128::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	mce_qd::pubkey Pub;
	mce_qd::privkey Priv;

	if (mce_qd::generate (Pub, Priv, rng, 16, 7, 32, 4) )
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}

int algo_mceqd256::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	mce_qd::pubkey Pub;
	mce_qd::privkey Priv;

	if (mce_qd::generate (Pub, Priv, rng, 16, 8, 32, 4) )
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}


