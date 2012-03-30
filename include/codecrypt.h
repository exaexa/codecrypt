
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <vector>

namespace ccr {

	typedef std::vector<bool> bvector;
	//for broken/old/weird STL uncomment this:
	//typedef std::bit_vector bvector;
	//TODO ifdef
	
	class matrix : public std::vector<bvector> {

	};

	class permutation : public vector<unsigned int> {

	};

	class polynomial : public bvector {

	};

	namespace mce {
		class privkey {
		public:
			matrix 

			int decrypt(const bvector&, bvector&);
		};

		class pubkey {
		public:
			matrix G;
			int t;
			int encrypt(const bvector&, bvector&);
		};

		int generate(pubkey&,privkey&);
	}

	namespace nd {
		class privkey {

			int decrypt(const bvector&, bvector&);
		};

		class pubkey {
		public:
			matrix H;
			int t;

			int encrypt(const bvector&, bvector&);
		};

		int generate(pubkey&,privkey&);
	}

	//TODO entropy sources

} //namespace CCR

#endif // _CODECRYPT_H_

