/*
 * This file is part of the number framework.
 *
 * (C) 2018 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
 *
 * number is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * number is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with number.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef number_number_h
#define number_number_h

#include <cstdio>
#include <unordered_map>
#include <functional>
#include "filters.h"


extern "C" {
#include <openssl/bn.h>
}


namespace number {


class number {

	BIGNUM *d_bn{nullptr};

	std::unordered_map<std::string, std::function<int(BIGNUM *)>> d_filter{
		{"bits", filter_bits},
		{"bytes", filter_bytes},
		{"prime", filter_prime},
		{"ecpoint", filter_ecpoint},
		{"hash", filter_hash},
		{"ssh-moduli", filter_match_ssh}
	};

public:

	number()
	{
	}


	~number()
	{
		if (d_bn)
			BN_free(d_bn);
	}


	int import_dec(const std::string &);

	int import_hex(const std::string &);

	int import_b64(const std::string &, bool mpi = 0);

	int add_filter(const std::string &, const std::function<int(BIGNUM*)> &);

	int run_filter(const std::string &);

};

}

#endif

