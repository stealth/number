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


#ifndef number_filters_h
#define number_filters_h

extern "C" {
#include <openssl/bn.h>
}

namespace number {

int filter_bits(BIGNUM *);

int filter_bytes(BIGNUM *);

int filter_hex(BIGNUM *);

int filter_dec(BIGNUM *);

int filter_prime(BIGNUM *);

int filter_b64(BIGNUM *);

int filter_mpi(BIGNUM *);

int filter_ecpoint(BIGNUM *);

int filter_hash(BIGNUM *);

int filter_match(BIGNUM *);

}


#endif

