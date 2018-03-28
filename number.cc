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

#include <string>
#include <map>
#include <functional>
#include "base64.h"
#include "number.h"

extern "C" {
#include <openssl/bn.h>
}


using namespace std;


namespace number {


int number::add_filter(const string &name, const function<int(BIGNUM *)> &f)
{
	d_filter.emplace(make_pair(name, f));
	return 0;
}


int number::run_filter(const string &name)
{
	if (name.size() == 0) {
		for (auto i = d_filter.begin(); i != d_filter.end(); ++i)
			i->second(d_bn);
		return 0;
	}

	auto it = d_filter.find(name);
	if (it == d_filter.end())
		return -1;

	return it->second(d_bn);
}


int number::import_hex(const string &s)
{
	if (BN_hex2bn(&d_bn, s.c_str()) == 0)
		return -1;

	return 0;
}


int number::import_dec(const string &s)
{
	if (BN_dec2bn(&d_bn, s.c_str()) == 0)
		return -1;

	return 0;
}


int number::import_b64(const string &b64, bool mpi)
{
	string s = "";
	if (b64_decode(b64, s).size() == 0)
		return -1;

	function<BIGNUM *(const unsigned char *, int, BIGNUM *)> f = BN_bin2bn;

	if (mpi)
		f = BN_mpi2bn;

	if (!(d_bn = f(reinterpret_cast<const unsigned char *>(s.c_str()), s.size(), nullptr)))
			return -1;

	return 0;
}


}

