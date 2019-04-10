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

#include <cstdio>
#include <cstring>
#include <string>
#include <memory>
#include <map>
#include "base64.h"
#include "filters.h"

extern "C" {
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
}


namespace number {

using namespace std;


// unique_ptr helper type
template<class T> using free_ptr = std::unique_ptr<T, void (*)(T *)>;


int filter_bits(BIGNUM *bn)
{
	if (!bn)
		return -1;

	printf("bits: %d\n", BN_num_bits(bn));
	return 0;
}


int filter_bytes(BIGNUM *bn)
{
	if (!bn)
		return -1;

	printf("bytes: %d\n", BN_num_bytes(bn));
	return 0;
}


int filter_dec(BIGNUM *bn)
{
	if (!bn)
		return -1;
	char *tmp = BN_bn2dec(bn);
	printf("dec: %s\n", tmp);
	OPENSSL_free(tmp);
	return 0;
}


int filter_hex(BIGNUM *bn)
{
	if (!bn)
		return -1;
	char *tmp = BN_bn2hex(bn);
	printf("hex: %s\n", tmp);
	OPENSSL_free(tmp);
	return 0;
}


int filter_b64(BIGNUM *bn)
{
	if (!bn)
		return -1;

	int n = BN_num_bytes(bn);
	unique_ptr<unsigned char[]> tmp(new (nothrow) unsigned char[n]);
	if (!tmp.get())
		return -1;
	if (BN_bn2bin(bn, tmp.get()) != n)
		return -1;

	string b64, tmps = string(reinterpret_cast<char *>(tmp.get()), n);
	printf("base64: %s\n", b64_encode(tmps, b64).c_str());
	return 0;
}


int filter_mpi(BIGNUM *bn)
{
	if (!bn)
		return -1;

	int n = BN_bn2mpi(bn, nullptr);
	unique_ptr<unsigned char[]> tmp(new (nothrow) unsigned char[n]);
	if (!tmp.get())
		return -1;
	if (BN_bn2mpi(bn, tmp.get()) != n)
		return -1;

	string b64, tmps = string(reinterpret_cast<char *>(tmp.get()), n);
	printf("MPI base64: %s\n", b64_encode(tmps, b64).c_str());
	return 0;
}


int filter_prime(BIGNUM *bn)
{
	if (!bn)
		return -1;
	int isprime = BN_is_prime_ex(bn, BN_prime_checks, nullptr, nullptr);
	printf("prime: %s\n", isprime ? "Yes" : "No");
	return 0;
}


int filter_ecpoint(BIGNUM *bn)
{
	if (!bn)
		return -1;

	map<string, int> name2nid{
#ifdef NID_brainpoolP160r1
		{"brainpoolP160r1", NID_brainpoolP160r1},
		{"brainpoolP160t1", NID_brainpoolP160t1},
		{"brainpoolP192r1", NID_brainpoolP192r1},
		{"brainpoolP192t1", NID_brainpoolP192t1},
		{"brainpoolP224r1", NID_brainpoolP224r1},
		{"brainpoolP224t1", NID_brainpoolP224t1},
		{"brainpoolP256r1", NID_brainpoolP256r1},
		{"brainpoolP256t1", NID_brainpoolP256t1},
		{"brainpoolP320r1", NID_brainpoolP320r1},
		{"brainpoolP320t1", NID_brainpoolP320t1},
		{"brainpoolP384r1", NID_brainpoolP384r1},
		{"brainpoolP384t1", NID_brainpoolP384t1},
		{"brainpoolP512r1", NID_brainpoolP512r1},
		{"brainpoolP512t1", NID_brainpoolP512t1},
#endif
		{"secp112r1", NID_secp112r1},
		{"secp112r2", NID_secp112r2},
		{"secp128r1", NID_secp128r1},
		{"secp128r2", NID_secp128r2},
		{"secp160k1", NID_secp160k1},
		{"secp160r1", NID_secp160r1},
		{"secp160r2", NID_secp160r2},
		{"secp192k1", NID_secp192k1},
		{"secp224k1", NID_secp224k1},
		{"secp224r1", NID_secp224r1},
		{"sect113r1", NID_sect113r1},
		{"sect113r2", NID_sect113r2},
		{"sect131r1", NID_sect131r1},
		{"sect131r2", NID_sect131r2},
		{"sect163k1", NID_sect163k1},
		{"sect163r1", NID_sect163r1},
		{"sect163r2", NID_sect163r2},
		{"sect193r1", NID_sect193r1},
		{"sect193r2", NID_sect193r2},
		{"sect233k1", NID_sect233k1},
		{"sect233r1", NID_sect233r1},
		{"sect239k1", NID_sect239k1},
		{"secp521r1", NID_secp521r1},
		{"secp384r1", NID_secp384r1},
		{"sect283k1", NID_sect283k1},
		{"sect283r1", NID_sect283r1},
		{"sect409k1", NID_sect409k1},
		{"sect409r1", NID_sect409r1},
		{"secp256k1", NID_secp256k1},
		{"sect571k1", NID_sect571k1},
		{"sect571r1", NID_sect571r1},
		{"prime192v1", NID_X9_62_prime192v1},
		{"prime192v2", NID_X9_62_prime192v2},
		{"prime192v3", NID_X9_62_prime192v3},
		{"prime239v1", NID_X9_62_prime239v1},
		{"prime239v2", NID_X9_62_prime239v2},
		{"prime239v3", NID_X9_62_prime239v3},
		{"prime256v1", NID_X9_62_prime256v1}
	};

	free_ptr<EC_GROUP> ecg(nullptr, EC_GROUP_free);
	free_ptr<BIGNUM> p(BN_new(), BN_free), a(BN_new(), BN_free), b(BN_new(), BN_free);
	if (!p.get() || !a.get() || !b.get())
		return -1;

	EC_POINT *ecp = nullptr;
	string r = "";
	for (auto it = name2nid.begin(); it != name2nid.end(); ++it) {
		ecg.reset(EC_GROUP_new_by_curve_name(it->second));
		if (!ecg.get())
			continue;
		// EC_GROUP_get_curve_GFp is as good as the GF2m variant, as its just a wrapper
		// for the ->meth->group_get_curve() call
		if (EC_GROUP_get_curve_GFp(ecg.get(), p.get(), a.get(), b.get(), nullptr) == 1) {
			if (BN_cmp(p.get(), bn) == 0)
				r += it->first + " prime,";
			else if (BN_cmp(a.get(), bn) == 0)
				r += it->first + " a,";
			else if (BN_cmp(b.get(), bn) == 0)
				r += it->first + " b,";
		}
		if ((ecp = EC_POINT_bn2point(ecg.get(), bn, nullptr, nullptr)) != nullptr) {
			EC_POINT_free(ecp);
			r += it->first + " point,";
		}
	}

	printf("ec: %s\n", r.size() > 0 ? r.c_str() : "No");

	return 0;
}


int filter_le(BIGNUM *bn)
{
	if (!bn)
		return -1;

	int n = 0;
	if ((n = BN_num_bytes(bn)) < 0)
		return -1;

	unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[n]);
	if (!bin.get())
		return -1;

	BN_bn2bin(bn, bin.get());

	free_ptr<BIGNUM> lebn(BN_lebin2bn(bin.get(), n, nullptr), BN_free);
	if (!lebn.get())
		return -1;

	printf("le: %s\n", BN_bn2hex(lebn.get()));
	return 0;
}


int filter_hash(BIGNUM *bn)
{
	if (!bn)
		return -1;

	map<int, string> bytes2hash{
		{16, "MD4, MD5"},
		{20, "SHA1, RIPEMD-160"},
		{24, "TIGER"},
		{32, "SHA256"},
		{64, "SHA512"}
	};

	int n = BN_num_bytes(bn);
	auto it = bytes2hash.find(n);
	printf("hash: %s\n", (it == bytes2hash.end()) ? "No" : it->second.c_str());
	return 0;
}


// helper function to remove int return
void fclose(FILE *f)
{
	::fclose(f);
}


int filter_match(BIGNUM *bn)
{
	if (!bn)
		return -1;

	// check match DB
	free_ptr<FILE> f(fopen("/usr/share/number/numbers.txt", "r"), number::fclose);
	if (!f.get())
		return -1;

	bool match = 0;
	char buf[8192] = {0};
	string line = "", s1 = "", s2 = "";
	string::size_type idx = 0;
	free_ptr<BIGNUM> moduli(nullptr, BN_free);
	BIGNUM *bn2 = nullptr;

	for (;!feof(f.get());) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf) - 1, f.get()))
			break;
		line = buf;
		if ((idx = line.find(",")) == string::npos)
			continue;
		s1 = line.substr(0, idx);
		line.erase(0, idx + 1);
		if ((idx = line.find(",")) == string::npos)
			continue;
		s2 = line.substr(0, idx);
		bn2 = nullptr;
		if (BN_hex2bn(&bn2, s1.c_str()) == 0)
			continue;
		moduli.reset(bn2);
		if (BN_cmp(bn, moduli.get()) == 0) {
			match = 1;
			break;
		}
	}

	printf("match: %s\n", match ? s2.c_str() : "No");
	return 0;
}



}

