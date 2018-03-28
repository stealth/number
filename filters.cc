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

	bool has_point = 0;

	map<string, int> name2nid{
		{"secp521r1", NID_secp521r1},
		{"secp384r1", NID_secp384r1},
		{"sect283k1", NID_sect283k1},
		{"sect283r1", NID_sect283r1},
		{"sect409k1", NID_sect409k1},
		{"sect409r1", NID_sect409r1},
		{"secp256k1", NID_secp256k1},
		{"sect571k1", NID_sect571k1},
		{"sect571r1", NID_sect571r1}
	};

	free_ptr<EC_GROUP> ecg(nullptr, EC_GROUP_free);
	EC_POINT *ecp = nullptr;
	for (auto it = name2nid.begin(); it != name2nid.end(); ++it) {
		ecg.reset(EC_GROUP_new_by_curve_name(it->second));
		if (!ecg.get())
			continue;
		if ((ecp = EC_POINT_bn2point(ecg.get(), bn, nullptr, nullptr)) != nullptr) {
			EC_POINT_free(ecp);
			printf("ec-point: %s\n", it->first.c_str());
			has_point = 1;
		}
	}

	if (!has_point)
		printf("ec-point: No\n");

	return 0;
}


int filter_hash(BIGNUM *bn)
{
	if (!bn)
		return -1;

	map<int, string> bits2hash{
		{128, "MD4, MD5"},
		{160, "SHA1, RIPEMD-160"},
		{192, "TIGER"},
		{256, "SHA256"},
		{512, "SHA512"}
	};

	int n = BN_num_bits(bn);
	auto it = bits2hash.find(n);
	printf("hash: %s\n", (it == bits2hash.end()) ? "No" : it->second.c_str());
	return 0;
}


// helper function to remove int return
void fclose(FILE *f)
{
	::fclose(f);
}


int filter_match_ssh(BIGNUM *bn)
{
	if (!bn)
		return -1;

	// check ssh moduli
	free_ptr<FILE> f(fopen("/etc/ssh/moduli", "r"), number::fclose);
	if (!f.get())
		return -1;

	bool has_moduli = 0;
	char buf[8192] = {0};
	string line = "";
	string::size_type idx = 0;
	free_ptr<BIGNUM> moduli(nullptr, BN_free);
	BIGNUM *bn2 = nullptr;

	for (;!feof(f.get());) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf) - 1, f.get()))
			break;
		line = buf;
		if ((idx = line.rfind(" ")) == string::npos)
			continue;
		line.erase(0, idx + 1);
		bn2 = nullptr;
		if (BN_hex2bn(&bn2, line.c_str()) == 0)
			continue;
		moduli.reset(bn2);
		if (BN_cmp(bn, moduli.get()) == 0) {
			has_moduli = 1;
			break;
		}
	}

	printf("SSH moduli: %s\n", has_moduli ? "Yes" : "No");
	return 0;
}



}
