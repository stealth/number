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

#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include "filters.h"
#include "number.h"

using namespace std;
using namespace number;


void usage()
{
	printf("\nnumber (C) 2018 Sebastian Krahmer -- https://github.com/stealth/number\n\n"
	       " number <-xdbm number> [-XDBM]\n\n"
	       "\t-x input is hex\n"
	       "\t-d input is dec\n"
	       "\t-b input is base64 BIGNUM (base64(BN_bn2bin()) output)\n"
	       "\t-m input is base64 MPI\n"
	       "\t-X add hex output filter\n"
	       "\t-D add dec output filter\n"
	       "\t-B add base64 BIGNUM output filter\n"
	       "\t-L add LE output filter (does not affect other out filters)\n"
	       "\t-M add base64 MPI output filter\n\n");

	exit(1);

}


int main(int argc, char **argv)
{
	number::number num;
	enum modes : uint32_t {
		MODE_INVALID	= 0,
		INMODE_HEX	= 1,
		INMODE_DEC	= 2,
		INMODE_B64	= 4,
		INMODE_MPI	= 8,
		OUTMODE_HEX	= 0x1000,
		OUTMODE_DEC	= 0x2000,
		OUTMODE_B64	= 0x4000,
		OUTMODE_MPI	= 0x8000,
		OUTMODE_LE	= 0x10000
	};
	uint32_t mode = modes::MODE_INVALID;
	int c;
	string n = "", filter = "";

	while ((c = getopt(argc, argv, "x:d:b:m:XDBML")) != -1) {
		switch (c) {
		case 'x':
			n = optarg;
			mode |= modes::INMODE_HEX;
			break;
		case 'd':
			n = optarg;
			mode |= modes::INMODE_DEC;
			break;
		case 'b':
			n = optarg;
			mode |= modes::INMODE_B64;
			break;
		case 'm':
			n = optarg;
			mode |= modes::INMODE_MPI;
			break;
		case 'X':
			mode |= modes::OUTMODE_HEX;
			break;
		case 'D':
			mode |= modes::OUTMODE_DEC;
			break;
		case 'B':
			mode |= modes::OUTMODE_B64;
			break;
		case 'M':
			mode |= modes::OUTMODE_MPI;
			break;
		case 'L':
			mode |= modes::OUTMODE_LE;
			break;
		default:
			usage();
		}
	}


	if (mode & modes::INMODE_HEX) {
		if (n.find("0x") == 0)
			n.erase(0, 2);
		num.import_hex(n);
	} else if (mode & modes::INMODE_DEC) {
		num.import_dec(n);
	} else if (mode & modes::INMODE_B64) {
		num.import_b64(n, 0);
	} else if (mode & modes::INMODE_MPI) {
		num.import_b64(n, 1);
	}

	if (mode & modes::OUTMODE_HEX)
		num.add_filter("hex", filter_hex);
	if (mode & modes::OUTMODE_DEC)
		num.add_filter("dec", filter_dec);
	if (mode & modes::OUTMODE_B64)
		num.add_filter("base64", filter_b64);
	if (mode & modes::OUTMODE_MPI)
		num.add_filter("mpi", filter_mpi);
	if (mode & modes::OUTMODE_LE)
		num.add_filter("le", filter_le);

	num.run_filter(filter);
	return 0;
}


