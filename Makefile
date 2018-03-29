
CXX=c++
LD=c++
DEFS=
INC=
LIBS=
LDFLAGS=

# reported to work with OSX brew
#INC+=-I/opt/local/include
#LIBS+=-L/opt/local/lib

# my alternate openssl path for 1.1.0
#INC+=-I/usr/local/ossl-1.1.0f/include
#LIBS+=-L/usr/local/ossl-1.1.0f/lib
#LIBS+=-Wl,--rpath=/usr/local/ossl-1.1.0f/lib


# LibreSSL setups, define your paths here
#INC+=-I/usr/local/libressl/include
#LIBS+=-L/usr/local/libressl/lib64
#LIBS+=-Wl,--rpath=/usr/local/libressl/lib64
#DEFS+=-DHAVE_LIBRESSL


CXXFLAGS=-O2 -pedantic -Wall -std=c++11 $(INC) $(DEFS)
LIBS+=-lcrypto

all: number

clean:
	rm -rf *.o

number: number.o main.o filters.o base64.o
	$(LD) number.o filters.o main.o base64.o $(LDFLAGS) $(LIBS) -o $@

main.o: main.cc
	$(CXX) -c $(CXXFLAGS) $<

base64.o: base64.cc base64.h
	$(CXX) -c $(CXXFLAGS) $<

number.o: number.cc number.h
	$(CXX) -c $(CXXFLAGS) $<

filters.o: filters.cc filters.h
	$(CXX) -c $(CXXFLAGS) $<

install:
	cp -r share /usr/share/number
	chown root.root /usr/share/number
	chown root.root /usr/share/number/numbers.txt
	chmod 0755 /usr/share/number
	chmod 0644 /usr/share/number/numbers.txt

