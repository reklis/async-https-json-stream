OAUTH=-I./liboauthcpp/include -L./liboauthcpp -loauthcpp
PICOJSON=-I./picojson/
BOOST=-I/usr/local/Cellar/boost/1.58.0/include -L/usr/local/Cellar/boost/1.58.0/lib -lboost_system -lboost_iostreams
OPENSSL=-I/usr/local/Cellar/openssl/1.0.2/include -L/usr/local/Cellar/openssl/1.0.2/lib -lcrypto -lssl

all: test.o

test.o:
	clang++ --std=c++1y test.cpp -o test.o $(OAUTH) $(BOOST) $(OPENSSL) $(PICOJSON)

clean:
	rm -f *.o
