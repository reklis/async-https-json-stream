# Async JSON stream

c++ header-only async http library to stream json to a lambda using boost asio

in a nutshell:

    AsyncHttpsJsonClient c(
        io_service,
        io_context,
        "httpbin.org",
        "443",
        "/post",
        "Basic test:test",
        "foo=bar",
        [] (const std::string& json) {

            std::cout << json << '\n';

        }
    );

primarily designed and built to work with twitter streams and chunked http json responses
see test.cpp for example code that uses twitter OAuth and picojson for parsing

currently accepts any certificate as valid for testing instead of properly validating certificate chain

### running the test

# edit .env to setup your environment variables
cp .env.sample.sh .env
source .env

# compile
make

# run
./test.o
