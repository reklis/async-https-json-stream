# Async JSON stream

c++ header-only async http library to stream json to a lambda using boost asio

in a nutshell:

    ahjs::AsyncHttpsJsonStream c(
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

The boost io context settings are used to validate the certificate chain.

### debug logging

    c.debug(true);

### error handling

    c.on_error([&c] (auto error, auto code)
    {

        std::cerr << "stream error: " << error
            << "\ncode: " << code << '\n';

        /* error codes are defined as an enum

        enum StreamErrorCode {
          Resolve = 1,
          Connect,
          Handshake,
          Write,
          ReadHeader,
          ReadStatus,
          StatusValue,
          ReadContent
        };

        */

    });


### stopping the stream

    c.stop();
    // plus whatever io_context cleanup

### running the test

    # fetch and compile dependencies
    git submodule update --init
    pushd liboauthcpp/build
    cmake .
    make
    popd

    # edit .env to setup your environment variables
    cp .env.sample.sh .env
    # export tw_consumer_key="..."
    # export tw_consumer_secret="..."
    # export tw_oauth_token="..."
    # export tw_oauth_token_secret="..."
    source .env

    # compile
    make clean all

    # run
    ./test.o

### contributing

fork and send me a pull request or submit a bug with a standard unix patch file

### license

GNU GPL v3