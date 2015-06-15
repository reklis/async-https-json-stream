#include <iostream>
#include <istream>
#include <string>

#include <liboauthcpp/liboauthcpp.h>

#include <picojson.h>

#include "./async_https_json_stream.hpp"

std::string tw_stream_host = "stream.twitter.com";
std::string tw_stream_port = "443";
std::string tw_stream_endpoint = "/1.1/statuses/filter.json";
std::string tw_stream_url = "https://" + tw_stream_host + tw_stream_endpoint;

int main(int argc, char** argv) {
    std::string consumer_key = std::getenv("tw_consumer_key");
    std::string consumer_secret = std::getenv("tw_consumer_secret");
    std::string oauth_token = std::getenv("tw_oauth_token");
    std::string oauth_token_secret = std::getenv("tw_oauth_token_secret");

    if (!consumer_key.length())
        return 1;

    if (!consumer_secret.length())
        return 2;

    if (!oauth_token.length())
        return 3;

    if (!oauth_token_secret.length())
        return 4;

    std::cout << "term to track (ex: apple): ";
    std::string tw_track_value;
    std::getline(std::cin, tw_track_value);

    std::string tw_stream_params = "track=" + tw_track_value;

    // setup oauth header using liboauthcpp
    OAuth::Consumer consumer(consumer_key, consumer_secret);
    OAuth::Token token(oauth_token, oauth_token_secret);
    OAuth::Client oauth(&consumer, &token);

    std::string oAuthHeader =
        oauth.getHttpHeader(
            OAuth::Http::Post,
            tw_stream_url,
            tw_stream_params);

    std::cout << "example curl command\n";
    std::cout << "curl -XPOST"
        << " '" << tw_stream_url << "'"
        << " --header 'Authorization: " << oAuthHeader << "'"
        << " --data '" << tw_stream_params << "'"
        << "\n\n";


    // setup
    boost::asio::io_service io_service;
    boost::asio::ssl::context io_context(boost::asio::ssl::context::sslv23);
    // io_context.set_default_verify_paths();

    int tweet_max = 10;
    int tweet_count;

    ahjs::AsyncHttpsJsonStream c(
        io_service,
        io_context,
        tw_stream_host,
        tw_stream_port,
        tw_stream_endpoint,
        oAuthHeader,
        tw_stream_params,
        [&tweet_max, &tweet_count] (const std::string& json) {

            picojson::value v;
            std::string err = picojson::parse(v, json);

            if (!err.empty()) {
              std::cout << "json parser error: " << err << std::endl;
              return;
            }

            if (v.is<picojson::object>()) {

                auto& t = v.get<picojson::object>();
                const auto& user = t["user"];

                if (user.is<picojson::object>()) {

                    const auto& screen_name = user.get("screen_name");
                    const auto& text = t["text"];

                    std::cout << "\n\t@" << screen_name.to_str() << '\n';
                    std::cout << '\t' << text.to_str() << "\n\n";

                    if (++tweet_count == tweet_max) {
                        exit(0);
                    }

                }

            }

        }
    );

    c.debug(true);

    io_service.run();

    return 0;
}
