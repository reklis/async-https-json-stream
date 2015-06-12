#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <functional>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>

namespace ahjs
{

using ContentCallback = std::function<void(const std::string&)>;

class AsyncHttpsJsonStream
{

public:

  AsyncHttpsJsonStream(
    boost::asio::io_service& io_service,
    boost::asio::ssl::context& context,
    const std::string& server,
    const std::string& port,
    const std::string& path,
    const std::string& auth_header,
    const std::string& post_body,
    ContentCallback content_handler
  )
    : resolver_(io_service),
      socket_(io_service, context),
      content_handler_(content_handler)
  {
    std::ostream request_stream(&request_);
    request_stream << "POST " << path << " HTTP/1.1\r\n";
    request_stream << "User-Agent: boost/asio 1.58.0\r\n";
    request_stream << "Host: " << server << "\r\n";
    request_stream << "Connection: close\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Authorization: " << auth_header << "\r\n";
    request_stream << "Content-Type: application/x-www-form-urlencoded\r\n";
    request_stream << "Content-Length: " << post_body.length() << "\r\n";

    request_stream << "\r\n" << post_body << "\r\n";

    boost::asio::ip::tcp::resolver::query query(server, port);
    resolver_.async_resolve(query,
        boost::bind(&AsyncHttpsJsonStream::handle_resolve, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::iterator));
  }

private:

  bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
  {
      // char subject_name[256];
      // X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
      // X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
      // std::cout << "Verifying:\n" << subject_name << std::endl;
      // return preverified;

      // accept any certificate
      return true;
  }

  void handle_resolve(const boost::system::error_code& err,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
  {
    if (!err)
    {
      // std::cout << "Resolve OK\n";

      socket_.set_verify_mode(
        boost::asio::ssl::context::verify_none);
      socket_.set_verify_callback(
        boost::bind(&AsyncHttpsJsonStream::verify_certificate, this, _1, _2));

      // socket_.lowest_layer()
      //   .set_option(boost::asio::ip::tcp::no_delay(true));

      // Attempt a connection to each endpoint in the list until we
      // successfully establish a connection.
      boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
          boost::bind(&AsyncHttpsJsonStream::handle_connect, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error(err);
    }
  }

  void handle_connect(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Connect OK\n";

      socket_.async_handshake(boost::asio::ssl::stream_base::client,
              boost::bind(&AsyncHttpsJsonStream::handle_handshake, this,
                  boost::asio::placeholders::error));
    }
    else
    {
      show_error(err);
    }
  }

  void handle_handshake(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Handshake OK\n";

      boost::asio::async_write(socket_, request_,
        boost::bind(&AsyncHttpsJsonStream::handle_write_request, this,
          boost::asio::placeholders::error));
    }
    else
    {
        std::cout << "Handshake failed: " << err.message() << "\n";
    }
  }

  void handle_write_request(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Write OK\n";

      // Read the response status line. The response_ streambuf will
      // automatically grow to accommodate the entire line. The growth may be
      // limited by passing a maximum size to the streambuf constructor.
      boost::asio::async_read_until(socket_, response_, "\r\n",
          boost::bind(&AsyncHttpsJsonStream::handle_read_status_line, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error(err);
    }
  }

  void handle_read_status_line(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Read Status OK\n";

      std::istream response_stream(&response_);
      std::string http_version;
      response_stream >> http_version;
      unsigned int status_code;
      response_stream >> status_code;
      std::string status_message;
      std::getline(response_stream, status_message);

      if (!response_stream || http_version.substr(0, 5) != "HTTP/")
      {
        std::cout << "Invalid response\n";
        return;
      }

      if (status_code != 200)
      {
        std::cout << "Response returned with status code ";
        std::cout << status_code << ":" << status_message << "\n";

        // return;
      }

      // Read the response headers, which are terminated by a blank line.
      boost::asio::async_read_until(socket_, response_, "\r\n",
          boost::bind(&AsyncHttpsJsonStream::handle_read_headers, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error(err);
    }
  }

  void handle_read_headers(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Read Header OK\n";

      consume_response_headers();
      consume_response_content();

    }
    else
    {
      std::cout << "Error: " << err << "\n";
    }
  }

  void handle_read_content(const boost::system::error_code& err)
  {
    if (!err)
    {
      // std::cout << "Read Content OK\n";

      consume_response_content();

    }
    else if (err != boost::asio::error::eof)
    {
      std::cout << "Error: " << err << "\n";
    }
  }

  void consume_response_headers()
  {
    // skip over the response headers
    std::istream response_stream(&response_);
    std::string header;
    while (std::getline(response_stream, header) && header != "\r")
    {
      std::cout << header << "\n";
      continue;
    }
    std::cout << "\n";
  }

  void consume_response_content()
  {
    http_chunk_flag_ = !http_chunk_flag_;

    if (http_chunk_flag_) {
      consume_response_chunksize();

      if (0 != http_chunk_size_) {
        boost::asio::async_read(socket_, response_,
            boost::asio::transfer_at_least(http_chunk_size_+2), // chunk size + \r\n
            boost::bind(&AsyncHttpsJsonStream::handle_read_content, this,
              boost::asio::placeholders::error));
      } else {
        http_chunk_flag_ = !http_chunk_flag_;
        boost::asio::async_read_until(socket_, response_, "\r\n",
            boost::bind(&AsyncHttpsJsonStream::handle_read_content, this,
              boost::asio::placeholders::error));
      }

    } else {
      consume_response_chunkdata();

      boost::asio::async_read_until(socket_, response_, "\r\n",
          boost::bind(&AsyncHttpsJsonStream::handle_read_content, this,
            boost::asio::placeholders::error));
    }
  }

  void consume_response_chunksize()
  {
    std::stringstream ss;
    ss << std::hex << &response_;
    ss >> http_chunk_size_;

    // std::cout << "chunk size:" << http_chunk_size_ << std::endl;
  }

  void consume_response_chunkdata()
  {
    std::istream response_stream(&response_);

    // std::cout << "data: \t";

    char c;
    while (response_stream.get(c))
    {
      // std::cout << c;

      // skip non-printable characters
      // if ((c < 32) || (c > 126)) continue;

      // read into the string buffer when we are inside an object
      if (
        ('{' == c)
        ||
        ('}' == c)
        ||
        (0 != json_indent)
      ) {
        ++json_size;
        json_buffer << c;
      }

      // increment / decrement based on object literals
      if ('{' == c) {
        ++json_indent;
      } else if ('}' == c) {
        --json_indent;
      }

      // yield complete objects
      if (
        (0 == json_indent)
        &&
        (0 != json_size)
      ) {
        // std::cout << "json size:\t" << json_size << '\n';
        content_handler_(json_buffer.str());
        json_indent = -1;
      }

      // reset the buffer
      if (0 > json_indent) {
        json_buffer.str(std::string());
        json_buffer.clear();
        json_size = 0;
        json_indent = 0;
      }
    }

    // std::cout << std::endl;
  }

  void show_error(const boost::system::error_code& error)
  {
    std::cout << "Error: " << error.message() << "\n";
  }

  boost::asio::ip::tcp::resolver resolver_;

  // boost::asio::ip::tcp::socket socket_;
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;

  boost::asio::streambuf request_;
  boost::asio::streambuf response_;

  ContentCallback content_handler_;

  // Transfer-Encoding: chunked
  // http://en.wikipedia.org/wiki/Chunked_transfer_encoding
  bool http_chunk_flag_;
  int http_chunk_size_;

  int json_indent;
  int json_size;
  std::stringstream json_buffer;
};

}