#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <functional>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>

namespace ahjs
{

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

using ContentCallback = std::function<void(const std::string&)>;
using ErrorCallback = std::function<void(const std::string&, const StreamErrorCode)>;

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

  void debug(bool d)
  {
    debug_log_ = d;
  }

  void stop()
  {
    active_ = false;
  }

  void on_error(ErrorCallback cb)
  {
    error_handler_ = cb;
  }

private:

  bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
  {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

    if (debug_log_)
    {
      std::cout << "Certificate Subject:\n" << subject_name
        << "\nPreverified: " << preverified << '\n';
    }

    return preverified;
  }

  void handle_resolve(const boost::system::error_code& err,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Resolve OK");

      socket_.set_verify_callback(
        boost::bind(&AsyncHttpsJsonStream::verify_certificate, this, _1, _2));

      // socket_.lowest_layer()
      //   .set_option(boost::asio::ip::tcp::no_delay(true));

      boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
          boost::bind(&AsyncHttpsJsonStream::handle_connect, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error("Resolve Failed", StreamErrorCode::Resolve, &err);
    }
  }

  void handle_connect(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Connect OK");

      socket_.async_handshake(boost::asio::ssl::stream_base::client,
              boost::bind(&AsyncHttpsJsonStream::handle_handshake, this,
                  boost::asio::placeholders::error));
    }
    else
    {
      show_error("Connect Failed", StreamErrorCode::Connect, &err);
    }
  }

  void handle_handshake(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Handshake OK");

      boost::asio::async_write(socket_, request_,
        boost::bind(&AsyncHttpsJsonStream::handle_write_request, this,
          boost::asio::placeholders::error));
    }
    else
    {
      show_error("Handshake Failed", StreamErrorCode::Handshake, &err);
    }
  }

  void handle_write_request(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Write OK");

      boost::asio::async_read_until(socket_, response_, "\r\n",
          boost::bind(&AsyncHttpsJsonStream::handle_read_status_line, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error("Write Failed", StreamErrorCode::Write, &err);
    }
  }

  void handle_read_status_line(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Read Status OK");

      std::istream response_stream(&response_);
      std::string http_version;
      response_stream >> http_version;
      unsigned int status_code;
      response_stream >> status_code;
      std::string status_message;
      std::getline(response_stream, status_message);

      if (!response_stream || http_version.substr(0, 5) != "HTTP/")
      {
        show_error("Invalid response", StreamErrorCode::ReadStatus);
        return;
      }

      if (debug_log_)
      {
        std::cout << "HTTP Status: "
          << status_code << ":" << status_message << '\n';
      }

      if ((status_code < 200) || (status_code > 299))
      {
        show_error("Response status code not OK", StreamErrorCode::StatusValue);
        return;
      }

      boost::asio::async_read_until(socket_, response_, "\r\n",
          boost::bind(&AsyncHttpsJsonStream::handle_read_headers, this,
            boost::asio::placeholders::error));
    }
    else
    {
      show_error("Read Status Failed", StreamErrorCode::ReadStatus, &err);
    }
  }

  void handle_read_headers(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Read Header OK");

      consume_response_headers();
      consume_response_content();
    }
    else
    {
      show_error("Read Header Failed", StreamErrorCode::ReadHeader, &err);
    }
  }

  void handle_read_content(const boost::system::error_code& err)
  {
    if (!active_) return;

    if (!err)
    {
      debug_log("Read Content OK");

      consume_response_content();
    }
    else if (err != boost::asio::error::eof)
    {
      show_error("Read Content Failed", StreamErrorCode::ReadContent, &err);
    }
  }

  void consume_response_headers()
  {
    std::istream response_stream(&response_);
    std::string header;
    while (std::getline(response_stream, header) && header != "\r")
    {
      debug_log(header);
    }
  }

  void consume_response_content()
  {
    http_chunk_flag_ = !http_chunk_flag_;

    if (http_chunk_flag_)
    {
      consume_response_chunksize();

      if (0 != http_chunk_size_)
      {
        boost::asio::async_read(socket_, response_,
            boost::asio::transfer_at_least(http_chunk_size_+2), // chunk size + \r\n
            boost::bind(&AsyncHttpsJsonStream::handle_read_content, this,
              boost::asio::placeholders::error));
      }
      else
      {
        http_chunk_flag_ = !http_chunk_flag_;
        boost::asio::async_read_until(socket_, response_, "\r\n",
            boost::bind(&AsyncHttpsJsonStream::handle_read_content, this,
              boost::asio::placeholders::error));
      }

    }
    else
    {
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

    if (debug_log_)
    {
      std::cout << "chunk size: "
        << http_chunk_size_ << '\n';
    }
  }

  void consume_response_chunkdata()
  {
    std::istream response_stream(&response_);

    // std::cout << "data: \t";

    char c;
    while (response_stream.get(c))
    {
      // std::cout << std::hex << (int)c;

      // read next printable character into buffer
      if ((c > 31) && (c < 127))
        json_buffer << c;

      // shift terminator left one
      std::rotate(
        json_terminator.begin(),
        json_terminator.begin() + 1,
        json_terminator.end());
      json_terminator[3] = c;

      // check for \r\n\r\n
      if (
        (0xd == json_terminator[0])
        &&
        (0xa == json_terminator[1])
        &&
        (0xd == json_terminator[2])
        &&
        (0xa == json_terminator[3])
      ) {
        if (debug_log_)
        {
          std::cout << "json: "
            << json_buffer.str() << '\n';
        }

        // yield object
        content_handler_(json_buffer.str());

        // reset the buffer
        json_buffer.str(std::string());
        json_buffer.clear();
      }
    }

    // std::cout << '|' << std::endl;
  }

  void show_error(const char* msg, const StreamErrorCode code, const boost::system::error_code* error = nullptr)
  {
    if (debug_log_)
    {
      std::cerr << "\nError: " << msg << '\n';

      if (nullptr != error)
        std::cerr << "Internal Error: " << error->message() << '\n';
    }

    if (nullptr != error_handler_)
      error_handler_(msg, code);
  }

  template<typename T>
  void debug_log(T msg)
  {
    if (debug_log_)
      std::cout << msg << '\n';
  }

  boost::asio::ip::tcp::resolver resolver_;

  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;

  boost::asio::streambuf request_;
  boost::asio::streambuf response_;

  ContentCallback content_handler_;
  ErrorCallback error_handler_ = nullptr;

  // Transfer-Encoding: chunked
  // http://en.wikipedia.org/wiki/Chunked_transfer_encoding
  bool http_chunk_flag_;
  int http_chunk_size_;

  std::stringstream json_buffer;
  std::vector<char> json_terminator = {0,0,0,0};

  bool debug_log_;

  bool active_ = true;
};

}
