#include "types.hpp"
#include <string>
#include <unordered_map>
#include <sstream>
#pragma once
using Method = cppi::types::Method;
using Status = cppi::types::Status;
namespace cppi::utils {
// Utility functions
inline std::string methodToString(Method method) {
  switch (method) {
  case Method::GET:
    return "GET";
  case Method::POST:
    return "POST";
  case Method::PUT:
    return "PUT";
  case Method::DELETE:
    return "DELETE";
  case Method::PATCH:
    return "PATCH";
  case Method::HEAD:
    return "HEAD";
  case Method::OPTIONS:
    return "OPTIONS";
  default:
    return "GET";
  }
}

inline Method stringToMethod(const std::string &method) {
  if (method == "GET")
    return Method::GET;
  if (method == "POST")
    return Method::POST;
  if (method == "PUT")
    return Method::PUT;
  if (method == "DELETE")
    return Method::DELETE;
  if (method == "PATCH")
    return Method::PATCH;
  if (method == "HEAD")
    return Method::HEAD;
  if (method == "OPTIONS")
    return Method::OPTIONS;
  return Method::GET;
}

inline std::string statusToString(Status status) {
  switch (status) {
  case Status::OK:
    return "200 OK";
  case Status::CREATED:
    return "201 Created";
  case Status::ACCEPTED:
    return "202 Accepted";
  case Status::NO_CONTENT:
    return "204 No Content";
  case Status::BAD_REQUEST:
    return "400 Bad Request";
  case Status::UNAUTHORIZED:
    return "401 Unauthorized";
  case Status::FORBIDDEN:
    return "403 Forbidden";
  case Status::NOT_FOUND:
    return "404 Not Found";
  case Status::METHOD_NOT_ALLOWED:
    return "405 Method Not Allowed";
  case Status::INTERNAL_SERVER_ERROR:
    return "500 Internal Server Error";
  case Status::NOT_IMPLEMENTED:
    return "501 Not Implemented";
  case Status::BAD_GATEWAY:
    return "502 Bad Gateway";
  case Status::SERVICE_UNAVAILABLE:
    return "503 Service Unavailable";
  default:
    return "200 OK";
  }
}
// URL decode function
// remove + and decode %XX sequences
inline std::string urlDecode(const std::string &str) {
  std::string result;
  for (size_t i = 0; i < str.length(); ++i) {
    if (str[i] == '%' && i + 2 < str.length()) {
      int hex = std::stoi(str.substr(i + 1, 2), nullptr, 16);
      result += static_cast<char>(hex);
      i += 2;
    } else if (str[i] == '+') {
      result += ' ';
    } else {
      result += str[i];
    }
  }
  return result;
}

// Parse query parameters
inline std::unordered_map<std::string, std::string>
parseQuery(const std::string &query) {
  std::unordered_map<std::string, std::string> params;
  std::stringstream ss(query);
  std::string pair;

  while (std::getline(ss, pair, '&')) {
    size_t pos = pair.find('=');
    if (pos != std::string::npos) {
      std::string key = urlDecode(pair.substr(0, pos));
      std::string value = urlDecode(pair.substr(pos + 1));
      params[key] = value;
    }
  }
  return params;
}

} // namespace cppi::utils
