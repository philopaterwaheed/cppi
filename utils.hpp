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
  case Status::MOVED_PERMANENTLY:
    return "301 Moved Permanently";
  case Status::FOUND:
    return "302 Found";
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
inline Status codeToStatus(const std::string &code) {
  if (code == "200")
    return Status::OK;
  if (code == "201")
    return Status::CREATED;
  if (code == "202")
    return Status::ACCEPTED;
  if (code == "204")
    return Status::NO_CONTENT;
  if (code == "301")
    return Status::MOVED_PERMANENTLY;
  if (code == "302")
    return Status::FOUND;
  if (code == "400")
    return Status::BAD_REQUEST;
  if (code == "401")
    return Status::UNAUTHORIZED;
  if (code == "403")
    return Status::FORBIDDEN;
  if (code == "404")
    return Status::NOT_FOUND;
  if (code == "405")
    return Status::METHOD_NOT_ALLOWED;
  if (code == "500")
    return Status::INTERNAL_SERVER_ERROR;
  if (code == "501")
    return Status::NOT_IMPLEMENTED;
  if (code == "502")
    return Status::BAD_GATEWAY;
  if (code == "503")
    return Status::SERVICE_UNAVAILABLE;
  return Status::OK; // Default case
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

// URL encoding helper
std::string urlEncode(const std::string& value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  
  for (char c : value) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
          escaped << c;
      } else {
          escaped << '%' << std::setw(2) << int((unsigned char)c);
      }
  }
  
  return escaped.str();
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
// Helper to convert types::BodyVariant to string and set appropriate headers
std::string processBody(const types::BodyVariant& body, std::unordered_map<std::string, std::string>& headers) {
    return std::visit([&headers](const auto& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "";
        }
        else if constexpr (std::is_same_v<T, std::string>) {
            return arg;
        }
        else if constexpr (std::is_same_v<T, nlohmann::json>) {
            headers["Content-Type"] = "application/json";
            return arg.dump();
        }
        else if constexpr (std::is_same_v<T, std::unordered_map<std::string, std::string>>) {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            std::string result;
            bool first = true;
            for (const auto& field : arg) {
                if (!first) result += "&";
                result += utils::urlEncode(field.first) + "=" + utils::urlEncode(field.second);
                first = false;
            }
            return result;
        }
    }, body);
}

} // namespace cppi::utils
