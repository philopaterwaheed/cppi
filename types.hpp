#pragma once
#include <variant>
#include <string>
#include "external/json/single_include/nlohmann/json.hpp"
namespace cppi::types {
// HTTP Methods
enum class Method { GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS };

// HTTP Status Codes
enum class Status {
  OK = 200,
  CREATED = 201,
  ACCEPTED = 202,
  NO_CONTENT = 204,
  MOVED_PERMANENTLY = 301,
  FOUND = 302,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_ALLOWED = 405,
  INTERNAL_SERVER_ERROR = 500,
  NOT_IMPLEMENTED = 501,
  BAD_GATEWAY = 502,
  SERVICE_UNAVAILABLE = 503
};

// Body variant type for different body types
using BodyVariant = std::variant<
    std::monostate,                                           // No body
    std::string,                                              // String body
    nlohmann::json,                                           // JSON body
    std::unordered_map<std::string, std::string>              // Form data
>;
} // namespace cppi::types
