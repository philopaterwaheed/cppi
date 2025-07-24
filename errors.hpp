#pragma once
#include <stdexcept>
namespace cppi::errors {
class HttpError : public std::runtime_error {
protected:
  int status;

public:
  HttpError(int statusCode, const std::string &message)
      : std::runtime_error(message), status(statusCode) {}

  int statusCode() const noexcept { return status; }
};
class BadRequestError : public HttpError {
public:
  explicit BadRequestError(const std::string &msg) : HttpError(400, msg) {}
};

class UnauthorizedError : public HttpError {
public:
  explicit UnauthorizedError(const std::string &msg) : HttpError(401, msg) {}
};

class ForbiddenError : public HttpError {
public:
  explicit ForbiddenError(const std::string &msg) : HttpError(403, msg) {}
};

class NotFoundError : public HttpError {
public:
  explicit NotFoundError(const std::string &msg) : HttpError(404, msg) {}
};

class MethodNotAllowedError : public HttpError {
public:
  explicit MethodNotAllowedError(const std::string &msg)
      : HttpError(405, msg) {}
};

class ValidationError : public HttpError {
public:
  explicit ValidationError(const std::string &msg) : HttpError(422, msg) {}
};

class TooManyRequestsError : public HttpError {
public:
  explicit TooManyRequestsError(const std::string &msg) : HttpError(429, msg) {}
};


class InternalServerError : public HttpError {
public:
    explicit InternalServerError(const std::string& details)
        : HttpError(500, "Internal Server Error: " + details) {}
};



class FileReadError : public HttpError {
public:
    std::string filename;
    explicit FileReadError(const std::string& file)
        : HttpError(500, "Failed to read file: " + file), filename(file) {}
};


class ServiceUnavailableError : public HttpError {
public:
  explicit ServiceUnavailableError(
      const std::string &msg = "Service Unavailable")
      : HttpError(503, msg) {}
};

} // namespace cppi::errors
