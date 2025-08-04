# CPPI - Modern C++ HTTP Server and Client Library

<img width="1024" height="1024" alt="cppi" src="http://iili.io/F6kAU12.md.png" />

![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

CPPI is a modern, header-only C++ HTTP server and client library designed for simplicity, performance, and ease of use with built-in support for streaming, JSON handling, and high-performance multi-threaded server operations.

## Features

### **High Performance**
- **Multi-threaded server** with configurable thread pool
- **Streaming support** for large files and unlimited request/response sizes
- **Connection pooling** and efficient memory management
- **Non-blocking I/O** with optimized buffer management

### **Easy to Use**
- **Header-only library** - just include and go!
- **Express.js-inspired API** for familiar web development patterns
- **Automatic content-type detection** based on file extensions
- **Built-in JSON support** using nlohmann/json

###  **Flexible Architecture**
- **Route parameters** and wildcards (e.g., `/users/:id`)
- **Middleware support** for request/response processing
- **Static file serving** with automatic streaming for large files
- **Custom error handling** and status codes

###  **Comprehensive HTTP Support**
- **All HTTP methods**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- **Request/Response streaming** for handling large payloads
- **File upload/download** with progress tracking
- **Custom headers** and query parameters
- **Form data** and multipart support

## Installation

### Quick Start (Header-Only)

1. **Clone the repository:**
```bash
git clone https://github.com/philopaterwaheed/cppi.git
cd cppi
```

2. **Include in your project:**
```cpp
#include "cppi.hpp"
using namespace cppi;
```

3. **Compile with C++17:**
```bash
g++ -std=c++17 -I. your_file.cpp -o your_app
```

### Using CMake

```cmake
# Option 1: Add as subdirectory
add_subdirectory(cppi)
target_link_libraries(your_target PRIVATE cppi::cppi)

# Option 2: Find installed package
find_package(cppi REQUIRED)
target_link_libraries(your_target PRIVATE cppi::cppi)
```

### Install System-wide

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## Quick Start Examples

### Simple HTTP Server

```cpp
#include "cppi.hpp"
using namespace cppi;

int main() {
    Server server(8080);
    
    server.route()
        .get("/", [](const Request& req, Response& res) {
            res.text("Hello, World!");
        })
        .get("/api/users/:id", [](const Request& req, Response& res) {
            std::string userId = req.getParam("id");
            nlohmann::json user = {
                {"id", userId},
                {"name", "User " + userId}
            };
            res.json(user);
        })
        .post("/api/data", [](const Request& req, Response& res) {
            // Handle JSON data
            auto data = nlohmann::json::parse(req.body);
            res.json({{"received", data}, {"status", "success"}});
        });
    
    server.start();
    return 0;
}
```

### HTTP Client

```cpp
#include "cppi.hpp"
using namespace cppi;

int main() {
    Client client;
    
    // GET request
    auto response = client.get("httpbin.org", 80, "/get");
    std::cout << "Status: " << static_cast<int>(response.status) << std::endl;
    
    // POST with JSON
    nlohmann::json data = {{"name", "John"}, {"age", 30}};
    auto postResp = client.post("api.example.com", 443, "/users", data);
    
    // Download file
    client.downloadFile("http://example.com/file.zip", "local_file.zip");
    
    return 0;
}
```

## API Documentation

### Server Class

#### Constructor
```cpp
Server(int port = 8080, size_t maxConnections = 1000, size_t threadCount = 0)
```
- `port`: Server port (default: 8080)
- `maxConnections`: Maximum concurrent connections (default: 1000)
- `threadCount`: Worker threads (default: hardware concurrency)

#### Methods

| Method | Description |
|--------|-------------|
| `start()` | Start the server (blocking) |
| `stop()` | Stop the server gracefully |
| `route()` | Get router for adding routes |
| `printStats()` | Display server performance statistics |

### Router Class

#### HTTP Methods
```cpp
Router& get(const std::string& path, Handler handler)
Router& post(const std::string& path, Handler handler)
Router& put(const std::string& path, Handler handler)
Router& del(const std::string& path, Handler handler)    // DELETE
Router& patch(const std::string& path, Handler handler)
Router& head(const std::string& path, Handler handler)
Router& options(const std::string& path, Handler handler)
```

#### Route Patterns
- **Static routes**: `/api/users`
- **Parameters**: `/users/:id` → access via `req.getParam("id")`
- **Wildcards**: `/files/*` → matches any path starting with `/files/`

#### Middleware
```cpp
Router& use(Middleware middleware)
```

### Request Class

#### Properties
| Property | Type | Description |
|----------|------|-------------|
| `method` | `Method` | HTTP method (GET, POST, etc.) |
| `path` | `std::string` | Request path |
| `query` | `std::string` | Raw query string |
| `headers` | `std::unordered_map<std::string, std::string>` | HTTP headers |
| `params` | `std::unordered_map<std::string, std::string>` | Route parameters |
| `queryParams` | `std::unordered_map<std::string, std::string>` | Query parameters |
| `body` | `std::string` | Request body |

#### Methods
```cpp
std::string getHeader(const std::string& name) const
std::string getParam(const std::string& name) const
std::string getQuery(const std::string& name) const
bool hasHeader(const std::string& name) const
bool hasParam(const std::string& name) const
bool hasQuery(const std::string& name) const

// Streaming support
bool hasStreamingBody() const
void streamBody(std::function<bool(const char*, size_t)> callback) const
bool saveBodyToFile(const std::string& filename) const
```

### Response Class

#### Status Management
```cpp
Response& setStatus(Status status)           // Set HTTP status code
```

#### Header Management
```cpp
Response& setHeader(const std::string& name, const std::string& value)
Response& setContentType(const std::string& contentType)
std::string getHeader(const std::string& name) const
bool hasHeader(const std::string& name) const
```

#### Content Methods
```cpp
Response& text(const std::string& content, bool isPath = false)
Response& html(const std::string& content, bool isPath = true)
Response& json(nlohmann::json jsonObj)
Response& send(const std::string& data)
```

#### Streaming Methods
```cpp
Response& streamFile(const std::string& filename)
Response& streamCallback(types::StreamDataCallback callback)
Response& streamReader(std::shared_ptr<helpers::StreamReader> reader)
```

### Client Class

#### Basic HTTP Methods
```cpp
// URL-based requests
Response get(const std::string& url, const Headers& headers = {})
Response post(const std::string& url, const BodyVariant& body = {}, const Headers& headers = {})
Response put(const std::string& url, const BodyVariant& body = {}, const Headers& headers = {})
Response del(const std::string& url, const Headers& headers = {})
Response patch(const std::string& url, const BodyVariant& body = {}, const Headers& headers = {})
Response head(const std::string& url, const Headers& headers = {})

// Host/Port/Path-based requests
Response get(const std::string& host, int port, const std::string& path, const Headers& headers = {})
Response post(const std::string& host, int port, const std::string& path, const BodyVariant& body = {}, const Headers& headers = {})
// ... similar for other methods
```

#### File Operations
```cpp
bool downloadFile(const std::string& url, const std::string& localPath, const Headers& headers = {})
Response uploadFile(const std::string& url, const std::string& filePath, const Headers& headers = {})
bool ping(const std::string& url)
```

#### Streaming Methods
```cpp
Response postStream(const std::string& url, std::shared_ptr<helpers::StreamReader> reader, const Headers& headers = {})
Response putStream(const std::string& url, std::shared_ptr<helpers::StreamReader> reader, const Headers& headers = {})
bool downloadFileStream(const std::string& url, const std::string& localPath, const Headers& headers = {})
void streamResponse(const std::string& url, std::function<bool(const char*, size_t)> callback, const Headers& headers = {})
```

## Advanced Features

### Streaming Support

CPPI automatically handles streaming for large files and unlimited request/response sizes:

#### Server-side Streaming
```cpp
server.route()
    .get("/download/:filename", [](const Request& req, Response& res) {
        std::string filename = req.getParam("filename");
        res.streamFile("files/" + filename);  // Automatic streaming for large files
    })
    .get("/live-data", [](const Request& req, Response& res) {
        res.streamCallback([](char* buffer, size_t maxSize) -> bool {
            // Generate data on-the-fly
            static int counter = 0;
            std::string data = "Data chunk " + std::to_string(++counter) + "\n";
            std::memcpy(buffer, data.c_str(), std::min(data.size(), maxSize));
            return counter < 100;  // Stop after 100 chunks
        });
    });
```

#### Client-side Streaming
```cpp
Client client;

// Stream large file upload
client.uploadFile("http://api.example.com/upload", "large_file.zip");

// Stream response processing
client.streamResponse("http://api.example.com/data", 
    [](const char* data, size_t size) -> bool {
        // Process data chunk by chunk
        std::cout.write(data, size);
        return true;  // Continue streaming
    });
```

### Middleware

```cpp
// CORS middleware
auto corsMiddleware = [](const Request& req, Response& res) -> bool {
    res.setHeader("Access-Control-Allow-Origin", "*")
       .setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
       .setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return true;  // Continue to next middleware/route
};

// Authentication middleware
auto authMiddleware = [](const Request& req, Response& res) -> bool {
    if (!req.hasHeader("Authorization")) {
        res.setStatus(Status::UNAUTHORIZED).json({{"error", "Authentication required"}});
        return false;  // Stop processing
    }
    return true;
};

server.route()
    .use(corsMiddleware)
    .use(authMiddleware)
    .get("/protected", [](const Request& req, Response& res) {
        res.json({{"message", "Access granted"}});
    });
```

### Static File Serving

```cpp
#include "cppi.hpp"

Server server(8080);

// Serve static files from 'public' directory
server.route().use(staticFiles("public/"));

// Manual static file serving with custom logic
server.route()
    .get("/assets/*", [](const Request& req, Response& res) {
        std::string filePath = "assets" + req.path.substr(7);  // Remove "/assets"
        
        if (std::filesystem::exists(filePath)) {
            res.streamFile(filePath);  // Automatic content-type detection
        } else {
            res.setStatus(Status::NOT_FOUND).text("File not found");
        }
    });
```

### Error Handling

```cpp
server.route()
    .get("/api/user/:id", [](const Request& req, Response& res) {
        try {
            int userId = std::stoi(req.getParam("id"));
            // Database lookup logic here
            
            if (userId <= 0) {
                throw errors::BadRequestError("Invalid user ID");
            }
            
            // User not found
            if (/* user not exists */) {
                throw errors::NotFoundError("User not found");
            }
            
            nlohmann::json user = {{"id", userId}, {"name", "John Doe"}};
            res.json(user);
            
        } catch (const errors::HttpError& e) {
            res.setStatus(static_cast<Status>(e.statusCode()))
               .json({{"error", e.what()}});
        } catch (const std::exception& e) {
            res.setStatus(Status::INTERNAL_SERVER_ERROR)
               .json({{"error", "Internal server error"}});
        }
    });
```

## Performance Features

### Multi-threading
- Configurable thread pool size
- Automatic load balancing
- Connection limits to prevent overload

### Memory Efficiency
- Streaming prevents loading large files into memory
- Efficient buffer management
- Connection pooling for client requests

### Monitoring
```cpp
server.printStats();  // Display performance metrics
```

Output:
```
=== Server Stats ===
Uptime: 3600 seconds
Active connections: 45
Total requests: 12847
Pending tasks: 3
Requests/second: 3.57
```

## Testing

The library includes comprehensive examples that demonstrate all features:

```bash
# Build examples
mkdir build && cd build
cmake ..
make

# Run tests
./simple_test           # Basic functionality test
./example_client        # HTTP client examples
./example_server        # HTTP server examples  
./example_streaming     # Streaming examples
```

## Error Handling

CPPI provides comprehensive error handling with custom exception types:

```cpp
try {
    Client client;
    auto response = client.get("invalid-url");
} catch (const errors::NetworkError& e) {
    std::cerr << "Network error: " << e.what() << std::endl;
} catch (const errors::TimeoutError& e) {
    std::cerr << "Request timeout: " << e.what() << std::endl;
} catch (const errors::HttpError& e) {
    std::cerr << "HTTP error " << e.statusCode() << ": " << e.what() << std::endl;
}
```

### Available Exception Types
- `errors::HttpError` - Base HTTP error with status code
- `errors::BadRequestError` - 400 Bad Request
- `errors::UnauthorizedError` - 401 Unauthorized  
- `errors::ForbiddenError` - 403 Forbidden
- `errors::NotFoundError` - 404 Not Found
- `errors::MethodNotAllowedError` - 405 Method Not Allowed
- `errors::ValidationError` - 422 Unprocessable Entity
- `errors::TooManyRequestsError` - 429 Too Many Requests
- `errors::InternalServerError` - 500 Internal Server Error
- `errors::NetworkError` - Network connectivity issues
- `errors::TimeoutError` - Request timeout
- `errors::FileReadError` - File system errors

## Build Requirements

- **C++17 or later**
- **CMake 3.15+** (for CMake builds)
- **Threading support** (pthreads on Unix, native on Windows)

### Platform Support
- **Linux** (tested on Ubuntu, CentOS, Alpine)
- **Windows** (MSVC, MinGW)
- **macOS** (Clang)
- **FreeBSD, OpenBSD**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/philopaterwaheed/cppi.git
cd cppi
mkdir build && cd build
cmake -DCPPI_BUILD_EXAMPLES=ON ..
make
```

## Roadmap

- [ ] WebSocket support
- [ ] HTTP/2 support  
- [ ] SSL/TLS encryption
- [ ] Built-in rate limiting
- [ ] Database integration helpers
- [ ] WebRTC support
- [ ] Prometheus metrics export
- [ ] Docker container examples

## Acknowledgments

- Built on [nlohmann/json](https://github.com/nlohmann/json) for JSON support
- Inspired by Express.js API design

---

**Made with ❤️**