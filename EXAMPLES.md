# CPPI Examples

This directory contains comprehensive examples demonstrating all features of the CPPI library.

## Quick Start

### 1. Basic Server
```bash
g++ -std=c++17 -I. example_server.cpp -o example_server
./example_server
```

Then visit: http://localhost:8080

### 2. HTTP Client
```bash
g++ -std=c++17 -I. example_client.cpp -o example_client
./example_client
```

### 3. Streaming Examples
```bash
g++ -std=c++17 -I. example_streaming.cpp -o example_streaming
./example_streaming
```

## Building All Examples

### Using Make
```bash
make all        # Build all examples
make test       # Run basic tests
make clean      # Clean build artifacts
```

### Using CMake
```bash
mkdir build && cd build
cmake ..
make
```

## Example Descriptions

### simple_test.cpp
Basic functionality test that verifies:
- Server initialization
- Client initialization  
- Basic compilation and linking

### example_server.cpp
Comprehensive HTTP server example featuring:
- REST API endpoints
- JSON request/response handling
- Route parameters (`:id`)
- Static file serving
- Error handling
- Performance monitoring

**Endpoints:**
- `GET /` - Welcome page
- `GET /api/users` - List all users
- `GET /api/users/:id` - Get specific user
- `POST /api/users` - Create new user
- `GET /api/health` - Health check
- `GET /upload` - File upload form

### example_client.cpp
HTTP client examples demonstrating:
- GET/POST requests
- JSON data handling
- Custom headers
- Form data submission
- URL-based requests
- Connection testing (ping)

### example_streaming.cpp
Advanced streaming examples:
- File streaming (large files)
- Real-time data streaming
- Chunked transfer encoding
- Memory-efficient processing

## Running Examples

### Server Examples
Start a server and test with curl:

```bash
# Start server
./example_server &

# Test endpoints
curl http://localhost:8080/
curl http://localhost:8080/api/users
curl http://localhost:8080/api/users/123
curl -X POST http://localhost:8080/api/users \
     -H "Content-Type: application/json" \
     -d '{"name":"John","email":"john@example.com"}'
```

### Client Examples
The client examples connect to external services (httpbin.org) to demonstrate real HTTP communication.

### Streaming Examples
```bash
# Start streaming server
./example_streaming &

# Test streaming endpoints
curl http://localhost:8080/stream/data
curl http://localhost:8080/stream/large
```

## Custom Examples

### Simple REST API
```cpp
#include "cppi.hpp"
using namespace cppi;

int main() {
    Server server(8080);
    
    // In-memory data store
    std::vector<nlohmann::json> users;
    
    server.route()
        .get("/users", [&](const Request& req, Response& res) {
            res.json(nlohmann::json{{"users", users}});
        })
        .post("/users", [&](const Request& req, Response& res) {
            try {
                auto user = nlohmann::json::parse(req.body);
                user["id"] = users.size() + 1;
                users.push_back(user);
                res.setStatus(Status::CREATED).json(user);
            } catch (const std::exception& e) {
                res.setStatus(Status::BAD_REQUEST)
                   .json({{"error", "Invalid JSON"}});
            }
        });
    
    server.run();
    return 0;
}
```

### File Upload Server
```cpp
#include "cppi.hpp"
using namespace cppi;

int main() {
    Server server(8080);
    
    server.route()
        .post("/upload", [](const Request& req, Response& res) {
            if (req.hasStreamingBody()) {
                // Large file upload
                std::string filename = "uploaded_" + 
                    std::to_string(std::time(nullptr)) + ".bin";
                
                if (req.saveBodyToFile(filename)) {
                    res.json({{"message", "File uploaded"}, 
                             {"filename", filename}});
                } else {
                    res.setStatus(Status::INTERNAL_SERVER_ERROR)
                       .json({{"error", "Upload failed"}});
                }
            } else {
                // Small file in memory
                std::ofstream file("small_upload.txt");
                file << req.body;
                res.json({{"message", "Small file saved"}});
            }
        });
    
    server.run();
    return 0;
}
```

### Proxy Server
```cpp
#include "cppi.hpp"
using namespace cppi;

int main() {
    Server server(8080);
    Client client;
    
    server.route()
        .get("/proxy/*", [&](const Request& req, Response& res) {
            std::string target = req.path.substr(7); // Remove "/proxy"
            auto response = client.get("httpbin.org", 80, target);
            
            res.setStatus(response.status)
               .setContentType(response.getHeader("Content-Type"))
               .send(response.body);
        });
    
    server.run();
    return 0;
}
```

## Performance Testing

### Load Testing with curl
```bash
# Test concurrent requests
for i in {1..100}; do
    curl http://localhost:8080/api/health &
done
wait
```

### Benchmark with ab (Apache Bench)
```bash
# Install apache2-utils first
sudo apt-get install apache2-utils

# Run benchmark
ab -n 1000 -c 10 http://localhost:8080/api/health
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```
   Error: Failed to bind socket
   ```
   Solution: Change port or kill existing process

2. **Permission denied**
   ```
   Error: Failed to create socket
   ```
   Solution: Run with appropriate permissions or use port > 1024

3. **Connection refused**
   ```
   Error: Network error
   ```
   Solution: Ensure server is running and firewall allows connections

### Debug Mode
```bash
make debug          # Build with debug symbols
gdb ./example_server # Debug with GDB
```

### Memory Check
```bash
valgrind --leak-check=full ./example_server
```

## Advanced Configuration

### Custom Thread Pool
```cpp
Server server(8080, 1000, 16);  // Port 8080, max 1000 connections, 16 threads
```

### Connection Limits
```cpp
Server server(8080, 500);       // Limit to 500 concurrent connections
```

### Client Timeouts
```cpp
Client client;
client.setTimeout(30);           // 30 second timeout
```

For more examples and documentation, see the main [README.md](README.md).
