#include "cppi.hpp"
#include <iostream>
#include <fstream>

using namespace cppi;

int main() {
    try {
        // Create server on port 8080
        Server server(8080);
        
        // Basic routes
        server.route()
            .get("/", [](const Request& req, Response& res) {
                res.html(R"(
                    <!DOCTYPE html>
                    <html>
                    <head><title>CPPI Server</title></head>
                    <body>
                        <h1>Welcome to CPPI HTTP Server!</h1>
                        <p>Server is running successfully</p>
                        <ul>
                            <li><a href="/api/users">Users API</a></li>
                            <li><a href="/api/health">Health Check</a></li>
                            <li><a href="/upload">File Upload</a></li>
                        </ul>
                    </body>
                    </html>
                )", false);
            })
            
            .get("/api/users", [](const Request& req, Response& res) {
                nlohmann::json users = {
                    {"users", {
                        {{"id", 1}, {"name", "Alice"}, {"email", "alice@example.com"}},
                        {{"id", 2}, {"name", "Bob"}, {"email", "bob@example.com"}}
                    }}
                };
                res.json(users);
            })
            
            .get("/api/users/:id", [](const Request& req, Response& res) {
                std::string id = req.getParam("id");
                nlohmann::json user = {
                    {"id", std::stoi(id)},
                    {"name", "User " + id},
                    {"email", "user" + id + "@example.com"}
                };
                res.json(user);
            })
            
            .post("/api/users", [](const Request& req, Response& res) {
                try {
                    nlohmann::json requestData = nlohmann::json::parse(req.body);
                    nlohmann::json response = {
                        {"message", "User created"},
                        {"user", requestData},
                        {"id", 42}
                    };
                    res.setStatus(Status::CREATED).json(response);
                } catch (const std::exception& e) {
                    nlohmann::json error = {{"error", "Invalid JSON"}};
                    res.setStatus(Status::BAD_REQUEST).json(error);
                }
            })
            
            .get("/api/health", [](const Request& req, Response& res) {
                nlohmann::json health = {
                    {"status", "healthy"},
                    {"timestamp", std::time(nullptr)},
                    {"version", "1.0.0"}
                };
                res.json(health);
            })
            
            .get("/upload", [](const Request& req, Response& res) {
                res.html(R"(
                    <!DOCTYPE html>
                    <html>
                    <head><title>File Upload</title></head>
                    <body>
                        <h1>File Upload Example</h1>
                        <form action="/upload" method="post" enctype="multipart/form-data">
                            <input type="file" name="file" required>
                            <button type="submit">Upload</button>
                        </form>
                    </body>
                    </html>
                )", false);
            });
        
        std::cout << "Starting server on http://localhost:8080" << std::endl;
        std::cout << "Press Ctrl+C to stop the server" << std::endl;
        
        if (!server.start()) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }
        
        std::string input;
        std::cout << "Server started. Type 'quit' to stop: ";
        while (std::getline(std::cin, input)) {
            if (input == "quit" || input == "exit") {
                break;
            }
            server.printStats();
            std::cout << "Type 'quit' to stop: ";
        }
        
        server.stop();
        std::cout << "Server stopped." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
