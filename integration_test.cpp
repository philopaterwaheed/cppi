#include "cppi.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>

using namespace cppi;

// Test results tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void pass(const std::string& test) {
        std::cout << "pass " << test << std::endl;
        passed++;
    }
    
    void fail(const std::string& test, const std::string& error = "") {
        std::cout << "failed " << test;
        if (!error.empty()) std::cout << " - " << error;
        std::cout << std::endl;
        failed++;
    }
    
    void summary() {
        std::cout << "\n=== Test Results ===" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total:  " << (passed + failed) << std::endl;
        
        if (failed == 0) {
            std::cout << "\n All tests passed!" << std::endl;
        } else {
            std::cout << "\n Some tests failed!" << std::endl;
        }
    }
};

int main() {
    TestResults results;
    
    std::cout << "=== CPPI Comprehensive Integration Tests ===" << std::endl;
    
    try {
        // Test 1: Basic library compilation and instantiation
        {
            Server server(8081);
            Client client;
            results.pass("Basic instantiation");
        }
        
        // Test 2: Server setup and route configuration
        {
            Server server(8082);
            
            server.route()
                .get("/test", [](const Request& req, Response& res) {
                    res.text("Test successful");
                })
                .post("/echo", [](const Request& req, Response& res) {
                    res.text("Echo: " + req.body);
                })
                .get("/json", [](const Request& req, Response& res) {
                    nlohmann::json data = {{"status", "ok"}, {"message", "JSON test"}};
                    res.json(data);
                })
                .get("/param/:id", [](const Request& req, Response& res) {
                    res.text("ID: " + req.getParam("id"));
                });
            
            results.pass("Server route configuration");
        }
        
        // Test 3: Response methods
        {
            Response res;
            
            // Test chaining
            res.setStatus(Status::OK)
               .setHeader("Custom-Header", "test-value")
               .setContentType("application/json");
            
            if (res.status == Status::OK && 
                res.getHeader("Custom-Header") == "test-value" &&
                res.getHeader("Content-Type") == "application/json") {
                results.pass("Response method chaining");
            } else {
                results.fail("Response method chaining");
            }
        }
        
        // Test 4: JSON handling
        {
            try {
                nlohmann::json testData = {
                    {"name", "Test User"},
                    {"age", 25},
                    {"active", true},
                    {"scores", {95, 87, 92}}
                };
                
                Response res;
                res.json(testData);
                
                // Parse back to verify
                auto parsed = nlohmann::json::parse(res.body);
                if (parsed["name"] == "Test User" && 
                    parsed["age"] == 25 &&
                    parsed["active"] == true) {
                    results.pass("JSON serialization/deserialization");
                } else {
                    results.fail("JSON serialization/deserialization");
                }
            } catch (const std::exception& e) {
                results.fail("JSON handling", e.what());
            }
        }
        
        // Test 5: HTTP Client basic functionality
        {
            try {
                Client client;
                
                // Test external API call
                auto response = client.get("httpbin.org", 80, "/status/200");
                if (response.status == Status::OK) {
                    results.pass("HTTP Client GET request");
                } else {
                    results.fail("HTTP Client GET request", 
                                "Status: " + std::to_string(static_cast<int>(response.status)));
                }
            } catch (const std::exception& e) {
                results.fail("HTTP Client GET request", e.what());
            }
        }
        
        // Test 6: HTTP Client POST with JSON
        {
            try {
                Client client;
                nlohmann::json postData = {{"test", "data"}, {"number", 42}};
                
                auto response = client.post("httpbin.org", 80, "/post", postData);
                if (response.status == Status::OK && 
                    response.body.find("\"test\": \"data\"") != std::string::npos) {
                    results.pass("HTTP Client POST with JSON");
                } else {
                    results.fail("HTTP Client POST with JSON");
                }
            } catch (const std::exception& e) {
                results.fail("HTTP Client POST with JSON", e.what());
            }
        }
        
        // Test 7: Client ping functionality
        {
            try {
                Client client;
                if (client.ping("httpbin.org", 80)) {
                    results.pass("HTTP Client ping");
                } else {
                    results.fail("HTTP Client ping");
                }
            } catch (const std::exception& e) {
                results.fail("HTTP Client ping", e.what());
            }
        }
        
        // Test 8: URL-based client requests
        {
            try {
                Client client;
                auto response = client.get("http://httpbin.org/uuid");
                if (response.status == Status::OK && 
                    response.body.find("uuid") != std::string::npos) {
                    results.pass("HTTP Client URL-based requests");
                } else {
                    results.fail("HTTP Client URL-based requests");
                }
            } catch (const std::exception& e) {
                results.fail("HTTP Client URL-based requests", e.what());
            }
        }
        
        // Test 9: Form data submission
        {
            try {
                Client client;
                std::unordered_map<std::string, std::string> formData = {
                    {"key1", "value1"},
                    {"key2", "value2"}
                };
                
                auto response = client.post("httpbin.org", 80, "/post", formData);
                if (response.status == Status::OK &&
                    response.body.find("key1") != std::string::npos &&
                    response.body.find("value1") != std::string::npos) {
                    results.pass("HTTP Client form data");
                } else {
                    results.fail("HTTP Client form data");
                }
            } catch (const std::exception& e) {
                results.fail("HTTP Client form data", e.what());
            }
        }
        
        // Test 10: File operations (create test file)
        {
            try {
                std::string testContent = "This is a test file for CPPI library testing.";
                std::ofstream file("test_file.txt");
                file << testContent;
                file.close();
                
                // Verify file was created
                std::ifstream readFile("test_file.txt");
                std::string readContent((std::istreambuf_iterator<char>(readFile)),
                                       std::istreambuf_iterator<char>());
                readFile.close();
                
                if (readContent == testContent) {
                    results.pass("File I/O operations");
                } else {
                    results.fail("File I/O operations");
                }
                
                // Clean up
                std::remove("test_file.txt");
            } catch (const std::exception& e) {
                results.fail("File I/O operations", e.what());
            }
        }
        
        // Test 11: Error handling
        {
            try {
                bool exceptionCaught = false;
                try {
                    throw errors::NotFoundError("Test error");
                } catch (const errors::HttpError& e) {
                    if (e.statusCode() == 404 && std::string(e.what()) == "Test error") {
                        exceptionCaught = true;
                    }
                }
                
                if (exceptionCaught) {
                    results.pass("Exception handling");
                } else {
                    results.fail("Exception handling");
                }
            } catch (const std::exception& e) {
                results.fail("Exception handling", e.what());
            }
        }
        
        // Test 12: Server-Client Integration Test
        {
            try {
                std::cout << "\nRunning server-client integration test..." << std::endl;
                
                // Start server in background
                Server server(8083);
                server.route()
                    .get("/integration-test", [](const Request& req, Response& res) {
                        res.json({{"message", "Integration test successful"}, {"server", "cppi"}});
                    })
                    .post("/echo", [](const Request& req, Response& res) {
                        auto data = nlohmann::json::parse(req.body);
                        res.json({{"echo", data}, {"received", true}});
                    });
                
                std::thread serverThread([&server]() {
                    server.start();
                });
                
                // Give server time to start
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
                // Test with client
                Client client;
                
                // Test 1: GET request
                auto getResponse = client.get("localhost", 8083, "/integration-test");
                bool getSuccess = (getResponse.status == Status::OK && 
                                  getResponse.body.find("Integration test successful") != std::string::npos);
                
                // Test 2: POST request
                nlohmann::json postData = {{"test", "integration"}, {"value", 123}};
                auto postResponse = client.post("localhost", 8083, "/echo", postData);
                bool postSuccess = (postResponse.status == Status::OK &&
                                   postResponse.body.find("integration") != std::string::npos);
                
                // Stop server
                server.stop();
                if (serverThread.joinable()) {
                    serverThread.join();
                }
                
                if (getSuccess && postSuccess) {
                    results.pass("Server-Client integration");
                } else {
                    results.fail("Server-Client integration", 
                                "GET: " + std::to_string(getSuccess) + 
                                ", POST: " + std::to_string(postSuccess));
                }
                
            } catch (const std::exception& e) {
                results.fail("Server-Client integration", e.what());
            }
        }
        
        std::cout << "\n=== Testing Complete ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Critical error during testing: " << e.what() << std::endl;
        results.fail("Critical error", e.what());
    }
    
    results.summary();
    return results.failed == 0 ? 0 : 1;
}
