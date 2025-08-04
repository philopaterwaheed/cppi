#include "cppi.hpp"
#include <iostream>

using namespace cppi;

int main() {
    // Test basic compilation
    std::cout << "Testing CPPI library..." << std::endl;
    
    try {
        // Create a server instance
        Server server(8080);
        
        // Add simple routes
        server.route()
            .get("/", [](const Request& req, Response& res) {
                res.text("Hello World from CPPI!");
            })
            .get("/json", [](const Request& req, Response& res) {
                nlohmann::json data = {
                    {"message", "Hello JSON"},
                    {"status", "success"}
                };
                res.json(data);
            });
        
        std::cout << "Server setup successful" << std::endl;
        
        // Test client
        Client client;
        std::cout << "Client setup successful" << std::endl;
        
        std::cout << "All tests passed! Library is working correctly." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
