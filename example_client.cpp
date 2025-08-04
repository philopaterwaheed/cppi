#include "cppi.hpp"
#include <iostream>

using namespace cppi;

int main() {
    try {
        Client client;
        
        std::cout << "=== CPPI HTTP Client Examples ===" << std::endl;
        
        // Basic GET request
        std::cout << "\n1. Testing GET request to httpbin.org..." << std::endl;
        auto response = client.get("httpbin.org", 80, "/get");
        std::cout << "Status: " << static_cast<int>(response.status) << std::endl;
        std::cout << "Response body preview: " << response.body.substr(0, 100) << "..." << std::endl;
        
        // POST request with JSON
        std::cout << "\n2. Testing POST request with JSON..." << std::endl;
        nlohmann::json postData = {
            {"name", "John Doe"},
            {"email", "john@example.com"},
            {"age", 30}
        };
        auto postResponse = client.post("httpbin.org", 80, "/post", postData);
        std::cout << "Status: " << static_cast<int>(postResponse.status) << std::endl;
        std::cout << "Response body preview: " << postResponse.body.substr(0, 150) << "..." << std::endl;
        
        // Test with headers
        std::cout << "\n3. Testing request with custom headers..." << std::endl;
        std::unordered_map<std::string, std::string> headers = {
            {"User-Agent", "CPPI-Client/1.0"},
            {"X-Custom-Header", "test-value"}
        };
        auto headerResponse = client.get("httpbin.org", 80, "/headers", headers);
        std::cout << "Status: " << static_cast<int>(headerResponse.status) << std::endl;
        std::cout << "Response body preview: " << headerResponse.body.substr(0, 200) << "..." << std::endl;
        
        // Test URL-based requests
        std::cout << "\n4. Testing URL-based requests..." << std::endl;
        auto urlResponse = client.get("http://httpbin.org/uuid");
        std::cout << "Status: " << static_cast<int>(urlResponse.status) << std::endl;
        std::cout << "UUID Response: " << urlResponse.body << std::endl;
        
        // Test ping functionality
        std::cout << "\n5. Testing ping functionality..." << std::endl;
        bool isAlive = client.ping("httpbin.org", 80);
        std::cout << "httpbin.org:80 is " << (isAlive ? "alive" : "down") << std::endl;
        
        // Test form data
        std::cout << "\n6. Testing form data submission..." << std::endl;
        std::unordered_map<std::string, std::string> formData = {
            {"username", "testuser"},
            {"password", "testpass"},
            {"remember", "1"}
        };
        auto formResponse = client.post("httpbin.org", 80, "/post", formData);
        std::cout << "Status: " << static_cast<int>(formResponse.status) << std::endl;
        std::cout << "Form response preview: " << formResponse.body.substr(0, 200) << "..." << std::endl;
        
        std::cout << "\n✓ All client tests completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
