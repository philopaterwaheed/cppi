#include "cppi.hpp"
#include <iostream>
#include <fstream>

using namespace cppi;

int main() {
    try {
        Server server(8080);
        
        // Streaming file download endpoint
        server.route()
            .get("/download/:filename", [](const Request& req, Response& res) {
                std::string filename = req.getParam("filename");
                std::string filepath = "public/" + filename;
                
                // Check if file exists
                std::ifstream file(filepath, std::ios::binary);
                if (!file.is_open()) {
                    res.setStatus(Status::NOT_FOUND).text("File not found");
                    return;
                }
                file.close();
                
                // Stream the file
                res.streamFile(filepath);
            })
            
            // Streaming response with callback
            .get("/stream/data", [](const Request& req, Response& res) {
                res.streamCallback([](char* buffer, size_t maxSize) -> bool {
                    static int counter = 0;
                    counter++;
                    
                    if (counter > 5) return false; // Stop after 5 chunks
                    
                    std::string chunk = "Data chunk " + std::to_string(counter) + "\n";
                    size_t chunkSize = std::min(chunk.size(), maxSize);
                    std::memcpy(buffer, chunk.c_str(), chunkSize);
                    
                    std::this_thread::sleep_for(std::chrono::seconds(1)); // Simulate delay
                    return true;
                });
            })
            
            // Large response streaming
            .get("/stream/large", [](const Request& req, Response& res) {
                res.streamCallback([](char* buffer, size_t maxSize) -> bool {
                    static size_t totalSent = 0;
                    const size_t maxData = 1024 * 1024; // 1MB total
                    
                    if (totalSent >= maxData) return false;
                    
                    size_t remaining = maxData - totalSent;
                    size_t sendSize = std::min(maxSize, remaining);
                    
                    // Fill buffer with test data
                    for (size_t i = 0; i < sendSize; ++i) {
                        buffer[i] = 'A' + (totalSent + i) % 26;
                    }
                    
                    totalSent += sendSize;
                    return true;
                });
            });
            
        std::cout << "Streaming server started on http://localhost:8080" << std::endl;
        std::cout << "Try these endpoints:" << std::endl;
        std::cout << "  GET /stream/data - Chunked streaming demo" << std::endl;
        std::cout << "  GET /stream/large - Large data streaming" << std::endl;
        std::cout << "  GET /download/filename - File download (place files in public/)" << std::endl;
        
        if (!server.start()) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }
        
        // Run for a short time for testing
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        server.stop();
        std::cout << "Server stopped." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
