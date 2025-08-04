#pragma once
#include "external/json/single_include/nlohmann/json.hpp"
#include "helpers.hpp"
#include "errors.hpp"
#include "utils.hpp"

#include <condition_variable>
#include <mutex>
#include <queue>
#include <atomic>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>
#include <sstream>
#include <thread>
#include <regex>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <variant>
#include <csignal>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <errno.h>
#endif

namespace cppi{

// Forward declarations
class Request;
class Response;
class Router;
class Server;
class Client;


// Request class
class Request {
public:
    Method method;
    std::string path;
    std::string query;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> params;
    std::unordered_map<std::string, std::string> queryParams;
    std::string body;
    
    // Streaming support
    std::shared_ptr<helpers::StreamReader> bodyStream;
    bool isStreamingRequest;
    
    Request() : method(Method::GET), isStreamingRequest(false) {}
    
    std::string getHeader(const std::string& name) const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : "";
    }
    
    std::string getParam(const std::string& name) const {
        auto it = params.find(name);
        return it != params.end() ? it->second : "";
    }
    
    std::string getQuery(const std::string& name) const {
        auto it = queryParams.find(name);
        return it != queryParams.end() ? it->second : "";
    }
    
    bool hasHeader(const std::string& name) const {
        return headers.find(name) != headers.end();
    }
    
    bool hasParam(const std::string& name) const {
        return params.find(name) != params.end();
    }
    
    bool hasQuery(const std::string& name) const {
        return queryParams.find(name) != queryParams.end();
    }
    
    // Streaming body access
    bool hasStreamingBody() const {
        return isStreamingRequest && bodyStream != nullptr;
    }
    
    void streamBody(types::StreamDataCallback callback) const {
        if (hasStreamingBody()) {
            char buffer[helpers::STREAM_BUFFER_SIZE];
            while (bodyStream->hasMore()) {
                size_t bytesRead = bodyStream->read(buffer, sizeof(buffer));
                if (bytesRead > 0) {
                    if (!callback(buffer, bytesRead)) {
                        break;
                    }
                }
            }
        }
    }
    
    // Save streaming body to file
    bool saveBodyToFile(const std::string& filename) const {
        if (!hasStreamingBody()) return false;
        
        try {
            helpers::FileStreamWriter writer(filename);
            char buffer[helpers::STREAM_BUFFER_SIZE];
            
            while (bodyStream->hasMore()) {
                size_t bytesRead = bodyStream->read(buffer, sizeof(buffer));
                if (bytesRead > 0) {
                    if (writer.write(buffer, bytesRead) != bytesRead) {
                        return false;
                    }
                }
            }
            writer.close();
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
};

// Response class
class Response {
public:
    Status status;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    
    // Streaming support
    types::ResponseBodyVariant streamingBody;
    std::shared_ptr<helpers::StreamWriter> streamWriter;
    bool isStreamingResponse;
    mutable std::unique_ptr<std::mutex> responseMutex;
    
    Response() : status(Status::OK), isStreamingResponse(false), 
                responseMutex(std::make_unique<std::mutex>()) {
        headers["Content-Type"] = "text/plain";
        headers["Server"] = "cppi/1.0.0";
    }
    
    // Move constructor
    Response(Response&& other) noexcept 
        : status(other.status), headers(std::move(other.headers)), 
          body(std::move(other.body)), streamingBody(std::move(other.streamingBody)),
          streamWriter(std::move(other.streamWriter)), 
          isStreamingResponse(other.isStreamingResponse),
          responseMutex(std::move(other.responseMutex)) {
    }
    
    // Move assignment
    Response& operator=(Response&& other) noexcept {
        if (this != &other) {
            status = other.status;
            headers = std::move(other.headers);
            body = std::move(other.body);
            streamingBody = std::move(other.streamingBody);
            streamWriter = std::move(other.streamWriter);
            isStreamingResponse = other.isStreamingResponse;
            responseMutex = std::move(other.responseMutex);
        }
        return *this;
    }
    
    // Copy constructor  
    Response(const Response& other)
        : status(other.status), headers(other.headers), body(other.body),
          streamingBody(other.streamingBody), streamWriter(other.streamWriter),
          isStreamingResponse(other.isStreamingResponse),
          responseMutex(std::make_unique<std::mutex>()) {
    }
    
    // Copy assignment
    Response& operator=(const Response& other) {
        if (this != &other) {
            status = other.status;
            headers = other.headers;
            body = other.body;
            streamingBody = other.streamingBody;
            streamWriter = other.streamWriter;
            isStreamingResponse = other.isStreamingResponse;
        }
        return *this;
    }
    
    Response& setStatus(Status s) {
        status = s;
        return *this;
    }
    
    Response& setHeader(const std::string& name, const std::string& value) {
        headers[name] = value;
        return *this;
    }
    
    Response& setContentType(const std::string& contentType) {
        headers["Content-Type"] = contentType;
        return *this;
    }
    
    std::string getHeader(const std::string& name) const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : "";
    }
    
    bool hasHeader(const std::string& name) const {
        return headers.find(name) != headers.end();
    }
    
    Response& json(nlohmann::json jsonObj) {
        setContentType("application/json");
        body = jsonObj.dump();
        isStreamingResponse = false;
        return *this;
    }
    
    Response& html(const std::string& htmlStr, bool is_path = true) {
        setContentType("text/html");
        isStreamingResponse = false;

        if (!is_path) {
            body = htmlStr;
            return *this;
        }

        try {
            // For small files, load directly. For large files, use streaming
            std::ifstream file(htmlStr, std::ios::binary | std::ios::ate);
            if (!file) {
                throw errors::FileReadError(htmlStr);
            }
            
            size_t fileSize = file.tellg();
            file.close();
            
            if (fileSize > 1024 * 1024) { // 1MB threshold for streaming
                return streamFile(htmlStr);
            } else {
                body = helpers::readFileToString(htmlStr);
            }
        } catch (const errors::FileReadError& e) {
            throw errors::InternalServerError("Failed to read HTML file at: " + e.filename);
        }
        return *this;
    }

    Response& text(const std::string& textStr, bool is_path = false) {
        setContentType("text/plain");
        isStreamingResponse = false;

        if (!is_path) {
            body = textStr;
            return *this;
        }

        try {
            // For small files, load directly. For large files, use streaming
            std::ifstream file(textStr, std::ios::binary | std::ios::ate);
            if (!file) {
                throw errors::FileReadError(textStr);
            }
            
            size_t fileSize = file.tellg();
            file.close();
            
            if (fileSize > 1024 * 1024) { // 1MB threshold for streaming
                return streamFile(textStr);
            } else {
                body = helpers::readFileToString(textStr);
            }
        } catch (const errors::FileReadError& e) {
            throw errors::InternalServerError("Failed to read text file at: " + e.filename);
        }

        return *this;
    }
    
    Response& send(const std::string& data) {
        body = data;
        isStreamingResponse = false;
        return *this;
    }
    
    // Streaming response methods
    Response& streamFile(const std::string& filename) {
        try {
            auto reader = std::make_shared<helpers::FileStreamReader>(filename);
            streamingBody = reader;
            isStreamingResponse = true;
            
            // Set content length if known
            size_t fileSize = reader->totalSize();
            if (fileSize > 0) {
                headers["Content-Length"] = std::to_string(fileSize);
            }
            
            // Guess content type from extension
            std::string ext = filename.substr(filename.find_last_of('.') + 1);
            if (ext == "html") setContentType("text/html");
            else if (ext == "css") setContentType("text/css");
            else if (ext == "js") setContentType("application/javascript");
            else if (ext == "json") setContentType("application/json");
            else if (ext == "png") setContentType("image/png");
            else if (ext == "jpg" || ext == "jpeg") setContentType("image/jpeg");
            else if (ext == "gif") setContentType("image/gif");
            else if (ext == "txt") setContentType("text/plain");
            else setContentType("application/octet-stream");
            
        } catch (const std::exception& e) {
            throw errors::InternalServerError("Failed to stream file: " + filename);
        }
        return *this;
    }
    
    Response& streamCallback(types::StreamDataCallback callback) {
        streamingBody = callback;
        isStreamingResponse = true;
        headers["Transfer-Encoding"] = "chunked";
        return *this;
    }
    
    Response& streamReader(std::shared_ptr<helpers::StreamReader> reader) {
        streamingBody = reader;
        isStreamingResponse = true;
        
        size_t totalSize = reader->totalSize();
        if (totalSize > 0) {
            headers["Content-Length"] = std::to_string(totalSize);
        } else {
            headers["Transfer-Encoding"] = "chunked";
        }
        return *this;
    }
    
    bool hasStreamingBody() const {
        return isStreamingResponse && !std::holds_alternative<std::monostate>(streamingBody);
    }
    
    std::string toString() const {
        if (isStreamingResponse) {
            // For streaming responses, only return headers
            std::stringstream ss;
            ss << "HTTP/1.1 " << utils::statusToString(status) << "\r\n";
            
            for(const auto& header : headers) {
                ss << header.first << ": " << header.second << "\r\n";
            }
            
            ss << "\r\n";
            return ss.str();
        } else {
            // Regular response
            std::stringstream ss;
            ss << "HTTP/1.1 " << utils::statusToString(status) << "\r\n";
            
            // Add content-length header
            auto headersCopy = headers;
            headersCopy["Content-Length"] = std::to_string(body.length());
            
            for(const auto& header : headersCopy) {
                ss << header.first << ": " << header.second << "\r\n";
            }
            
            ss << "\r\n" << body;
            return ss.str();
        }
    }
    
    // Write streaming response to stream writer
    void writeStreamingBody(helpers::StreamWriter& writer) const {
        if (!hasStreamingBody()) return;
        
        std::lock_guard<std::mutex> lock(*responseMutex);
        
        std::visit([&writer](const auto& arg) {
            using T = std::decay_t<decltype(arg)>;
            
            if constexpr (std::is_same_v<T, std::shared_ptr<helpers::StreamReader>>) {
                char buffer[helpers::STREAM_BUFFER_SIZE];
                while (arg->hasMore()) {
                    size_t bytesRead = arg->read(buffer, sizeof(buffer));
                    if (bytesRead > 0) {
                        writer.write(buffer, bytesRead);
                    }
                }
            }
            else if constexpr (std::is_same_v<T, types::StreamDataCallback>) {
                char buffer[helpers::STREAM_BUFFER_SIZE];
                while (arg(buffer, sizeof(buffer))) {
                    writer.write(buffer, sizeof(buffer));
                }
            }
        }, streamingBody);
        
        writer.close();
    }
};

// Route handler type
using Handler = std::function<void(const Request&, Response&)>;

// Route structure
struct Route {
    Method method;
    std::string pattern;
    std::regex regex;
    std::vector<std::string> paramNames;
    Handler handler;
    
    Route(Method m, const std::string& p, Handler h) 
        : method(m), pattern(p), handler(h) {
        
        // Convert route pattern to regex
        std::string regexPattern = pattern;
        std::regex paramRegex(R"(\:([a-zA-Z_][a-zA-Z0-9_]*))");
        std::sregex_iterator iter(regexPattern.begin(), regexPattern.end(), paramRegex);
        std::sregex_iterator end;
        
        // Extract parameter names
        for(; iter != end; ++iter) {
            paramNames.push_back(iter->str(1));
        }
        
        // Replace :param with capture groups
        regexPattern = std::regex_replace(regexPattern, paramRegex, "([^/]+)");
        
        // Escape other regex characters
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\.)"), R"(\.)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\?)"), R"(\?)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\+)"), R"(\+)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\*)"), R"(\*)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\^)"), R"(\^)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\$)"), R"(\$)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\()"), R"(\()");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\))"), R"(\))");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\[)"), R"(\[)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\])"), R"(\])");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\{)"), R"(\{)");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\})"), R"(\})");
        regexPattern = std::regex_replace(regexPattern, std::regex(R"(\|)"), R"(\|)");
        
        regexPattern = "^" + regexPattern + "$";
        regex = std::regex(regexPattern);
    }
};

// Middleware type
using Middleware = std::function<bool(const Request&, Response&)>;

// Router class
class Router {
private:
    std::vector<Route> routes;
    std::vector<Middleware> middlewares;
    
public:
    Router& get(const std::string& path, Handler handler) {
        routes.emplace_back(Method::GET, path, handler);
        return *this;
    }
    
    Router& post(const std::string& path, Handler handler) {
        routes.emplace_back(Method::POST, path, handler);
        return *this;
    }
    
    Router& put(const std::string& path, Handler handler) {
        routes.emplace_back(Method::PUT, path, handler);
        return *this;
    }
    
    Router& del(const std::string& path, Handler handler) {
        routes.emplace_back(Method::DELETE, path, handler);
        return *this;
    }
    
    Router& patch(const std::string& path, Handler handler) {
        routes.emplace_back(Method::PATCH, path, handler);
        return *this;
    }
    
    Router& head(const std::string& path, Handler handler) {
        routes.emplace_back(Method::HEAD, path, handler);
        return *this;
    }
    
    Router& options(const std::string& path, Handler handler) {
        routes.emplace_back(Method::OPTIONS, path, handler);
        return *this;
    }
    
    Router& use(Middleware middleware) {
        middlewares.push_back(middleware);
        return *this;
    }
    
    bool handle(Request& req, Response& res) {
        // Run middlewares
        for(const auto& middleware : middlewares) {
            if(!middleware(req, res)) {
                return true; // Middleware handled the request
            }
        }
        
        // Find matching route
        for(const auto& route : routes) {
            if(route.method == req.method) {
                std::smatch match;
                if(std::regex_match(req.path, match, route.regex)) {
                    // Extract parameters
                    for(size_t i = 0; i < route.paramNames.size() && i + 1 < match.size(); ++i) {
                        req.params[route.paramNames[i]] = match[i + 1].str();
                    }
                    
                    route.handler(req, res);
                    return true;
                }
            }
        }
        
        return false; // No route found
    }
};

// HTTP Parser with streaming support
class HttpParser {
public:
    static Request parse(const std::string& rawRequest) {
        Request req;
        std::stringstream ss(rawRequest);
        std::string line;
        
        // Parse request line
        if(std::getline(ss, line)) {
            line.erase(line.find_last_not_of("\r\n") + 1);
            std::stringstream lineStream(line);
            std::string method, url, version;
            
            lineStream >> method >> url >> version;
            req.method = utils::stringToMethod(method);
            
            // Parse URL and query
            size_t queryPos = url.find('?');
            if(queryPos != std::string::npos) {
                req.path = url.substr(0, queryPos);
                req.query = url.substr(queryPos + 1);
                req.queryParams = utils::parseQuery(req.query);
            } else {
                req.path = url;
            }
        }
        
        // Parse headers
        while(std::getline(ss, line) && line != "\r") {
            line.erase(line.find_last_not_of("\r\n") + 1);
            size_t colonPos = line.find(':');
            if(colonPos != std::string::npos) {
                std::string name = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                
                // Trim whitespace
                name.erase(0, name.find_first_not_of(" \t"));
                name.erase(name.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                req.headers[name] = value;
            }
        }
        
        // Parse body - only read what's already available
        std::string bodyLine;
        while(std::getline(ss, bodyLine)) {
            req.body += bodyLine + "\n";
        }
        if(!req.body.empty()) {
            req.body.pop_back(); // Remove last newline
        }
        
        return req;
    }
    
    // Parse request with streaming support
    static Request parseStreaming(int socket, const std::string& initialData) {
        Request req = parse(initialData);
        
        // Check if we need to handle streaming body
        auto contentLengthIt = req.headers.find("Content-Length");
        auto transferEncodingIt = req.headers.find("Transfer-Encoding");
        
        bool isChunked = (transferEncodingIt != req.headers.end() && 
                         transferEncodingIt->second == "chunked");
        
        if (contentLengthIt != req.headers.end() || isChunked) {
            size_t contentLength = 0;
            if (contentLengthIt != req.headers.end()) {
                contentLength = std::stoull(contentLengthIt->second);
            }
            
            // Check if body is already complete in initial data
            size_t headerEnd = initialData.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                size_t bodyStart = headerEnd + 4;
                size_t availableBodySize = initialData.length() - bodyStart;
                
                if (isChunked || (contentLength > 0 && availableBodySize < contentLength)) {
                    // Need streaming for remaining body
                    req.isStreamingRequest = true;
                    req.bodyStream = std::make_shared<helpers::SocketStreamReader>(
                        socket, contentLength, isChunked);
                    
                    // Clear the partial body from string
                    req.body.clear();
                }
            }
        }
        
        return req;
    }
};

class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    mutable std::mutex queueMutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};
    
public:
    ThreadPool(size_t numThreads = std::thread::hardware_concurrency()) {
        for(size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    
                    {
                        std::unique_lock<std::mutex> lock(queueMutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        
                        if(stop && tasks.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    
                    task();
                }
            });
        }
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            stop = true;
        }
        
        condition.notify_all();
        
        for(std::thread& worker : workers) {
            worker.join();
        }
    }
    
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            if(stop) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    
    size_t pendingTasks() const {
        std::lock_guard<std::mutex> lock(queueMutex);
        return tasks.size();
    }
};

class Server {
private:
    int port;
    int serverSocket;
    std::atomic<bool> running{false};
    Router router;
    std::unique_ptr<ThreadPool> threadPool;
    std::thread acceptorThread;
    
    // Connection management
    std::atomic<size_t> activeConnections{0};
    size_t maxConnections;
    
    // Performance monitoring
    std::atomic<size_t> totalRequests{0};
    std::chrono::steady_clock::time_point startTime;
    
#ifdef _WIN32
    WSADATA wsaData;
#endif
    
public:
    Server(int p = 8080, size_t maxConn = 1000, size_t threadCount = 0) 
        : port(p), serverSocket(-1), maxConnections(maxConn) {
        
        // Use hardware concurrency if not specified
        size_t threads = threadCount > 0 ? threadCount : std::thread::hardware_concurrency();
        threadPool = std::make_unique<ThreadPool>(threads);
        
#ifdef _WIN32
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }
    
    ~Server() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    Router& route() {
        return router;
    }
    
    // Run server in blocking mode
    bool run() {
        if (!startListening()) {
            return false;
        }
        
        // Setup signal handling for graceful shutdown
        setupSignalHandling();
        
        std::cout << "Server running on http://localhost:" << port << std::endl;
        std::cout << "Press Ctrl+C to stop the server" << std::endl;
        
        // Block until server is stopped
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return true;
    }
    
    // Run server in non-blocking mode
    bool runAsync() {
        if (!startListening()) {
            return false;
        }
        
        setupSignalHandling();
        std::cout << "Server started in async mode on http://localhost:" << port << std::endl;
        return true;
    }
    
    // Check if server is running
    bool isRunning() const {
        return running.load();
    }
    
    // Wait for server to stop
    void waitForStop() {
        if (acceptorThread.joinable()) {
            acceptorThread.join();
        }
    }
    
    void stop() {
        running = false;
        
        if(serverSocket >= 0) {
#ifdef _WIN32
            closesocket(serverSocket);
#else
            close(serverSocket);
#endif
            serverSocket = -1;
        }
        
        if(acceptorThread.joinable()) {
            acceptorThread.join();
        }
        
        // ThreadPool destructor will handle cleanup
        threadPool.reset();
        
        std::cout << "Server stopped. Total requests handled: " << totalRequests << std::endl;
    }
    
    // Performance monitoring
    void printStats() const {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        
        std::cout << "=== Server Stats ===" << std::endl;
        std::cout << "Uptime: " << uptime << " seconds" << std::endl;
        std::cout << "Active connections: " << activeConnections.load() << std::endl;
        std::cout << "Total requests: " << totalRequests.load() << std::endl;
        std::cout << "Pending tasks: " << threadPool->pendingTasks() << std::endl;
        std::cout << "Requests/second: " << (uptime > 0 ? totalRequests.load() / uptime : 0) << std::endl;
    }
    
private:
    // Static instance for signal handling
    static inline Server* currentInstance = nullptr;
    
    // Signal handler for graceful shutdown
    static void signalHandler(int signal) {
        if (currentInstance) {
            std::cout << "\nReceived signal " << signal << ". Shutting down gracefully..." << std::endl;
            currentInstance->stop();
        }
    }
    
    // Setup signal handling for graceful shutdown
    void setupSignalHandling() {
        currentInstance = this;
        std::signal(SIGINT, signalHandler);   // Ctrl+C
        std::signal(SIGTERM, signalHandler);  // Termination signal
#ifndef _WIN32
        std::signal(SIGPIPE, SIG_IGN);        // Ignore broken pipe signals
#endif
    }
    
    // Private method to start listening (used by run() and runAsync())
    bool startListening() {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if(serverSocket < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        // Set socket options for better performance
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        // Set non-blocking mode for better responsiveness
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(serverSocket, FIONBIO, &mode);
#else
        int flags = fcntl(serverSocket, F_GETFL, 0);
        fcntl(serverSocket, F_SETFL, flags | O_NONBLOCK);
#endif
        
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if(bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Failed to bind socket" << std::endl;
            return false;
        }
        
        if(listen(serverSocket, SOMAXCONN) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            return false;
        }
        
        running = true;
        startTime = std::chrono::steady_clock::now();
        std::cout << "Server started on port " << port << " with " 
                  << threadPool->pendingTasks() << " worker threads" << std::endl;
        
        // Start acceptor thread
        acceptorThread = std::thread([this] { acceptConnections(); });
        
        return true;
    }
    
    void acceptConnections() {
        fd_set readSet;
        struct timeval timeout;
        
        while(running) {
            FD_ZERO(&readSet);
            FD_SET(serverSocket, &readSet);
            
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;
            
            int activity = select(serverSocket + 1, &readSet, nullptr, nullptr, &timeout);
            
            if(activity < 0 && errno != EINTR) {
                break;
            }
            
            if(activity > 0 && FD_ISSET(serverSocket, &readSet)) {
                sockaddr_in clientAddr{};
                socklen_t clientLen = sizeof(clientAddr);
                int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
                
                if(clientSocket >= 0) {
                    // Check connection limits
                    if(activeConnections.load() >= maxConnections) {
                        std::string response = "HTTP/1.1 503 Service Unavailable\r\n"
                                             "Content-Length: 21\r\n"
                                             "Connection: close\r\n\r\n"
                                             "Server overloaded";
                        ::send(clientSocket, response.c_str(), response.length(), 0);
#ifdef _WIN32
                        closesocket(clientSocket);
#else
                        close(clientSocket);
#endif
                        continue;
                    }
                    
                    // Enqueue client handling task
                    activeConnections++;
                    threadPool->enqueue([this, clientSocket] {
                        handleClient(clientSocket);
                        activeConnections--;
                    });
                }
            }
        }
    }
    
    void handleClient(int clientSocket) {
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 30;  // 30 second timeout
        tv.tv_usec = 0;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        
        try {
            // Efficient header reading with pre-allocated buffer and incremental search
            constexpr size_t BUFFER_SIZE = 8192;
            constexpr size_t MAX_HEADER_SIZE = 1024 * 1024; // 1MB header limit
            
            std::string rawRequest;
            rawRequest.reserve(BUFFER_SIZE); // Pre-allocate to avoid multiple reallocations
            
            char buffer[BUFFER_SIZE];
            size_t searchStart = 0; // Track where to start searching for header delimiter
            size_t headerEnd = std::string::npos;
            
            // Read initial chunk
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if(bytesRead <= 0) {
                return;
            }
            
            buffer[bytesRead] = '\0';
            rawRequest.assign(buffer, bytesRead);
            
            // Check if we have complete headers in the first read
            headerEnd = rawRequest.find("\r\n\r\n");
            
            // If headers are incomplete, continue reading with optimized search
            while (headerEnd == std::string::npos && rawRequest.length() < MAX_HEADER_SIZE) {
                // Calculate optimal search start position (overlap for boundary cases)
                searchStart = rawRequest.length() >= 3 ? rawRequest.length() - 3 : 0;
                
                bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                if (bytesRead <= 0) break;
                
                buffer[bytesRead] = '\0';
                rawRequest.append(buffer, bytesRead);
                
                // Only search the newly added portion plus small overlap
                headerEnd = rawRequest.find("\r\n\r\n", searchStart);
            }
            
            if (headerEnd == std::string::npos) {
                throw std::runtime_error("Invalid HTTP request - headers too large or incomplete");
            }
            
            // Parse request with streaming support
            Request req = HttpParser::parseStreaming(clientSocket, rawRequest);
            Response res;
            
            // Add server headers
            res.setHeader("Server", "cppi/1.1.0")
               .setHeader("Connection", "close");
            
            if(!router.handle(req, res)) {
                res.setStatus(Status::NOT_FOUND).text("Not Found");
            }
            
            // Send response
            if (res.hasStreamingBody()) {
                // Send headers first
                std::string responseHeaders = res.toString();
                ::send(clientSocket, responseHeaders.c_str(), responseHeaders.length(), 0);
                
                // Create stream writer and send body
                bool useChunked = res.headers.find("Transfer-Encoding") != res.headers.end() &&
                                res.headers.at("Transfer-Encoding") == "chunked";
                helpers::SocketStreamWriter writer(clientSocket, useChunked);
                res.writeStreamingBody(writer);
            } else {
                // Regular response
                std::string response = res.toString();
                ::send(clientSocket, response.c_str(), response.length(), 0);
            }
            
            totalRequests++;
            
        } catch(const std::exception& e) {
            Response errorRes;
            errorRes.setStatus(Status::INTERNAL_SERVER_ERROR)
                   .setHeader("Server", "cppi/1.1.0")
                   .setHeader("Connection", "close")
                   .text("Internal Server Error");
            std::string response = errorRes.toString();
            ::send(clientSocket, response.c_str(), response.length(), 0);
        }
        
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
    }
};

// Static file middleware with streaming support
inline Middleware staticFiles(const std::string& directory) {
    return [directory](const Request& req, Response& res) -> bool {
        if(req.method != Method::GET) return true;
        
        std::string filepath = directory + req.path;
        
        // Security check - prevent directory traversal
        if(filepath.find("..") != std::string::npos) {
            res.setStatus(Status::FORBIDDEN).text("Forbidden");
            return false;
        }
        
        // Check if file exists and get size
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if(!file.is_open()) {
            return true; // Continue to next middleware/route
        }
        
        size_t fileSize = file.tellg();
        file.close();
        
        // Set content type based on file extension
        std::string ext = filepath.substr(filepath.find_last_of('.') + 1);
        if(ext == "html") res.setContentType("text/html");
        else if(ext == "css") res.setContentType("text/css");
        else if(ext == "js") res.setContentType("application/javascript");
        else if(ext == "json") res.setContentType("application/json");
        else if(ext == "png") res.setContentType("image/png");
        else if(ext == "jpg" || ext == "jpeg") res.setContentType("image/jpeg");
        else if(ext == "gif") res.setContentType("image/gif");
        else if(ext == "txt") res.setContentType("text/plain");
        else res.setContentType("application/octet-stream");
        
        // Use streaming for files larger than 1MB
        if (fileSize > 1024 * 1024) {
            res.streamFile(filepath);
        } else {
            // Load small files directly
            std::ifstream file(filepath, std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
            res.send(content);
        }
        
        return false; // Request handled
    };
}

// CORS middleware
inline Middleware cors(const std::string& origin = "*") {
    return [origin](const Request& req, Response& res) -> bool {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
        if(req.method == Method::OPTIONS) {
            res.setStatus(Status::OK).text("");
            return false; // Request handled
        }
        
        return true; // Continue to next middleware/route
    };
}

// Logger middleware
inline Middleware logger() {
    return [](const Request& req, Response& res) -> bool {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                  << utils::methodToString(req.method) << " " << req.path << std::endl;
        
        return true; // Continue to next middleware/route
    };
}

// HTTP Client class
class Client {
private:
    int timeoutSeconds;
    std::unordered_map<std::string, std::string> defaultHeaders;
    
public:
    Client(int timeout = 30) : timeoutSeconds(timeout) {
        defaultHeaders["User-Agent"] = "cppi-client/1.0.0";
        defaultHeaders["Connection"] = "close";
    }
    
    // Set default headers for all requests
    Client& setHeader(const std::string& name, const std::string& value) {
        defaultHeaders[name] = value;
        return *this;
    }
    
    Client& setTimeout(int seconds) {
        timeoutSeconds = seconds;
        return *this;
    }
    
    // Unified HTTP method with host/port/path
    Response send(Method method, const std::string& host, int port, const std::string& path,
                  const types::BodyVariant& body = std::monostate{},
                  const std::unordered_map<std::string, std::string>& headers = {}) {
        if (utils::isStreamingBody(body)) {
            return requestStreaming(method, host, port, path, body, headers);
        } else {
            auto allHeaders = headers;
            std::string bodyStr = utils::processBody(body, allHeaders);
            return request(method, host, port, path, bodyStr, allHeaders);
        }
    }
    
    // Unified HTTP method with full URL
    Response sendUrl(Method method, const std::string& url,
                     const types::BodyVariant& body = std::monostate{},
                     const std::unordered_map<std::string, std::string>& headers = {}) {
        if (utils::isStreamingBody(body)) {
            UrlComponents components = parseUrl(url);
            
            if (components.isHttps) {
                Response response;
                response.setStatus(Status::INTERNAL_SERVER_ERROR)
                       .text("HTTPS not supported in this implementation");
                return response;
            }
            
            return requestStreaming(method, components.host, components.port, 
                                  components.path, body, headers);
        } else {
            auto allHeaders = headers;
            std::string bodyStr = utils::processBody(body, allHeaders);
            return requestUrl(method, url, bodyStr, allHeaders);
        }
    }
        
    Response get(const std::string& url,
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::GET, url, std::monostate{}, headers);
    }

    // GET method - overloaded for host/port/path and URL
    Response get(const std::string& host, int port, const std::string& path,
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::GET, host, port, path, std::monostate{}, headers);
    }

    Response post(const std::string& url,
                  const types::BodyVariant& body = std::monostate{},
                  const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::POST, url, body, headers);
    }

    // POST method - overloaded for host/port/path and URL
    Response post(const std::string& host, int port, const std::string& path,
                  const types::BodyVariant& body = std::monostate{},
                  const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::POST, host, port, path, body, headers);
    }
    
    Response put(const std::string& url,
                 const types::BodyVariant& body = std::monostate{},
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::PUT, url, body, headers);
    }
    
    // PUT method - overloaded for host/port/path and URL
    Response put(const std::string& host, int port, const std::string& path,
                 const types::BodyVariant& body = std::monostate{},
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::PUT, host, port, path, body, headers);
    }
    
    
    Response patch(const std::string& url,
                   const types::BodyVariant& body = std::monostate{},
                   const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::PATCH, url, body, headers);
    }

    // PATCH method - overloaded for host/port/path and URL
    Response patch(const std::string& host, int port, const std::string& path,
                   const types::BodyVariant& body = std::monostate{},
                   const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::PATCH, host, port, path, body, headers);
    }
    
    Response del(const std::string& url,
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::DELETE, url, std::monostate{}, headers);
    }
    
    // DELETE method - overloaded for host/port/path and URL
    Response del(const std::string& host, int port, const std::string& path,
                 const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::DELETE, host, port, path, std::monostate{}, headers);
    }
    
    
    Response head(const std::string& url,
                  const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::HEAD, url, std::monostate{}, headers);
    }

    // HEAD method - overloaded for host/port/path and URL
    Response head(const std::string& host, int port, const std::string& path,
                  const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::HEAD, host, port, path, std::monostate{}, headers);
    }
    
    
    Response options(const std::string& url,
                     const std::unordered_map<std::string, std::string>& headers = {}) {
        return sendUrl(Method::OPTIONS, url, std::monostate{}, headers);
    }

    // OPTIONS method - overloaded for host/port/path and URL
    Response options(const std::string& host, int port, const std::string& path,
                     const std::unordered_map<std::string, std::string>& headers = {}) {
        return send(Method::OPTIONS, host, port, path, std::monostate{}, headers);
    }

    bool downloadFile(const std::string& url, const std::string& localFilePath,
                      const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(url, headers);
        if (response.status == Status::OK) {
            std::ofstream file(localFilePath, std::ios::binary);
            if (file.is_open()) {
                file.write(response.body.c_str(), response.body.length());
                file.close();
                return true;
            }
        }
        return false;
    }

    // Overloaded for host/port/path and URL
    bool downloadFile(const std::string& host, int port, const std::string& path, 
                      const std::string& localFilePath, 
                      const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(host, port, path, headers);
        if (response.status == Status::OK) {
            std::ofstream file(localFilePath, std::ios::binary);
            if (file.is_open()) {
                file.write(response.body.c_str(), response.body.length());
                file.close();
                return true;
            }
        }
        return false;
    }
    
    bool ping(const std::string& url) {
        try {
            auto response = head(url);
            return response.status == Status::OK || 
                   response.status == Status::NOT_FOUND; // Server is responding
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    // Overloaded for host/port/path and URL
    bool ping(const std::string& host, int port, const std::string& path = "/") {
        try {
            auto response = head(host, port, path);
            return response.status == Status::OK || 
                   response.status == Status::NOT_FOUND; // Server is responding
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    // Streaming methods for large files and unlimited request/response sizes
    
    // Upload file with streaming (doesn't load entire file into memory)
    Response uploadFile(const std::string& url, const std::string& filePath,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        auto reader = std::make_shared<helpers::FileStreamReader>(filePath);
        types::BodyVariant body = reader;
        return sendUrl(Method::POST, url, body, headers);
    }
    
    Response uploadFile(const std::string& host, int port, const std::string& path, 
                       const std::string& filePath,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        auto reader = std::make_shared<helpers::FileStreamReader>(filePath);
        types::BodyVariant body = reader;
        return send(Method::POST, host, port, path, body, headers);
    }
    
    // Stream large POST/PUT requests
    Response postStream(const std::string& url, std::shared_ptr<helpers::StreamReader> reader,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        types::BodyVariant body = reader;
        return sendUrl(Method::POST, url, body, headers);
    }
    
    Response postStream(const std::string& host, int port, const std::string& path,
                       std::shared_ptr<helpers::StreamReader> reader,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        types::BodyVariant body = reader;
        return send(Method::POST, host, port, path, body, headers);
    }
    
    Response putStream(const std::string& url, std::shared_ptr<helpers::StreamReader> reader,
                      const std::unordered_map<std::string, std::string>& headers = {}) {
        types::BodyVariant body = reader;
        return sendUrl(Method::PUT, url, body, headers);
    }
    
    Response putStream(const std::string& host, int port, const std::string& path,
                      std::shared_ptr<helpers::StreamReader> reader,
                      const std::unordered_map<std::string, std::string>& headers = {}) {
        types::BodyVariant body = reader;
        return send(Method::PUT, host, port, path, body, headers);
    }
    
    // Download file with streaming (doesn't load entire response into memory)
    bool downloadFileStream(const std::string& url, const std::string& localFilePath,
                           const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(url, headers);
        if (response.status == Status::OK) {
            if (response.hasStreamingBody()) {
                try {
                    helpers::FileStreamWriter writer(localFilePath);
                    response.writeStreamingBody(writer);
                    return true;
                } catch (const std::exception& e) {
                    return false;
                }
            } else {
                // Fallback to regular download for small responses
                std::ofstream file(localFilePath, std::ios::binary);
                if (file.is_open()) {
                    file.write(response.body.c_str(), response.body.length());
                    file.close();
                    return true;
                }
            }
        }
        return false;
    }
    
    bool downloadFileStream(const std::string& host, int port, const std::string& path,
                           const std::string& localFilePath,
                           const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(host, port, path, headers);
        if (response.status == Status::OK) {
            if (response.hasStreamingBody()) {
                try {
                    helpers::FileStreamWriter writer(localFilePath);
                    response.writeStreamingBody(writer);
                    return true;
                } catch (const std::exception& e) {
                    return false;
                }
            } else {
                // Fallback to regular download for small responses
                std::ofstream file(localFilePath, std::ios::binary);
                if (file.is_open()) {
                    file.write(response.body.c_str(), response.body.length());
                    file.close();
                    return true;
                }
            }
        }
        return false;
    }
    
    // Stream response data with callback
    void streamResponse(const std::string& url, 
                       std::function<bool(const char*, size_t)> callback,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(url, headers);
        if (response.status == Status::OK && response.hasStreamingBody()) {
            std::visit([&callback](const auto& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, std::shared_ptr<helpers::StreamReader>>) {
                    char buffer[helpers::STREAM_BUFFER_SIZE];
                    while (arg->hasMore()) {
                        size_t bytesRead = arg->read(buffer, sizeof(buffer));
                        if (bytesRead > 0) {
                            if (!callback(buffer, bytesRead)) {
                                break;
                            }
                        }
                    }
                }
            }, response.streamingBody);
        } else if (response.status == Status::OK && !response.body.empty()) {
            // Handle regular response
            callback(response.body.c_str(), response.body.length());
        }
    }
    
    void streamResponse(const std::string& host, int port, const std::string& path,
                       std::function<bool(const char*, size_t)> callback,
                       const std::unordered_map<std::string, std::string>& headers = {}) {
        auto response = get(host, port, path, headers);
        if (response.status == Status::OK && response.hasStreamingBody()) {
            std::visit([&callback](const auto& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, std::shared_ptr<helpers::StreamReader>>) {
                    char buffer[helpers::STREAM_BUFFER_SIZE];
                    while (arg->hasMore()) {
                        size_t bytesRead = arg->read(buffer, sizeof(buffer));
                        if (bytesRead > 0) {
                            if (!callback(buffer, bytesRead)) {
                                break;
                            }
                        }
                    }
                }
            }, response.streamingBody);
        } else if (response.status == Status::OK && !response.body.empty()) {
            // Handle regular response
            callback(response.body.c_str(), response.body.length());
        }
    }
    

private:
    // Request method with streaming support
    Response request(Method method, const std::string& host, int port, const std::string& path, 
                     const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
        Response response;
        int clientSocket = -1;
        
        try {
            // Create socket
            clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket < 0) {
                throw std::runtime_error("Failed to create socket");
            }
            
            // Set socket timeout
            struct timeval tv;
            tv.tv_sec = timeoutSeconds;
            tv.tv_usec = 0;
            setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
            setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
            
            // Resolve host and connect
            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            
            // Simple IP address detection (for basic usage)
            if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
                // Try hostname resolution
                struct hostent* hostEntry = gethostbyname(host.c_str());
                if (hostEntry == nullptr) {
                    throw std::runtime_error("Failed to resolve hostname: " + host);
                }
                serverAddr.sin_addr = *((struct in_addr*)hostEntry->h_addr);
            }
            
            if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                throw std::runtime_error("Failed to connect to server");
            }
            
            // Build HTTP request
            std::stringstream requestStream;
            requestStream << utils::methodToString(method) << " " << path << " HTTP/1.1\r\n";
            requestStream << "Host: " << host;
            if (port != 80 && port != 443) {
                requestStream << ":" << port;
            }
            requestStream << "\r\n";
            
            // Merge default headers with request headers
            auto allHeaders = defaultHeaders;
            for (const auto& header : headers) {
                allHeaders[header.first] = header.second;
            }
            
            // Add Content-Length for requests with body
            if (!body.empty()) {
                allHeaders["Content-Length"] = std::to_string(body.length());
            }
            
            // Add headers to request
            for (const auto& header : allHeaders) {
                requestStream << header.first << ": " << header.second << "\r\n";
            }
            
            requestStream << "\r\n";
            
            // Add body if present
            if (!body.empty()) {
                requestStream << body;
            }
            
            std::string requestStr = requestStream.str();
            
            // Send request
            if (::send(clientSocket, requestStr.c_str(), requestStr.length(), 0) < 0) {
                throw std::runtime_error("Failed to send request");
            }
            
            // Receive response with streaming support
            response = receiveStreamingResponse(clientSocket);
            
        } catch (const std::exception& e) {
            response.setStatus(Status::INTERNAL_SERVER_ERROR)
                   .setHeader("Error", e.what())
                   .text("Request failed: " + std::string(e.what()));
        }
        
        // Clean up
        if (clientSocket >= 0) {
#ifdef _WIN32
            closesocket(clientSocket);
#else
            close(clientSocket);
#endif
        }
        
        return response;
    }
    
    // Streaming request method
    Response requestStreaming(Method method, const std::string& host, int port, const std::string& path,
                             const types::BodyVariant& body, const std::unordered_map<std::string, std::string>& headers) {
        Response response;
        int clientSocket = -1;
        
        try {
            // Create socket and connect (same as above)
            clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket < 0) {
                throw std::runtime_error("Failed to create socket");
            }
            
            struct timeval tv;
            tv.tv_sec = timeoutSeconds;
            tv.tv_usec = 0;
            setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
            setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
            
            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            
            if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
                struct hostent* hostEntry = gethostbyname(host.c_str());
                if (hostEntry == nullptr) {
                    throw std::runtime_error("Failed to resolve hostname: " + host);
                }
                serverAddr.sin_addr = *((struct in_addr*)hostEntry->h_addr);
            }
            
            if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                throw std::runtime_error("Failed to connect to server");
            }
            
            // Build and send request with streaming body
            auto allHeaders = defaultHeaders;
            for (const auto& header : headers) {
                allHeaders[header.first] = header.second;
            }
            
            // Handle streaming body
            if (utils::isStreamingBody(body)) {
                auto reader = utils::getStreamReader(body);
                size_t totalSize = reader->totalSize();
                
                if (totalSize > 0) {
                    allHeaders["Content-Length"] = std::to_string(totalSize);
                } else {
                    allHeaders["Transfer-Encoding"] = "chunked";
                }
                
                // Send headers first
                std::stringstream headerStream;
                headerStream << utils::methodToString(method) << " " << path << " HTTP/1.1\r\n";
                headerStream << "Host: " << host;
                if (port != 80 && port != 443) {
                    headerStream << ":" << port;
                }
                headerStream << "\r\n";
                
                for (const auto& header : allHeaders) {
                    headerStream << header.first << ": " << header.second << "\r\n";
                }
                headerStream << "\r\n";
                
                std::string headerStr = headerStream.str();
                if (::send(clientSocket, headerStr.c_str(), headerStr.length(), 0) < 0) {
                    throw std::runtime_error("Failed to send headers");
                }
                
                // Send body using stream writer
                bool useChunked = allHeaders.find("Transfer-Encoding") != allHeaders.end() &&
                                allHeaders.at("Transfer-Encoding") == "chunked";
                helpers::SocketStreamWriter writer(clientSocket, useChunked);
                
                char buffer[helpers::STREAM_BUFFER_SIZE];
                while (reader->hasMore()) {
                    size_t bytesRead = reader->read(buffer, sizeof(buffer));
                    if (bytesRead > 0) {
                        if (writer.write(buffer, bytesRead) != bytesRead) {
                            throw std::runtime_error("Failed to send body data");
                        }
                    }
                }
                writer.close();
                
            } else {
                // Regular non-streaming body
                std::string bodyStr = utils::processBody(body, allHeaders);
                if (!bodyStr.empty()) {
                    allHeaders["Content-Length"] = std::to_string(bodyStr.length());
                }
                
                std::stringstream requestStream;
                requestStream << utils::methodToString(method) << " " << path << " HTTP/1.1\r\n";
                requestStream << "Host: " << host;
                if (port != 80 && port != 443) {
                    requestStream << ":" << port;
                }
                requestStream << "\r\n";
                
                for (const auto& header : allHeaders) {
                    requestStream << header.first << ": " << header.second << "\r\n";
                }
                requestStream << "\r\n";
                
                if (!bodyStr.empty()) {
                    requestStream << bodyStr;
                }
                
                std::string requestStr = requestStream.str();
                if (::send(clientSocket, requestStr.c_str(), requestStr.length(), 0) < 0) {
                    throw std::runtime_error("Failed to send request");
                }
            }
            
            // Receive response
            response = receiveStreamingResponse(clientSocket);
            
        } catch (const std::exception& e) {
            response.setStatus(Status::INTERNAL_SERVER_ERROR)
                   .setHeader("Error", e.what())
                   .text("Request failed: " + std::string(e.what()));
        }
        
        if (clientSocket >= 0) {
#ifdef _WIN32
            closesocket(clientSocket);
#else
            close(clientSocket);
#endif
        }
        
        return response;
    }
    
    // Receive streaming response
    Response receiveStreamingResponse(int clientSocket) {
        Response response;
        
        // header reading with pre-allocated buffer and incremental search
        constexpr size_t BUFFER_SIZE = 8192;
        constexpr size_t MAX_HEADER_SIZE = 1024 * 1024; // 1MB header limit
        
        std::string responseStr;
        responseStr.reserve(BUFFER_SIZE); // Pre-allocate to avoid multiple reallocations
        
        char buffer[BUFFER_SIZE];
        size_t searchStart = 0; // Track where to start searching for header delimiter
        size_t headerEnd = std::string::npos;
        int bytesReceived;
        
        // Read initial chunk
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            throw std::runtime_error("Failed to receive response");
        }
        
        buffer[bytesReceived] = '\0';
        responseStr.assign(buffer, bytesReceived);
        
        // Check if we have complete headers in the first read
        headerEnd = responseStr.find("\r\n\r\n");
        
        // If headers are incomplete, continue reading with search
        while (headerEnd == std::string::npos && responseStr.length() < MAX_HEADER_SIZE) {
            // Calculate optimal search start position (overlap for boundary cases)
            searchStart = responseStr.length() >= 3 ? responseStr.length() - 3 : 0;
            
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived <= 0) break;
            
            buffer[bytesReceived] = '\0';
            responseStr.append(buffer, bytesReceived);
            
            headerEnd = responseStr.find("\r\n\r\n", searchStart);
        }
        
        if (headerEnd == std::string::npos) {
            throw std::runtime_error("Invalid HTTP response - headers too large or incomplete");
        }
        
        {
                // Parse response headers
                response = parseResponseHeaders(responseStr.substr(0, headerEnd));
                
                // Check if we need streaming for the body
                auto contentLengthIt = response.headers.find("Content-Length");
                auto transferEncodingIt = response.headers.find("Transfer-Encoding");
                
                bool isChunked = (transferEncodingIt != response.headers.end() && 
                                transferEncodingIt->second == "chunked");
                
                if (contentLengthIt != response.headers.end() || isChunked) {
                    size_t contentLength = 0;
                    if (contentLengthIt != response.headers.end()) {
                        contentLength = std::stoull(contentLengthIt->second);
                    }
                    
                    // Check if we should use streaming (for large responses)
                    if (isChunked || contentLength > 1024 * 1024) { // 1MB threshold
                        // Set up streaming response
                        response.isStreamingResponse = true;
                        auto reader = std::make_shared<helpers::SocketStreamReader>(
                            clientSocket, contentLength, isChunked);
                        response.streamingBody = reader;
                        
                        // Clear any partial body data
                        response.body.clear();
                    } else {
                        // Small response, read into string
                        size_t bodyStart = headerEnd + 4;
                        response.body = responseStr.substr(bodyStart);
                        
                        // Read remaining body if needed
                        size_t remainingBytes = contentLength - response.body.length();
                        while (remainingBytes > 0 && (bytesReceived = recv(clientSocket, buffer, 
                               std::min(remainingBytes, sizeof(buffer) - 1), 0)) > 0) {
                            buffer[bytesReceived] = '\0';
                            response.body += std::string(buffer, bytesReceived);
                            remainingBytes -= bytesReceived;
                        }
                    }
                } else {
                    // No body or body already complete
                    size_t bodyStart = headerEnd + 4;
                    if (bodyStart < responseStr.length()) {
                        response.body = responseStr.substr(bodyStart);
                    }
                }
        }
        
        if (bytesReceived < 0) {
            throw std::runtime_error("Failed to receive response");
        }
        
        return response;
    }
    
    // Helper method to parse URLs
    struct UrlComponents {
        std::string host;
        int port;
        std::string path;
        bool isHttps;
    };
    
    UrlComponents parseUrl(const std::string& url) {
        UrlComponents components;
        components.port = 80;
        components.path = "/";
        components.isHttps = false;
        
        std::string remaining = url;
        
        // Check for protocol
        if (remaining.substr(0, 8) == "https://") {
            components.isHttps = true;
            components.port = 443;
            remaining = remaining.substr(8);
        } else if (remaining.substr(0, 7) == "http://") {
            remaining = remaining.substr(7);
        }
        
        // Find path separator
        size_t pathPos = remaining.find('/');
        std::string hostPart;
        if (pathPos != std::string::npos) {
            hostPart = remaining.substr(0, pathPos);
            components.path = remaining.substr(pathPos);
        } else {
            hostPart = remaining;
        }
        
        // Check for port in host part
        size_t colonPos = hostPart.find(':');
        if (colonPos != std::string::npos) {
            components.host = hostPart.substr(0, colonPos);
            components.port = std::stoi(hostPart.substr(colonPos + 1));
        } else {
            components.host = hostPart;
        }
        
        return components;
    }
    
    // Request method with full URL
    Response requestUrl(Method method, const std::string& url, const std::string& body,
                        const std::unordered_map<std::string, std::string>& headers) {
        UrlComponents components = parseUrl(url);
        
        // Note: This implementation doesn't handle HTTPS/SSL
        if (components.isHttps) {
            Response response;
            response.setStatus(Status::INTERNAL_SERVER_ERROR)
                   .text("HTTPS not supported in this implementation");
            return response;
        }
        
        return request(method, components.host, components.port, components.path, body, headers);
    }
    
    Response parseResponse(const std::string& responseStr) {
        Response response;
        std::stringstream ss(responseStr);
        std::string line;
        
        // Parse status line
        if (std::getline(ss, line)) {
            line.erase(line.find_last_not_of("\r\n") + 1);
            std::stringstream lineStream(line);
            std::string version, statusCode, statusText;
            
            lineStream >> version >> statusCode;
            std::getline(lineStream, statusText);
            
            // Convert status code to Status enum
            response.status = utils::codeToStatus(statusCode);
        }
        
        // Parse headers
        while (std::getline(ss, line) && line != "\r") {
            line.erase(line.find_last_not_of("\r\n") + 1);
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string name = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                
                // Trim whitespace
                name.erase(0, name.find_first_not_of(" \t"));
                name.erase(name.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                response.headers[name] = value;
            }
        }
        
        // Parse body
        std::string bodyLine;
        while (std::getline(ss, bodyLine)) {
            response.body += bodyLine + "\n";
        }
        if (!response.body.empty()) {
            response.body.pop_back(); // Remove last newline
        }
        
        return response;
    }
    
    Response parseResponseHeaders(const std::string& headerStr) {
        Response response;
        std::stringstream ss(headerStr);
        std::string line;
        
        // Parse status line
        if (std::getline(ss, line)) {
            line.erase(line.find_last_not_of("\r\n") + 1);
            std::stringstream lineStream(line);
            std::string version, statusCode, statusText;
            
            lineStream >> version >> statusCode;
            std::getline(lineStream, statusText);
            
            response.status = utils::codeToStatus(statusCode);
        }
        
        // Parse headers only
        while (std::getline(ss, line)) {
            line.erase(line.find_last_not_of("\r\n") + 1);
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string name = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                
                // Trim whitespace
                name.erase(0, name.find_first_not_of(" \t"));
                name.erase(name.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                response.headers[name] = value;
            }
        }
        
        return response;
    }
};

}//cppi namespace
