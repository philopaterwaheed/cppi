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
    
    Request() : method(Method::GET) {}
    
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
};

// Response class
class Response {
public:
    Status status;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    
    Response() : status(Status::OK) {
        headers["Content-Type"] = "text/plain";
        headers["Server"] = "cppi/1.0.0";
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
        return *this;
    }
    

    Response& html(const std::string& htmlStr, bool is_path = true) {
	setContentType("text/html");

	if (!is_path) {
	    body = htmlStr;
	    return *this;
	}

	try {
	    body = helpers::readFileToString(htmlStr);
	} catch (const errors::FileReadError& e) {
	    throw errors::InternalServerError("Failed to read HTML file at: " + e.filename);
	}
	return *this;
}

    

    Response& text(const std::string& textStr, bool is_path = false) {
	setContentType("text/plain");

	if (!is_path) {
	    body = textStr;
	    return *this;
	}

	try {
	    body = helpers::readFileToString(textStr);
	} catch (const errors::FileReadError& e) {
	    throw errors::InternalServerError("Failed to read text file at: " + e.filename);
	}

	return *this;
    }

    
    Response& send(const std::string& data) {
        body = data;
        return *this;
    }
    
    std::string toString() const {
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

// HTTP Parser
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
        
        // Parse body
        std::string bodyLine;
        while(std::getline(ss, bodyLine)) {
            req.body += bodyLine + "\n";
        }
        if(!req.body.empty()) {
            req.body.pop_back(); // Remove last newline
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
    
    bool start() {
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
        
        char buffer[8192];  // Larger buffer for better performance
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if(bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string rawRequest(buffer);
            
            try {
                Request req = HttpParser::parse(rawRequest);
                Response res;
                
                // Add server headers
                res.setHeader("Server", "cppi/1.1.0")
                   .setHeader("Connection", "close");
                
                if(!router.handle(req, res)) {
                    res.setStatus(Status::NOT_FOUND).text("Not Found");
                }
                
                std::string response = res.toString();
                ::send(clientSocket, response.c_str(), response.length(), 0);
                
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
        }
        
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
    }
};

// Static file middleware
inline Middleware staticFiles(const std::string& directory) {
    return [directory](const Request& req, Response& res) -> bool {
        if(req.method != Method::GET) return true;
        
        std::string filepath = directory + req.path;
        
        // Security check - prevent directory traversal
        if(filepath.find("..") != std::string::npos) {
            res.setStatus(Status::FORBIDDEN).text("Forbidden");
            return false;
        }
        
        std::ifstream file(filepath, std::ios::binary);
        if(!file.is_open()) {
            return true; // Continue to next middleware/route
        }
        
        // Read file content
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        
        // Set content type based on file extension
        std::string ext = filepath.substr(filepath.find_last_of('.') + 1);
        if(ext == "html") res.setContentType("text/html");
        else if(ext == "css") res.setContentType("text/css");
        else if(ext == "js") res.setContentType("application/javascript");
        else if(ext == "json") res.setContentType("application/json");
        else if(ext == "png") res.setContentType("image/png");
        else if(ext == "jpg" || ext == "jpeg") res.setContentType("image/jpeg");
        else if(ext == "gif") res.setContentType("image/gif");
        else res.setContentType("application/octet-stream");
        
        res.send(content);
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
        auto allHeaders = headers;
        std::string bodyStr = utils::processBody(body, allHeaders);
        return request(method, host, port, path, bodyStr, allHeaders);
    }
    
    // Unified HTTP method with full URL
    Response sendUrl(Method method, const std::string& url,
                     const types::BodyVariant& body = std::monostate{},
                     const std::unordered_map<std::string, std::string>& headers = {}) {
        auto allHeaders = headers;
        std::string bodyStr = utils::processBody(body, allHeaders);
        return requestUrl(method, url, bodyStr, allHeaders);
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
    

private:
    // Request method
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
            
            // Receive response 
            std::string responseStr;
            char buffer[4096];
            int bytesReceived;
            
            while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
                buffer[bytesReceived] = '\0';
                responseStr += buffer;
                
                if (responseStr.find("\r\n\r\n") != std::string::npos) {
                    size_t headerEnd = responseStr.find("\r\n\r\n");
                    std::string headers = responseStr.substr(0, headerEnd);
                    
                    if (headers.find("Content-Length:") != std::string::npos) {
                        std::regex contentLengthRegex(R"(Content-Length:\s*(\d+))");
                        std::smatch match;
                        if (std::regex_search(headers, match, contentLengthRegex)) {
                            int contentLength = std::stoi(match[1].str());
                            int currentBodyLength = responseStr.length() - (headerEnd + 4);
                            if (currentBodyLength >= contentLength) {
                                break;
                            }
                        }
                    } else if (headers.find("Transfer-Encoding: chunked") == std::string::npos) {
                        break;
                    }
                }
            }
            
            if (bytesReceived < 0) {
                throw std::runtime_error("Failed to receive response");
            }
            
            response = parseResponse(responseStr);
            
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
};

}//cppi namespace
