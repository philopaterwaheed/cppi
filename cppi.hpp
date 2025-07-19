#pragma once

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
#endif

namespace cppi {

// Forward declarations
class Request;
class Response;
class Router;
class Server;

// HTTP Methods
enum class Method {
    GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
};

// HTTP Status Codes
enum class Status {
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NO_CONTENT = 204,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503
};

// Utility functions
inline std::string methodToString(Method method) {
    switch(method) {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        case Method::PATCH: return "PATCH";
        case Method::HEAD: return "HEAD";
        case Method::OPTIONS: return "OPTIONS";
        default: return "GET";
    }
}

inline Method stringToMethod(const std::string& method) {
    if(method == "GET") return Method::GET;
    if(method == "POST") return Method::POST;
    if(method == "PUT") return Method::PUT;
    if(method == "DELETE") return Method::DELETE;
    if(method == "PATCH") return Method::PATCH;
    if(method == "HEAD") return Method::HEAD;
    if(method == "OPTIONS") return Method::OPTIONS;
    return Method::GET;
}

inline std::string statusToString(Status status) {
    switch(status) {
        case Status::OK: return "200 OK";
        case Status::CREATED: return "201 Created";
        case Status::ACCEPTED: return "202 Accepted";
        case Status::NO_CONTENT: return "204 No Content";
        case Status::BAD_REQUEST: return "400 Bad Request";
        case Status::UNAUTHORIZED: return "401 Unauthorized";
        case Status::FORBIDDEN: return "403 Forbidden";
        case Status::NOT_FOUND: return "404 Not Found";
        case Status::METHOD_NOT_ALLOWED: return "405 Method Not Allowed";
        case Status::INTERNAL_SERVER_ERROR: return "500 Internal Server Error";
        case Status::NOT_IMPLEMENTED: return "501 Not Implemented";
        case Status::BAD_GATEWAY: return "502 Bad Gateway";
        case Status::SERVICE_UNAVAILABLE: return "503 Service Unavailable";
        default: return "200 OK";
    }
}

// URL decode function
// remove + and decode %XX sequences
inline std::string urlDecode(const std::string& str) {
    std::string result;
    for(size_t i = 0; i < str.length(); ++i) {
        if(str[i] == '%' && i + 2 < str.length()) {
            int hex = std::stoi(str.substr(i + 1, 2), nullptr, 16);
            result += static_cast<char>(hex);
            i += 2;
        } else if(str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// Parse query parameters
inline std::unordered_map<std::string, std::string> parseQuery(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    std::stringstream ss(query);
    std::string pair;
    
    while(std::getline(ss, pair, '&')) {
        size_t pos = pair.find('=');
        if(pos != std::string::npos) {
            std::string key = urlDecode(pair.substr(0, pos));
            std::string value = urlDecode(pair.substr(pos + 1));
            params[key] = value;
        }
    }
    return params;
}

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
    
    Response& json(const std::string& jsonStr) {
        setContentType("application/json");
        body = jsonStr;
        return *this;
    }
    
    Response& html(const std::string& htmlStr) {
        setContentType("text/html");
        body = htmlStr;
        return *this;
    }
    
    Response& text(const std::string& textStr) {
        setContentType("text/plain");
        body = textStr;
        return *this;
    }
    
    Response& send(const std::string& data) {
        body = data;
        return *this;
    }
    
    std::string toString() const {
        std::stringstream ss;
        ss << "HTTP/1.1 " << statusToString(status) << "\r\n";
        
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
            req.method = stringToMethod(method);
            
            // Parse URL and query
            size_t queryPos = url.find('?');
            if(queryPos != std::string::npos) {
                req.path = url.substr(0, queryPos);
                req.query = url.substr(queryPos + 1);
                req.queryParams = parseQuery(req.query);
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

// Server class
class Server {
private:
    int port;
    int serverSocket;
    bool running;
    Router router;
    std::vector<std::thread> workers;
    
#ifdef _WIN32
    WSADATA wsaData;
#endif
    
public:
    Server(int p = 8080) : port(p), serverSocket(-1), running(false) {
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
        
        // Set socket options
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if(bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Failed to bind socket" << std::endl;
            return false;
        }
        
        if(listen(serverSocket, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            return false;
        }
        
        running = true;
        std::cout << "Server started on port " << port << std::endl;
        
        // Accept connections
        while(running) {
            sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
            
            if(clientSocket >= 0) {
                // Handle client in a separate thread
                workers.emplace_back([this, clientSocket]() {
                    handleClient(clientSocket);
                });
            }
        }
        
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
        
        // Wait for all worker threads to finish
        for(auto& worker : workers) {
            if(worker.joinable()) {
                worker.join();
            }
        }
        workers.clear();
    }
    
private:
    void handleClient(int clientSocket) {
        char buffer[4096];
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if(bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string rawRequest(buffer);
            
            try {
                Request req = HttpParser::parse(rawRequest);
                Response res;
                
                if(!router.handle(req, res)) {
                    res.setStatus(Status::NOT_FOUND).text("Not Found");
                }
                
                std::string response = res.toString();
                send(clientSocket, response.c_str(), response.length(), 0);
            } catch(const std::exception& e) {
                Response errorRes;
                errorRes.setStatus(Status::INTERNAL_SERVER_ERROR).text("Internal Server Error");
                std::string response = errorRes.toString();
                send(clientSocket, response.c_str(), response.length(), 0);
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
                  << methodToString(req.method) << " " << req.path << std::endl;
        
        return true; // Continue to next middleware/route
    };
}

}
