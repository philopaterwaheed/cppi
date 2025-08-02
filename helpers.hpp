#pragma once
#include "errors.hpp"
#include <fstream>
#include <string>
#include <functional>
#include <memory>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/socket.h>
    #include <unistd.h>
#endif

namespace cppi::helpers {

// Streaming buffer size
constexpr size_t STREAM_BUFFER_SIZE = 65536; // 64KB chunks for optimal performance

// Stream reader interface for handling unlimited input sizes
class StreamReader {
public:
    virtual ~StreamReader() = default;
    virtual size_t read(char* buffer, size_t maxSize) = 0;
    virtual bool hasMore() const = 0;
    virtual size_t totalSize() const = 0; // Returns 0 if unknown
    virtual void reset() = 0;
};

// File stream reader
class FileStreamReader : public StreamReader {
private:
    std::ifstream file;
    size_t fileSize;
    size_t bytesRead;
    
public:
    explicit FileStreamReader(const std::string& filename) : bytesRead(0) {
        file.open(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            throw errors::FileReadError(filename);
        }
        fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
    }
    
    size_t read(char* buffer, size_t maxSize) override {
        if (!hasMore()) return 0;
        
        file.read(buffer, maxSize);
        size_t actualRead = file.gcount();
        bytesRead += actualRead;
        return actualRead;
    }
    
    bool hasMore() const override {
        return bytesRead < fileSize && file.good();
    }
    
    size_t totalSize() const override {
        return fileSize;
    }
    
    void reset() override {
        file.seekg(0, std::ios::beg);
        bytesRead = 0;
    }
};

// Memory stream reader for string data
class MemoryStreamReader : public StreamReader {
private:
    const std::string& data;
    size_t position;
    
public:
    explicit MemoryStreamReader(const std::string& str) : data(str), position(0) {}
    
    size_t read(char* buffer, size_t maxSize) override {
        if (position >= data.size()) return 0;
        
        size_t toRead = std::min(maxSize, data.size() - position);
        std::memcpy(buffer, data.data() + position, toRead);
        position += toRead;
        return toRead;
    }
    
    bool hasMore() const override {
        return position < data.size();
    }
    
    size_t totalSize() const override {
        return data.size();
    }
    
    void reset() override {
        position = 0;
    }
};

// Socket stream reader for network data
class SocketStreamReader : public StreamReader {
private:
    int socket;
    size_t contentLength;
    size_t bytesRead;
    bool isChunked;
    size_t currentChunkSize;
    size_t currentChunkRead;
    bool chunkSizeRead;
    std::string chunkBuffer;
    
public:
    SocketStreamReader(int sock, size_t length = 0, bool chunked = false) 
        : socket(sock), contentLength(length), bytesRead(0), isChunked(chunked),
          currentChunkSize(0), currentChunkRead(0), chunkSizeRead(false) {}
    
    size_t read(char* buffer, size_t maxSize) override {
        if (!hasMore()) return 0;
        
        if (isChunked) {
            return readChunked(buffer, maxSize);
        } else {
            size_t toRead = contentLength > 0 ? 
                std::min(maxSize, contentLength - bytesRead) : maxSize;
            int received = recv(socket, buffer, toRead, 0);
            if (received > 0) {
                bytesRead += received;
                return received;
            }
            return 0;
        }
    }
    
    bool hasMore() const override {
        if (isChunked) {
            return currentChunkSize > 0 || !chunkSizeRead;
        }
        return contentLength == 0 || bytesRead < contentLength;
    }
    
    size_t totalSize() const override {
        return contentLength; // 0 if unknown
    }
    
    void reset() override {
        // Cannot reset socket streams
        bytesRead = 0;
        currentChunkSize = 0;
        currentChunkRead = 0;
        chunkSizeRead = false;
        chunkBuffer.clear();
    }
    
private:
    size_t readChunked(char* buffer, size_t maxSize) {
        if (!chunkSizeRead) {
            if (!readChunkSize()) return 0;
        }
        
        if (currentChunkSize == 0) return 0; // End of chunks
        
        size_t toRead = std::min(maxSize, currentChunkSize - currentChunkRead);
        int received = recv(socket, buffer, toRead, 0);
        
        if (received > 0) {
            currentChunkRead += received;
            if (currentChunkRead >= currentChunkSize) {
                // Read chunk trailer (CRLF)
                char trailer[2];
                recv(socket, trailer, 2, 0);
                chunkSizeRead = false;
                currentChunkRead = 0;
            }
            return received;
        }
        return 0;
    }
    
    bool readChunkSize() {
        std::string sizeLine;
        char c;
        while (recv(socket, &c, 1, 0) == 1) {
            if (c == '\r') continue;
            if (c == '\n') break;
            sizeLine += c;
        }
        
        if (sizeLine.empty()) return false;
        
        // Parse hex chunk size
        std::stringstream ss;
        ss << std::hex << sizeLine;
        ss >> currentChunkSize;
        chunkSizeRead = true;
        return true;
    }
};

// Stream writer interface for handling unlimited output sizes
class StreamWriter {
public:
    virtual ~StreamWriter() = default;
    virtual size_t write(const char* data, size_t size) = 0;
    virtual void flush() = 0;
    virtual bool isChunked() const = 0;
    virtual void close() = 0;
};

// Socket stream writer
class SocketStreamWriter : public StreamWriter {
private:
    int socket;
    bool chunkedEncoding;
    mutable std::mutex writeMutex;
    
public:
    SocketStreamWriter(int sock, bool chunked = false) 
        : socket(sock), chunkedEncoding(chunked) {}
    
    size_t write(const char* data, size_t size) override {
        std::lock_guard<std::mutex> lock(writeMutex);
        
        if (chunkedEncoding) {
            return writeChunked(data, size);
        } else {
            return ::send(socket, data, size, 0);
        }
    }
    
    void flush() override {
        // Socket auto-flushes
    }
    
    bool isChunked() const override {
        return chunkedEncoding;
    }
    
    void close() override {
        if (chunkedEncoding) {
            std::lock_guard<std::mutex> lock(writeMutex);
            const char* endChunk = "0\r\n\r\n";
            ::send(socket, endChunk, 5, 0);
        }
    }
    
private:
    size_t writeChunked(const char* data, size_t size) {
        // Write chunk size in hex
        std::stringstream ss;
        ss << std::hex << size << "\r\n";
        std::string chunkHeader = ss.str();
        
        if (::send(socket, chunkHeader.c_str(), chunkHeader.length(), 0) < 0) {
            return 0;
        }
        
        // Write chunk data
        int sent = ::send(socket, data, size, 0);
        if (sent < 0) return 0;
        
        // Write chunk trailer
        const char* trailer = "\r\n";
        ::send(socket, trailer, 2, 0);
        
        return sent;
    }
};

// File stream writer
class FileStreamWriter : public StreamWriter {
private:
    std::ofstream file;
    mutable std::mutex writeMutex;
    
public:
    explicit FileStreamWriter(const std::string& filename) {
        file.open(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file for writing: " + filename);
        }
    }
    
    size_t write(const char* data, size_t size) override {
        std::lock_guard<std::mutex> lock(writeMutex);
        file.write(data, size);
        return file.good() ? size : 0;
    }
    
    void flush() override {
        std::lock_guard<std::mutex> lock(writeMutex);
        file.flush();
    }
    
    bool isChunked() const override {
        return false;
    }
    
    void close() override {
        std::lock_guard<std::mutex> lock(writeMutex);
        file.close();
    }
};

// Utility function for streaming file reads without loading entire file
inline void streamFile(const std::string& filename, 
                      std::function<bool(const char*, size_t)> callback) {
    FileStreamReader reader(filename);
    char buffer[STREAM_BUFFER_SIZE];
    
    while (reader.hasMore()) {
        size_t bytesRead = reader.read(buffer, sizeof(buffer));
        if (bytesRead > 0) {
            if (!callback(buffer, bytesRead)) {
                break; // Callback requested to stop
            }
        }
    }
}

inline std::string readFileToString(const std::string &filename) {
  try {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
      throw std::runtime_error("Cannot open file");

    std::streamsize size = file.tellg();
    if (size > 1024 * 1024 * 100) { // 100MB limit for direct string loading
        throw std::runtime_error("File too large for direct string loading, use streaming instead");
    }
    
    std::string content(size, '\0');
    file.seekg(0, std::ios::beg);
    file.read(&content[0], size);
    return content;
  } catch (const std::exception &e) {
    throw errors::FileReadError(filename);
  }
}

} // namespace cppi::helpers
