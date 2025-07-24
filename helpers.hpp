#pragma once
#include "errors.hpp"
#include <fstream>
#include <string>

namespace cppi::helpers {
inline std::string readFileToString(const std::string &filename) {
  try {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
      throw std::runtime_error("Cannot open file");

    std::streamsize size = file.tellg();
    std::string content(size, '\0');
    file.seekg(0, std::ios::beg);
    file.read(&content[0], size);
    return content;
  } catch (const std::exception &e) {
    throw cppi::errors::FileReadError(filename);
  }
}

} // namespace cppi::helpers
