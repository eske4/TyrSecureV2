#pragma once

#include <string>
#include <vector>

namespace OdinSight::Util::CInterop {
/**
 * Converts std::vector<std::string> into std::vector<char*>.
 * The resulting vector is NULL-terminated for compatibility with fexecve.
 * @warning The pointers point directly to the memory owned by the input vector.
 */
[[nodiscard]] inline std::vector<char *> toCStringVector(const std::vector<std::string> &items) {
  std::vector<char *> raw;

  raw.reserve(items.size() + 1);

  for (const auto &str : items) {
    // str.c_str() returns const char*, so we cast to char* for C APIs
    raw.emplace_back(const_cast<char *>(str.c_str()));
  }

  raw.emplace_back(nullptr);
  return raw;
}
} // namespace OdinSight::Util::CInterop
