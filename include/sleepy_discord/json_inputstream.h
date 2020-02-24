#pragma once

#include <string>

namespace SleepyDiscord {

class JsonInputStream {
 public:
  typedef char Ch;

  [[nodiscard]] virtual Ch Peek() const = 0;
  virtual Ch Take() = 0;
  [[nodiscard]] virtual size_t Tell() const = 0;

  Ch* PutBegin() { return nullptr; }
  void Put(Ch ch) {}
  void Flush() {}
  size_t PutEnd(Ch* ch) { return 0; }

  [[nodiscard]] const Ch* Peek4() const { return nullptr; }

  virtual void SetCache(bool enable) = 0;
  [[nodiscard]] virtual const std::string& GetCache() const = 0;
};
}  // namespace SleepyDiscord
