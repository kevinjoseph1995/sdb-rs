#include <cstdio>
#include <ios>
#include <iostream>
#include <cstdint>
#include <numeric>

extern "C" void an_innocent_function() {
  std::cout << "Unmodified" << std::endl;
}
extern "C" void an_innocent_function_end() {}
extern "C" int checksum() {
  auto start = reinterpret_cast<volatile const char *>(&an_innocent_function);
  auto end = reinterpret_cast<volatile const char *>(&an_innocent_function_end);
  return std::accumulate(start, end, 0);
}
extern "C" void print_address_of_an_innocent_function() {
  std::cout <<  std::hex << reinterpret_cast<std::uintptr_t>(an_innocent_function) << std::endl;
  fflush(stdout);
}