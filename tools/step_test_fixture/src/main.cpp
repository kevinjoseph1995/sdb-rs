// clang-format off
// The layout here is deliberate: tests look up lines by `// MARK:` comments and
// rely on specific line structure, so keep clang-format away from this file.
#include <cstdio>

// Lines tagged `// MARK:<name>` are looked up by the tests in
// libsdb/tests/stepping.rs, so they can find lines without hard-coding numbers.

volatile int sink = 0;

__attribute__((always_inline)) inline void scratch_ears() {
  std::puts("Scratching ears");
}

inline void pet_cat() {
  scratch_ears();
  std::puts("Done petting cat");
}

void find_happiness() {
  pet_cat();
  std::puts("Found happiness");
}

// ---------------------------------------------------------------------------
// Corner-case scenarios. Each is a separate noinline function, so a test can
// stop at its entry with a function breakpoint.
// ---------------------------------------------------------------------------

__attribute__((noinline)) void leaf() {
  sink = sink + 1; // MARK:leaf_body
}

__attribute__((noinline)) void empty() {} // MARK:empty

// A callee that a test places a breakpoint in while stepping over its caller.
__attribute__((noinline)) void breakpoint_in_callee_scenario() {
  leaf();   // MARK:bp_callee_call
  sink = 0; // MARK:bp_callee_after
}

// Inline functions nested three deep. All three begin at the same address.
__attribute__((always_inline)) inline void inner() {
  sink = sink + 1; // MARK:inner_body
}
__attribute__((always_inline)) inline void middle() {
  inner();         // MARK:middle_call
  sink = sink + 2; // MARK:middle_after
}
__attribute__((always_inline)) inline void outer() {
  middle();        // MARK:outer_call
  sink = sink + 3; // MARK:outer_after
}
__attribute__((noinline)) void nested_inline_scenario() {
  outer();         // MARK:nested_call
  sink = sink + 4; // MARK:nested_after
}

// The same inline function inlined twice in a row.
__attribute__((always_inline)) inline void twice_inlined() { sink = sink + 10; }
__attribute__((noinline)) void inline_twice_scenario() {
  twice_inlined(); // MARK:inline_first
  twice_inlined(); // MARK:inline_second
  sink = 0;        // MARK:inline_twice_after
}

// An inline function whose body contains a real call.
__attribute__((always_inline)) inline void inline_calls_leaf() {
  leaf();   // MARK:inline_call_leaf
  sink = 5; // MARK:inline_call_after_leaf
}
__attribute__((noinline)) void inline_with_call_scenario() {
  inline_calls_leaf(); // MARK:inline_with_call_site
  sink = 0;            // MARK:inline_with_call_after
}

// A loop: the body line is visited several times.
__attribute__((noinline)) void loop_scenario() {
  for (int i = 0; i < 3; ++i) { // MARK:loop_header
    leaf();                     // MARK:loop_body
  }
  sink = 0; // MARK:loop_after
}

// Recursion: the same return address is shared by every active frame.
__attribute__((noinline)) int recurse(int n) {
  if (n == 0)
    return 0;                // MARK:recurse_check
  return recurse(n - 1) + 1; // MARK:recurse_call
}
__attribute__((noinline)) void recursion_scenario() {
  int r = recurse(2); // MARK:recurse_call_site
  sink = r;           // MARK:recurse_after
}

// Two calls on one source line.
__attribute__((noinline)) void two_calls_scenario() {
  leaf();
  leaf();   // MARK:two_calls
  sink = 0; // MARK:two_calls_after
}

// Control flow that jumps over a line.
__attribute__((noinline)) int clamp(int x) {
  if (x > 10) { // MARK:clamp_if
    return 10;  // MARK:clamp_return_ten
  }
  return x; // MARK:clamp_return_x
} // MARK:clamp_end
__attribute__((noinline)) void branch_scenario() {
  sink = clamp(5); // MARK:branch_call
  sink = 0;        // MARK:branch_after
}

// Indirect call through a function pointer.
__attribute__((noinline)) void function_pointer_scenario() {
  void (*fp)() = leaf; // MARK:fp_assign
  fp();                // MARK:fp_call
  sink = 0;            // MARK:fp_after
}

// Virtual dispatch.
struct Base {
  virtual void speak() { sink = 1; }
};
struct Derived : Base {
  void speak() override {
    sink = 2; // MARK:derived_speak
  }
};
__attribute__((noinline)) void virtual_scenario() {
  Derived derived;
  Base *base = &derived; // MARK:virtual_assign
  base->speak();         // MARK:virtual_call
  sink = 0;              // MARK:virtual_after
}

// A line that calls only into code without debug info (libc).
__attribute__((noinline)) void libc_scenario() {
  std::puts("libc call"); // MARK:libc_call
  sink = 0;               // MARK:libc_after
}

// A function with an empty body.
__attribute__((noinline)) void empty_scenario() {
  empty();  // MARK:empty_call
  sink = 0; // MARK:empty_after
}

int main() {
  find_happiness();
  find_happiness();
  breakpoint_in_callee_scenario();
  nested_inline_scenario();
  inline_twice_scenario();
  inline_with_call_scenario();
  loop_scenario();
  recursion_scenario();
  two_calls_scenario();
  branch_scenario();
  function_pointer_scenario();
  virtual_scenario();
  libc_scenario();
  empty_scenario();
  return 0; // MARK:main_return
} // MARK:main_end
// clang-format on
