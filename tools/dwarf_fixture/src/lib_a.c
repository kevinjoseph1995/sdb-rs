/*
 * Translation unit A — exercises a broad mix of DWARF tags, attribute forms,
 * and DIE references so the gimli comparison tests have varied input.
 */

#include <stddef.h>
#include <stdint.h>

/* A bit-fielded struct: exercises DW_TAG_member with DW_AT_bit_size /
 * DW_AT_data_bit_offset (typically data1 / udata forms). */
struct flags_a {
    uint8_t  a_low  : 3;
    uint8_t  a_high : 5;
    uint16_t a_wide;
    uint32_t a_word;
};

/* Tagged enum — DW_TAG_enumeration_type with DW_TAG_enumerator children
 * carrying DW_AT_const_value (data forms). */
enum color_a {
    COLOR_A_RED   = 0,
    COLOR_A_GREEN = 1,
    COLOR_A_BLUE  = 0x7fffffff,
    COLOR_A_NEG   = -1,
};

/* Union — DW_TAG_union_type. */
union maybe_a {
    int32_t  as_int;
    float    as_float;
    void    *as_ptr;
};

/* Typedef chain — produces DW_TAG_typedef DIEs with DW_AT_type references. */
typedef struct flags_a flags_a_t;
typedef flags_a_t      flags_alias_t;

/* A function pointer type — DW_TAG_subroutine_type with parameter children. */
typedef int (*binop_a)(int, int);

/* Multi-dimensional array — DW_TAG_array_type with DW_TAG_subrange_type. */
static const int matrix_a[3][4] = {
    {  1,  2,  3,  4 },
    {  5,  6,  7,  8 },
    {  9, 10, 11, 12 },
};

/* Global with string initializer — pulls a .rodata address into DW_AT_location. */
const char hello_a[] = "hello from translation unit a";

/* extern global so the linker actually keeps these symbols. */
extern int sink_a;
int sink_a = 0;

/* Static function — DW_AT_external = false. */
static int add_a(int x, int y) {
    return x + y;
}

/* extern function — DW_AT_external = true, DW_AT_low_pc / DW_AT_high_pc. */
int compute_a(flags_alias_t *f, enum color_a c, union maybe_a *m, binop_a op) {
    int acc = 0;
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 4; ++j) {
            acc = op(acc, matrix_a[i][j]);
        }
    }
    if (f) {
        acc += f->a_low + f->a_high + f->a_wide + (int)f->a_word;
    }
    if (m) {
        acc ^= m->as_int;
    }
    return acc + (int)c + add_a(acc, 1);
}

/* Public entry the Rust main calls. */
int entry_a(void) {
    flags_alias_t f = { 1, 2, 3, 4 };
    union maybe_a m;
    m.as_int = 42;
    sink_a += compute_a(&f, COLOR_A_GREEN, &m, add_a);
    sink_a += (int)hello_a[0];
    return sink_a;
}
