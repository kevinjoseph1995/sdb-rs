/*
 * Entry point so the fixture links as a standalone, C-only executable. The
 * interesting DWARF lives in lib_a.c / lib_b.c; this just references their
 * public entries so the linker keeps them.
 */

extern int  entry_a(void);
extern long entry_b(void);

int main(void) {
    int  a = entry_a();
    long b = entry_b();
    return (int)(((long)a + b) & 0xff);
}
