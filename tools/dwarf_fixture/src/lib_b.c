/*
 * Translation unit B — second CU. Forces find_cu_containing / abbrev-offset
 * bookkeeping to handle more than one compile unit, with its own distinct
 * abbreviation table (different declaration mix from lib_a.c).
 */

#include <stdint.h>

/* A linked-list-ish struct that references itself — exercises a DW_AT_type
 * reference whose target appears earlier in the same CU. */
struct node_b {
    int            value;
    struct node_b *next;
    double         weight;
};

/* Enum with explicit underlying values to push the encoder toward varied
 * data forms. */
enum mode_b {
    MODE_B_OFF    = 0,
    MODE_B_ON     = 1,
    MODE_B_PULSED = 0xabcd,
};

/* Nested struct — generates DW_AT_type references between siblings. */
struct pair_b {
    struct node_b head;
    enum mode_b   mode;
};

extern long sink_b;
long sink_b = 0;

/* Recursive function — DW_TAG_subprogram with DW_AT_inline maybe. */
static long sum_b(struct node_b *n) {
    if (!n) return 0;
    return (long)n->value + sum_b(n->next);
}

long entry_b(void) {
    struct node_b tail = { .value = 3, .next = 0,    .weight = 1.5 };
    struct node_b mid  = { .value = 2, .next = &tail, .weight = 2.5 };
    struct node_b head = { .value = 1, .next = &mid,  .weight = 3.5 };
    struct pair_b p    = { .head = head, .mode = MODE_B_PULSED };
    sink_b += sum_b(&p.head);
    return sink_b;
}
