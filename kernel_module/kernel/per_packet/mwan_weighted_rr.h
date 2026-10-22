#ifndef MWAN_WEIGHTED_RR_H
#define MWAN_WEIGHTED_RR_H

/* Exact weighted round-robin over an immutable eligibility snapshot.
 * Reduce by GCD so 80:20 repeats every five selections rather than 100.
 * Zero weights are ineligible. The cursor remains valid after path/weight
 * changes and is advanced only on a successful selection. */
static inline int mwan_weighted_rr_pick(const unsigned int *weights,
                                        unsigned int count,
                                        unsigned int *cursor)
{
    unsigned int divisor = 0, total = 0, slot, i;

    for (i = 0; i < count; i++) {
        unsigned int a = divisor, b = weights[i];

        while (b) {
            unsigned int remainder = a % b;

            a = b;
            b = remainder;
        }
        divisor = a;
        total += weights[i];
    }
    if (!total)
        return -1;
    total /= divisor;
    slot = *cursor % total;
    *cursor = (slot + 1) % total;
    for (i = 0; i < count; i++) {
        unsigned int quota = weights[i] / divisor;

        if (slot < quota)
            return (int)i;
        slot -= quota;
    }
    return -1;
}

#endif
