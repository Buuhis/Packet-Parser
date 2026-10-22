#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/per_packet/mwan_weighted_rr.h"
#include "../src/config/config_semantics.h"

static void check_ratio(const unsigned int *weights, unsigned int n)
{
    unsigned int starts[] = {0, 1, 17, UINT_MAX};
    unsigned int total = 0;

    for (unsigned int i = 0; i < n; i++)
        total += weights[i];
    for (unsigned int s = 0; s < sizeof(starts) / sizeof(starts[0]); s++) {
        unsigned int counts[100] = {0}, cursor = starts[s];

        for (unsigned int packet = 0; packet < total * 10; packet++) {
            int selected = mwan_weighted_rr_pick(weights, n, &cursor);

            assert(selected >= 0 && (unsigned int)selected < n);
            counts[selected]++;
        }
        for (unsigned int i = 0; i < n; i++)
            assert(counts[i] == weights[i] * 10);
    }
}

int main(void)
{
    const unsigned int ratios[][4] = {
        {80, 20, 0, 0}, {50, 50, 0, 0}, {33, 33, 34, 0},
        {1, 99, 0, 0}, {0, 0, 100, 0}, {40, 0, 20, 0}
    };
    unsigned int zero[4] = {0}, cursor = UINT_MAX;
    unsigned int weights[2] = {80, 20};
    app_config_t before = {0}, after;

    for (unsigned int i = 0; i < sizeof(ratios) / sizeof(ratios[0]); i++)
        check_ratio(ratios[i], 4);
    assert(mwan_weighted_rr_pick(zero, 4, &cursor) == -1);
    assert(cursor == UINT_MAX);
    assert(mwan_weighted_rr_pick(weights, 2, &cursor) >= 0);
    weights[0] = 0;
    for (int i = 0; i < 100; i++)
        assert(mwan_weighted_rr_pick(weights, 2, &cursor) == 1);
    weights[0] = 80;
    check_ratio(weights, 2);
    weights[0] = 20; weights[1] = 80;
    check_ratio(weights, 2);

    /* Exhaust all two-path integer percentage profiles. */
    for (unsigned int i = 0; i <= 100; i++) {
        weights[0] = i; weights[1] = 100 - i;
        check_ratio(weights, 2);
    }
    before.node_id = 1;
    before.sdwan_tun_count = 2;
    strcpy(before.sdwan_tuns[0].tunnel_ifname, "tun1");
    strcpy(before.sdwan_tuns[1].tunnel_ifname, "tun2");
    assert(config_weights_valid(&before)); /* disabled, all zero */
    after = before;
    after.weight_enabled = true;
    assert(!config_weights_valid(&after));
    after.sdwan_tuns[0].weight = 80;
    after.sdwan_tuns[1].weight = 20;
    assert(config_weights_valid(&after));
    assert(config_kernel_weight_only_changed(&before, &after));
    assert(!config_kernel_equal(&before, &after));
    assert(config_failover_equal(&before, &after)); /* keep BFD sessions */

    /* Flag-only updates must reach the kernel even with identical numbers. */
    before = after;
    after.weight_enabled = false;
    assert(!config_kernel_equal(&before, &after));
    assert(config_kernel_weight_only_changed(&before, &after));
    assert(config_failover_equal(&before, &after));
    assert(!config_pqc_policy_changed(&before, &after));
    assert(config_weights_valid(&after));
    after.sdwan_tuns[0].weight = -1;
    assert(!config_weights_valid(&after));
    puts("weight policy: ratios, DOWN/recovery, zero weights and config toggles passed");
    return 0;
}
