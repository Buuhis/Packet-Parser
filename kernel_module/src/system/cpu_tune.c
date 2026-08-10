#define _GNU_SOURCE
#include "cpu_tune.h"
#include "../utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <net/if.h>

/* ================================================================
 *  Backup / Restore Infrastructure
 *  - Mỗi lần ghi sysfs, lưu giá trị cũ vào mảng backup
 *  - Khi restore, ghi lại giá trị cũ theo thứ tự ngược
 * ================================================================ */

#define MAX_BACKUP_ENTRIES 128
#define MAX_MODIFIED_IFACES 16

typedef struct {
    char path[256];
    char original[64];
} backup_entry_t;

typedef struct {
    char ifname[IF_NAMESIZE];
} qdisc_backup_t;

typedef struct {
    char ifname[IF_NAMESIZE];
    int  original_combined;      /* Original combined queue count */
} multiqueue_backup_t;

static backup_entry_t       g_backups[MAX_BACKUP_ENTRIES];
static int                  g_backup_count = 0;

static qdisc_backup_t       g_qdisc_backups[MAX_MODIFIED_IFACES];
static int                  g_qdisc_count = 0;

static multiqueue_backup_t  g_mq_backups[MAX_MODIFIED_IFACES];
static int                  g_mq_count = 0;

static bool g_irqbalance_was_active = false;
static bool g_tuning_applied = false;

/* ================================================================
 *  Low-level helpers
 * ================================================================ */

static int get_num_cpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

static int read_sysfs(const char *path, char *buf, size_t len)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(buf, 0, len);
    if (!fgets(buf, (int)len, f)) { fclose(f); return -1; }
    fclose(f);
    buf[strcspn(buf, "\n\r")] = '\0';
    return 0;
}

/* Write to sysfs, saving original value for restore */
static int write_sysfs(const char *path, const char *value)
{
    /* Save original */
    if (g_backup_count < MAX_BACKUP_ENTRIES) {
        backup_entry_t *e = &g_backups[g_backup_count];
        if (read_sysfs(path, e->original, sizeof(e->original)) == 0) {
            snprintf(e->path, sizeof(e->path), "%s", path);
            g_backup_count++;
        }
    }

    /* Write new value */
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", value);
    fclose(f);
    return 0;
}

/* Count TX or RX queues for an interface */
static int count_queues(const char *ifname, const char *prefix)
{
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "/sys/class/net/%s/queues", ifname);
    DIR *d = opendir(dirpath);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    size_t plen = strlen(prefix);
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, prefix, plen) == 0)
            count++;
    }
    closedir(d);
    return count;
}

/* Detect the underlying physical NIC of a virtual (e.g. VXLAN) interface.
 * Scans /sys/class/net/<virt_ifname>/ for symlinks starting with lower_ (e.g. lower_enp4s0).
 * Falls back to ifindex vs iflink comparison if no lower_ symlink is found. */
static int get_lower_ifname(const char *virt_ifname, char *lower_name, size_t len)
{
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "/sys/class/net/%s", virt_ifname);
    DIR *d = opendir(dirpath);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "lower_", 6) == 0) {
                const char *phys_name = ent->d_name + 6;
                if (strlen(phys_name) > 0 && strlen(phys_name) < len) {
                    snprintf(lower_name, len, "%s", phys_name);
                    closedir(d);
                    return 0;
                }
            }
        }
        closedir(d);
    }

    /* Fallback: Compares ifindex vs iflink */
    char path[256], buf[32];
    int own_idx, link_idx;

    snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", virt_ifname);
    if (read_sysfs(path, buf, sizeof(buf)) < 0) return -1;
    own_idx = atoi(buf);

    snprintf(path, sizeof(path), "/sys/class/net/%s/iflink", virt_ifname);
    if (read_sysfs(path, buf, sizeof(buf)) < 0) return -1;
    link_idx = atoi(buf);

    if (own_idx == link_idx || link_idx == 0) return -1;

    char temp[IF_NAMESIZE];
    if (if_indextoname((unsigned)link_idx, temp) == NULL) return -1;

    snprintf(lower_name, len, "%s", temp);
    return 0;
}

static bool is_irqbalance_active(void)
{
    int ret = system("systemctl is-active --quiet irqbalance 2>/dev/null");
    return (ret == 0);
}

/* ================================================================
 *  NIC Hardware Setup (ethtool)
 * ================================================================ */

typedef struct {
    int max_combined;
    int cur_combined;
} ethtool_queues_t;

/* Get both Max and Current combined queue count for a NIC. */
static ethtool_queues_t get_ethtool_queues(const char *ifname)
{
    ethtool_queues_t res = {-1, -1};
    char cmd[256], line[256];
    snprintf(cmd, sizeof(cmd), "ethtool -l %s 2>/dev/null", ifname);
    FILE *p = popen(cmd, "r");
    if (!p) return res;

    bool in_max_block = false;
    bool in_cur_block = false;

    while (fgets(line, sizeof(line), p)) {
        if (strstr(line, "Pre-set maximums:")) {
            in_max_block = true; 
            in_cur_block = false;
            continue;
        }
        if (strstr(line, "Current hardware settings:")) {
            in_max_block = false;
            in_cur_block = true;
            continue;
        }
        
        char *colon = strchr(line, ':');
        if (colon && strstr(line, "Combined")) {
            int val = atoi(colon + 1);
            if (in_max_block) res.max_combined = val;
            else if (in_cur_block) res.cur_combined = val;
        }
    }
    pclose(p);
    return res;
}

/* Set combined queue count on a physical NIC.
 * Equivalent to: ethtool -L <dev> combined <n>
 * Respects hardware limits to avoid "failed to set" errors. */
static void setup_multiqueue(const char *ifname, int num_cpus)
{
    ethtool_queues_t q = get_ethtool_queues(ifname);
    if (q.max_combined <= 0) {
        log_debug("    MultiQ: %s — cannot read queue capability (max=%d)", ifname, q.max_combined);
        return;
    }

    int target = (num_cpus < q.max_combined) ? num_cpus : q.max_combined;

    if (q.cur_combined == target) {
        log_info("    MultiQ: %s already has %d combined queues (max is %d)", ifname, target, q.max_combined);
        return;
    }

    /* Save original for restore */
    if (g_mq_count < MAX_MODIFIED_IFACES) {
        multiqueue_backup_t *b = &g_mq_backups[g_mq_count];
        snprintf(b->ifname, sizeof(b->ifname), "%s", ifname);
        b->original_combined = q.cur_combined;
        g_mq_count++;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ethtool -L %s combined %d 2>/dev/null", ifname, target);
    int ret = system(cmd);
    if (ret == 0) {
        log_info("    MultiQ: %s %d -> %d combined queues (cap at max %d)", ifname, q.cur_combined, target, q.max_combined);
    } else {
        log_warn("    MultiQ: %s failed to set %d queues (hardware max is %d)",
                 ifname, target, q.max_combined);
    }
}

/* Set RSS hash to full 4-tuple (src_ip, dst_ip, src_port, dst_port) for UDP & TCP.
 * Equivalent to: ethtool -N <dev> rx-flow-hash udp4/tcp4 sdfn */
static void setup_rss_hash(const char *ifname)
{
    char cmd[256];
    int res;

    snprintf(cmd, sizeof(cmd), "/sbin/ethtool -N %s rx-flow-hash udp4 sdfn 2>/dev/null || ethtool -N %s rx-flow-hash udp4 sdfn 2>/dev/null", ifname, ifname);
    res = system(cmd);
    if (res == 0)
        log_info("    RSS: %s udp4 -> sdfn (4-tuple)", ifname);
    else
        log_warn("    RSS: %s udp4 sdfn configuration returned code %d", ifname, res);

    /* Also set for TCP */
    snprintf(cmd, sizeof(cmd), "/sbin/ethtool -N %s rx-flow-hash tcp4 sdfn 2>/dev/null || ethtool -N %s rx-flow-hash tcp4 sdfn 2>/dev/null", ifname, ifname);
    res = system(cmd);
    if (res == 0)
        log_info("    RSS: %s tcp4 -> sdfn (4-tuple)", ifname);
    else
        log_warn("    RSS: %s tcp4 sdfn configuration returned code %d", ifname, res);
}

/* ================================================================
 *  Per-interface CPU tuning functions
 * ================================================================ */

/* XPS: Map TX queues to CPUs.
 * If num_queues < num_cpus (like single-queue tunnels), we map ALL CPUs to that queue 
 * to allow distributed parallel transmission without bottlenecking Core 0. */
static void setup_xps(const char *ifname, int num_cpus)
{
    (void)num_cpus;
    int num_tx = count_queues(ifname, "tx-");
    if (num_tx == 0) return;

    char path[256], mask[32];
    
    /* Optimization: If num_queues is very small (like a 1-queue tunnel),
     * we limit the XPS mask to a sub-group of CPUs (Hardware Master: Core 0-4). */
    int xps_limit = 4;

    for (int i = 0; i < num_tx; i++) {
        unsigned int cpu_mask = 0;
        
        if (num_tx == 1) {
            /* Case: Single queue tunnel. Map to all Master cores (0-4). */
            cpu_mask = (1U << xps_limit) - 1;
        } else {
            /* Case: Multi-queue. Distribute evenly across Master cores (0-4). */
            int target_cpu = i % xps_limit;
            cpu_mask = (1U << target_cpu);
        }
        
        if (cpu_mask == 0) continue;

        snprintf(path, sizeof(path), "/sys/class/net/%s/queues/tx-%d/xps_cpus", ifname, i);
        snprintf(mask, sizeof(mask), "%x", cpu_mask);
        
        if (write_sysfs(path, mask) == 0)
            log_info("    XPS: %s tx-%d -> CPU Mask %s", ifname, i, mask);
    }
}

/* RPS: Distribute RX processing across Software Worker cores */
static void setup_rps(const char *ifname, int num_cpus)
{
    int num_rx = count_queues(ifname, "rx-");
    if (num_rx == 0) return;

    int worker_start = 0;
    int num_workers = num_cpus;
    if (num_cpus >= 8) {
        worker_start = 2; /* Reserve Core 0 & 1 for system/control plane */
        num_workers = num_cpus - 2;
    } else if (num_cpus >= 4) {
        worker_start = 1; /* Reserve Core 0 for system */
        num_workers = num_cpus - 1;
    }

    unsigned int worker_mask = 0;
    for (int w = 0; w < num_workers; w++) {
        worker_mask |= (1U << (worker_start + w));
    }

    char path[256], mask[16];
    snprintf(mask, sizeof(mask), "%x", worker_mask);

    for (int i = 0; i < num_rx; i++) {
        snprintf(path, sizeof(path),
                 "/sys/class/net/%s/queues/rx-%d/rps_cpus", ifname, i);
        if (write_sysfs(path, mask) == 0)
            log_info("    RPS: %s rx-%d -> Worker CPUs (mask %s, start=%d, count=%d)",
                     ifname, i, mask, worker_start, num_workers);

        snprintf(path, sizeof(path),
                 "/sys/class/net/%s/queues/rx-%d/rps_flow_cnt", ifname, i);
        write_sysfs(path, "4096");
    }
}

/* IRQ Affinity: Pin each queue's hardware interrupt to a dedicated CPU.
 * Improved to avoid pinning management/link interrupts to extra cores. */
static void setup_irq_affinity(const char *ifname, int num_cpus)
{
    FILE *f = fopen("/proc/interrupts", "r");
    if (!f) return;

    char line[1024];
    int data_irq_idx = 0;

    while (fgets(line, sizeof(line), f) && data_irq_idx < num_cpus) {
        if (!strstr(line, ifname)) continue;

        /* Skip management/link interrupts if they don't look like data queues.
         * Data queues usually have labels like eth0-rx-0, eth0-0, or eth0-TxRx-0.
         * Simple heuristic: if there are multiple interrupts, the ones with numbers are data. */
        bool has_digit = false;
        char *suffix = strstr(line, ifname);
        for (char *p = suffix; *p; p++) { if (*p >= '0' && *p <= '9') { has_digit = true; break; } }
        
        /* If we found many interrupts but this one has no digit in name, 
         * it's likely a management interrupt — we'll pin it to CPU0 or skip. */
        if (!has_digit && data_irq_idx > 0) continue;

        int irq = 0;
        if (sscanf(line, " %d:", &irq) != 1 || irq <= 0) continue;

        char path[128], mask[32];
        snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
        
        /* Pin to Master Cores (0-4) only */
        int target_cpu = data_irq_idx % 5;
        snprintf(mask, sizeof(mask), "%x", 1 << target_cpu);

        if (write_sysfs(path, mask) == 0)
            log_info("    IRQ: %s irq=%d -> Master CPU %d", ifname, irq, target_cpu);
        
        data_irq_idx++;
    }
    fclose(f);
}

/* Qdisc: set mq (multi-queue) — each TX queue gets its own independent qdisc */
static void setup_mq_qdisc(const char *ifname)
{
    int num_tx = count_queues(ifname, "tx-");
    if (num_tx <= 1) return;   /* mq requires > 1 queue */

    /* Save interface name for restore */
    if (g_qdisc_count < MAX_MODIFIED_IFACES) {
        snprintf(g_qdisc_backups[g_qdisc_count].ifname, sizeof(g_qdisc_backups[g_qdisc_count].ifname), "%s", ifname);
        g_qdisc_count++;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root mq 2>/dev/null", ifname);
    int unused_ret = system(cmd);
    (void)unused_ret;
    log_info("    Qdisc: %s -> mq (%d queues)", ifname, num_tx);
}

/* Full setup for a physical NIC: multiqueue + sdfn + IRQ + XPS + RPS */
static void tune_physical_nic(const char *ifname, int num_cpus)
{
    setup_multiqueue(ifname, num_cpus);
    setup_rss_hash(ifname);
    setup_irq_affinity(ifname, num_cpus);
    setup_xps(ifname, num_cpus);
    setup_rps(ifname, num_cpus);
    setup_mq_qdisc(ifname);
}

/* Full setup for a tunnel interface: XPS + RPS + mq qdisc */
static void tusdwan_tun(const char *ifname, int num_cpus)
{
    setup_xps(ifname, num_cpus);
    setup_rps(ifname, num_cpus);
    setup_mq_qdisc(ifname);
}

/* ================================================================
 *  Public API
 * ================================================================ */

int cpu_tune_apply(const app_context_t *ctx)
{
    int num_cpus = get_num_cpus();

    log_info("========================================");
    log_info("  CPU Tuning: %d cores detected", num_cpus);
    log_info("========================================");

    /* 0. Stop irqbalance to prevent it from overriding our pinning */
    g_irqbalance_was_active = is_irqbalance_active();
    if (g_irqbalance_was_active) {
        int unused_ret = system("systemctl stop irqbalance 2>/dev/null");
        (void)unused_ret;
        log_info("  [+] Stopped irqbalance (will restart on restore)");
    }

    /* 1. Global settings */
    write_sysfs("/proc/sys/net/core/rps_sock_flow_entries", "32768");
    write_sysfs("/proc/sys/net/core/netdev_max_backlog", "10000");
    write_sysfs("/proc/sys/net/core/netdev_budget", "600");
    log_info("  [+] Global: rfs=32768, backlog=10000, budget=600");

    /* 2. Local interface — physical NIC (e.g. enp6s0) */
    log_info("  [Local NIC: %s]", ctx->cfg.local_if);
    tune_physical_nic(ctx->cfg.local_if, num_cpus);

    /* 3. Tunnel interfaces + auto-detect underlying physical NICs */
    char tuned_nics[MAX_SDWAN_TUNS][IF_NAMESIZE];
    int  tuned_nic_count = 0;

    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const char *tun = ctx->cfg.sdwan_tuns[i].ifname;
        log_info("  [Tunnel: %s]", tun);
        tusdwan_tun(tun, num_cpus);

        /* Auto-detect and tune the physical NIC underneath the VXLAN */
        char lower[IF_NAMESIZE] = {0};
        if (get_lower_ifname(tun, lower, sizeof(lower)) == 0) {
            /* Avoid tuning the same physical NIC twice */
            bool already = false;
            for (int j = 0; j < tuned_nic_count; j++) {
                if (strcmp(tuned_nics[j], lower) == 0) { already = true; break; }
            }
            /* Also skip if it's the same as local_if (already tuned above) */
            if (!already && strcmp(lower, ctx->cfg.local_if) != 0) {
                log_info("  [Physical WAN: %s (under %s)]", lower, tun);
                tune_physical_nic(lower, num_cpus);
                snprintf(tuned_nics[tuned_nic_count++], sizeof(tuned_nics[0]), "%s", lower);
            }
        }
    }

    g_tuning_applied = true;
    log_info("  ----------------------------------------");
    log_info("  CPU Tuning complete (%d sysfs, %d qdisc, %d multiqueue entries saved)",
             g_backup_count, g_qdisc_count, g_mq_count);
    return 0;
}

void cpu_tune_restore(void)
{
    if (!g_tuning_applied) return;

    log_info("========================================");
    log_info("  Restoring CPU settings to defaults...");
    log_info("========================================");

    /* 1. Restore all sysfs values in reverse order */
    for (int i = g_backup_count - 1; i >= 0; i--) {
        FILE *f = fopen(g_backups[i].path, "w");
        if (f) {
            fprintf(f, "%s\n", g_backups[i].original);
            fclose(f);
        }
    }
    log_info("  [+] Restored %d sysfs entries", g_backup_count);
    g_backup_count = 0;

    /* 2. Restore qdiscs to kernel default */
    for (int i = 0; i < g_qdisc_count; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "tc qdisc del dev %s root 2>/dev/null", g_qdisc_backups[i].ifname);
        int unused_ret = system(cmd);
        (void)unused_ret;
        log_info("  [+] Qdisc restored: %s -> default", g_qdisc_backups[i].ifname);
    }
    g_qdisc_count = 0;

    /* 3. Restore original combined queue counts */
    for (int i = 0; i < g_mq_count; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "ethtool -L %s combined %d 2>/dev/null",
                 g_mq_backups[i].ifname, g_mq_backups[i].original_combined);
        int unused_ret = system(cmd);
        (void)unused_ret;
        log_info("  [+] MultiQ restored: %s -> %d combined queues",
                 g_mq_backups[i].ifname, g_mq_backups[i].original_combined);
    }
    g_mq_count = 0;

    /* 4. Restart irqbalance if it was running before we stopped it */
    if (g_irqbalance_was_active) {
        int unused_ret = system("systemctl start irqbalance 2>/dev/null");
        (void)unused_ret;
        log_info("  [+] Restarted irqbalance");
        g_irqbalance_was_active = false;
    }

    g_tuning_applied = false;
    log_info("  System restored to default state");
}
