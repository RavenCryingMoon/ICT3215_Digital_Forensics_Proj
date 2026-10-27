// plant_maps.c - create BPF maps with known contents via the raw bpf() syscall,
// print the ground truth, then hold the fds open so the maps stay allocated.
// Static build: gcc -static -O2 -o plant_maps plant_maps.c
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_bpf(int cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int map_create(uint32_t type, uint32_t ks, uint32_t vs, uint32_t max,
                      uint32_t flags, const char *name) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_type = type;
    a.key_size = ks;
    a.value_size = vs;
    a.max_entries = max;
    a.map_flags = flags;
    strncpy(a.map_name, name, sizeof(a.map_name) - 1);
    int fd = sys_bpf(BPF_MAP_CREATE, &a);
    if (fd < 0) { perror(name); exit(1); }
    return fd;
}

static void map_update(int fd, const void *k, const void *v) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = fd;
    a.key = (uint64_t)(uintptr_t)k;
    a.value = (uint64_t)(uintptr_t)v;
    a.flags = BPF_ANY;
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) < 0) { perror("update"); exit(1); }
}

static uint32_t map_id(int fd) {
    struct bpf_map_info info;
    union bpf_attr a;
    memset(&info, 0, sizeof(info));
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = fd;
    a.info.info_len = sizeof(info);
    a.info.info = (uint64_t)(uintptr_t)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) < 0) { perror("info"); exit(1); }
    return info.id;
}

static void hex(const char *tag, const uint8_t *p, size_t n) {
    printf("%s=", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void truth(const char *map, uint32_t id, const void *k, size_t ks,
                  const void *v, size_t vs) {
    printf("TRUTH map=%s id=%u ", map, id);
    hex("key", k, ks);
    printf(" ");
    hex("value", v, vs);
    printf("\n");
}

int main(void) {
    // 1. Array control: key 4, value 8, 4 entries; index 1 set.
    int arr = map_create(BPF_MAP_TYPE_ARRAY, 4, 8, 4, 0, "cart_arr");
    uint32_t ai = 1;
    uint8_t av[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    map_update(arr, &ai, av);
    truth("cart_arr", map_id(arr), &ai, 4, av, 8);

    // 2. Preallocated hash: key 4 (u32 PID-like), value 8, 16 entries.
    //    Several entries so that at least some buckets are likely to chain.
    int h = map_create(BPF_MAP_TYPE_HASH, 4, 8, 16, 0, "cart_hash");
    uint32_t hid = map_id(h);
    uint32_t keys[] = {1337, 4242, 31337, 7, 65535, 100, 101, 102, 103, 104};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        uint8_t v[8];
        memcpy(v, "CARTGR", 6);
        v[6] = (uint8_t)('0' + i);
        v[7] = 0;
        map_update(h, &keys[i], v);
        truth("cart_hash", hid, &keys[i], 4, v, 8);
    }
    // 2b. LRU hash: same bucket/chain layout as a regular hash, plus an
    //     eviction policy. Tests that the hash walk also handles LRU_HASH.
    int lru = map_create(BPF_MAP_TYPE_LRU_HASH, 4, 8, 64, 0, "cart_lru");
    uint32_t lid = map_id(lru);
    uint32_t lkeys[] = {11, 22, 33};
    for (size_t i = 0; i < sizeof(lkeys) / sizeof(lkeys[0]); i++) {
        uint8_t v[8];
        memcpy(v, "LRUMAP", 6);
        v[6] = (uint8_t)('0' + i);
        v[7] = 0;
        map_update(lru, &lkeys[i], v);
        truth("cart_lru", lid, &lkeys[i], 4, v, 8);
    }
    // 2c. Per-CPU hash: the map keeps one value PER CPU. To set an entry from
    //     userspace you must hand the kernel a buffer holding a value for EVERY
    //     CPU, laid out back-to-back (stride = round_up(value_size, 8) per CPU;
    //     value_size is 8 here, so stride is just 8). We write the same value to
    //     every CPU to keep the ground truth simple for now.
    int ncpus = (int)sysconf(_SC_NPROCESSORS_CONF);
    int pcpu = map_create(BPF_MAP_TYPE_PERCPU_HASH, 4, 8, 16, 0, "cart_pcpu");
    uint32_t pid = map_id(pcpu);
    uint32_t pkeys[] = {1000, 2000};
    for (size_t i = 0; i < sizeof(pkeys) / sizeof(pkeys[0]); i++) {
        uint8_t one[8];                       // the value we put on every CPU
        memcpy(one, "PCPUMAP", 7);
        one[7] = (uint8_t)('0' + i);

        // per-CPU update buffer: ncpus copies of the 8-byte value, back to back
        uint8_t *buf = (uint8_t *)malloc((size_t)ncpus * 8);
        if (!buf) { perror("malloc"); exit(1); }
        for (int c = 0; c < ncpus; c++)
            memcpy(buf + (size_t)c * 8, one, 8);

        map_update(pcpu, &pkeys[i], buf);     // kernel copies slot c -> CPU c
        truth("cart_pcpu", pid, &pkeys[i], 4, one, 8);  // records the per-CPU value
        free(buf);
    }

    // 3. Non-preallocated hash with odd sizes: key 6, value 12 (tests
    //    round_up(key_size, 8) alignment of the value).
    int hn = map_create(BPF_MAP_TYPE_HASH, 6, 12, 8, BPF_F_NO_PREALLOC,
                        "cart_hash_np");
    uint32_t hnid = map_id(hn);
    uint8_t k6a[6] = {'s', 'e', 'c', 'r', 'e', 't'};
    uint8_t v12a[12] = "hidden.txt\0";
    map_update(hn, k6a, v12a);
    truth("cart_hash_np", hnid, k6a, 6, v12a, 12);
    uint8_t k6b[6] = {'p', 'i', 'd', 0, 0x39, 0x05};
    uint8_t v12b[12] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8};
    map_update(hn, k6b, v12b);
    truth("cart_hash_np", hnid, k6b, 6, v12b, 12);

    // 4. Empty hash map (expected result: zero entries, status traversed).
    int he = map_create(BPF_MAP_TYPE_HASH, 4, 4, 8, 0, "cart_empty");
    printf("TRUTH map=cart_empty id=%u (empty)\n", map_id(he));

    printf("PLANTED-OK\n");
    fflush(stdout);
    for (;;) pause();
}
