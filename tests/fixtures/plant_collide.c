// plant_collide.c — plant one hash map with 64 keys in 64 buckets, so many
// buckets end up holding a chain of two or more entries (hash collisions).
// Prints ground truth in the same TRUTH format as the other planters and stays
// running so the map is alive during capture.
//
// Why 64 in 64: the kernel sizes a hash map's bucket array to max_entries
// rounded up to a power of two, and places each key with a randomly seeded
// hash. With 64 keys in 64 buckets, the chance that no two keys share a bucket
// is about 1 in 10^27, so collisions are certain in practice. The chain_stats
// plugin then counts the actual chain lengths in the memory image.
//
// Build:  gcc -static -O2 -o plant_collide plant_collide.c
// Run:    sudo ./plant_collide | tee ~/DF_proj/truth_collide.txt

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define N_KEYS 64

static long sys_bpf(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static void print_hex(const void *p, size_t n)
{
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void)
{
    union bpf_attr a;

    memset(&a, 0, sizeof(a));
    a.map_type    = BPF_MAP_TYPE_HASH;
    a.key_size    = 4;
    a.value_size  = 8;
    a.max_entries = N_KEYS;
    strncpy(a.map_name, "cart_collide", sizeof(a.map_name) - 1);
    int fd = sys_bpf(BPF_MAP_CREATE, &a);
    if (fd < 0) { perror("BPF_MAP_CREATE"); return 1; }

    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd   = fd;
    a.info.info_len = sizeof(info);
    a.info.info     = (uint64_t)(uintptr_t)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) != 0) { perror("get_info"); return 1; }

    for (uint32_t i = 0; i < N_KEYS; i++) {
        uint32_t key = 5000 + i;
        unsigned char val[8];
        memcpy(val, "COLL", 4);          // bytes 0-3: "COLL"
        memcpy(val + 4, &i, 4);          // bytes 4-7: entry number

        memset(&a, 0, sizeof(a));
        a.map_fd = fd;
        a.key    = (uint64_t)(uintptr_t)&key;
        a.value  = (uint64_t)(uintptr_t)val;
        a.flags  = BPF_ANY;
        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) != 0) { perror("BPF_MAP_UPDATE_ELEM"); return 1; }

        printf("TRUTH map=cart_collide id=%u key=", info.id);
        print_hex(&key, 4);
        printf(" value=");
        print_hex(val, 8);
        printf("\n");
    }

    printf("PLANTED-OK\n");
    fflush(stdout);
    pause();   // keep the fd (and so the map) alive until Ctrl+C
    return 0;
}
