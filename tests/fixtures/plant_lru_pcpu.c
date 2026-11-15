// plant_lru_pcpu.c — plant one BPF_MAP_TYPE_LRU_PERCPU_HASH map with known
// entries, print ground truth, and stay running so the map is alive during
// capture. Same TRUTH format as plant_maps, so verify.py reads it unchanged.
//
// Build:  gcc -static -O2 -o plant_lru_pcpu plant_lru_pcpu.c
// Run:    sudo ./plant_lru_pcpu | tee ~/DF_proj/truth_lru_pcpu.txt
//         (leave it running until the image is taken, then Ctrl+C)

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static long sys_bpf(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

// Number of possible CPUs, e.g. "0-127" -> 128. The kernel expects one value
// per possible CPU when user space writes a per-CPU map.
static int possible_cpus(void)
{
    char buf[256] = {0};
    FILE *f = fopen("/sys/devices/system/cpu/possible", "r");
    if (!f || !fgets(buf, sizeof(buf), f)) { perror("cpu/possible"); exit(1); }
    fclose(f);
    int count = 0;
    for (char *tok = strtok(buf, ",\n"); tok; tok = strtok(NULL, ",\n")) {
        int a, b;
        int n = sscanf(tok, "%d-%d", &a, &b);
        count += (n == 2) ? (b - a + 1) : 1;
    }
    return count;
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
    a.map_type    = BPF_MAP_TYPE_LRU_PERCPU_HASH;
    a.key_size    = 4;
    a.value_size  = 8;
    a.max_entries = 16;
    strncpy(a.map_name, "cart_lru_pcpu", sizeof(a.map_name) - 1);
    int fd = sys_bpf(BPF_MAP_CREATE, &a);
    if (fd < 0) { perror("BPF_MAP_CREATE"); return 1; }

    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd   = fd;
    a.info.info_len = sizeof(info);
    a.info.info     = (uint64_t)(uintptr_t)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) != 0) { perror("get_info"); return 1; }

    int ncpu = possible_cpus();
    uint64_t *vals = calloc(ncpu, sizeof(uint64_t));   // value_size 8, already 8-aligned
    if (!vals) { perror("calloc"); return 1; }

    const uint32_t keys[3]  = { 42, 99, 1024 };
    const char    *names[3] = { "LRUPCPU0", "LRUPCPU1", "LRUPCPU2" };  // 8 bytes each

    for (int k = 0; k < 3; k++) {
        uint64_t v;
        memcpy(&v, names[k], 8);
        for (int c = 0; c < ncpu; c++) vals[c] = v;       // same value in every CPU slot

        memset(&a, 0, sizeof(a));
        a.map_fd = fd;
        a.key    = (uint64_t)(uintptr_t)&keys[k];
        a.value  = (uint64_t)(uintptr_t)vals;
        a.flags  = BPF_ANY;
        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) != 0) { perror("BPF_MAP_UPDATE_ELEM"); return 1; }

        printf("TRUTH map=cart_lru_pcpu id=%u key=", info.id);
        print_hex(&keys[k], 4);
        printf(" value=");
        print_hex(&v, 8);
        printf("\n");
    }

    printf("PLANTED-OK\n");
    fflush(stdout);
    pause();   // keep the fd (and so the map) alive until Ctrl+C
    return 0;
}
