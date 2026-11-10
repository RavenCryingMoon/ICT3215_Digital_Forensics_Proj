// cart_btf_loader.c — load cart_btf.bpf.o, fill its map with known entries,
// print ground truth, and stay running so the map lives in RAM during capture.
//
// Build:
//   gcc -O2 -o cart_btf_loader cart_btf_loader.c -lbpf
// Run (hold it open while you acquire the image, Ctrl+C after):
//   sudo ./cart_btf_loader | tee ~/DF_proj/truth_btf.txt

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

// Must match struct cart_evt in cart_btf.bpf.c exactly (same order, same types).
struct cart_evt {
    uint32_t pid;
    char     comm[16];
    uint64_t count;
};

// Print a byte buffer as lowercase hex, in memory order (matches how the
// planter and verify.py treat keys and values).
static void print_hex(const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
}

// One planted entry: print the TRUTH line, then insert it into the map.
static void plant(int fd, uint32_t id, uint32_t key, const struct cart_evt *val)
{
    printf("TRUTH map=cart_btf id=%u key=", id);
    print_hex(&key, sizeof(key));
    printf(" value=");
    print_hex(val, sizeof(*val));
    printf("\n");
    if (bpf_map_update_elem(fd, &key, val, BPF_ANY) != 0)
        perror("bpf_map_update_elem");
}

int main(void)
{
    struct bpf_object *obj = bpf_object__open_file("cart_btf.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open_file failed\n"); return 1; }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "cart_btf");
    if (!map) { fprintf(stderr, "map not found\n"); return 1; }
    int fd = bpf_map__fd(map);

    // Look up the map's kernel id so the TRUTH lines carry it (verify.py keys on id).
    struct bpf_map_info info;
    uint32_t len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) { perror("get_info"); return 1; }
    uint32_t id = info.id;

    // Two known entries. memset first so the padding byte(s) are deterministic
    // zeros — otherwise the recovered value bytes wouldn't match ground truth.
    struct cart_evt v;

    memset(&v, 0, sizeof(v));
    v.pid = 1337; strncpy(v.comm, "cartographer", sizeof(v.comm) - 1); v.count = 42;
    plant(fd, id, 1337, &v);

    memset(&v, 0, sizeof(v));
    v.pid = 4242; strncpy(v.comm, "evil", sizeof(v.comm) - 1); v.count = 7;
    plant(fd, id, 4242, &v);

    printf("PLANTED-OK\n");
    fflush(stdout);

    // Hold the object (and therefore the map) alive in the kernel until Ctrl+C.
    pause();

    bpf_object__close(obj);
    return 0;
}
