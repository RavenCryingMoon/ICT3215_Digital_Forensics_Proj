// hide_loader.c — load hide.bpf.o, populate its hide-list, attach it, print
// ground truth, and stay running so the map lives in RAM during capture.
//
// Build:
//   gcc -O2 -o hide_loader hide_loader.c -lbpf
// Run (hold it open while you acquire the image, Ctrl+C after):
//   sudo ./hide_loader | tee ~/DF_proj/truth_hide.txt

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

// Must match struct hide_rule in hide.bpf.c exactly.
struct hide_rule {
    uint32_t pid;
    char     fname[32];
};

static void print_hex(const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
}

static void plant(int fd, uint32_t id, uint32_t slot, const struct hide_rule *r)
{
    printf("TRUTH map=hide_rules id=%u key=", id);
    print_hex(&slot, sizeof(slot));
    printf(" value=");
    print_hex(r, sizeof(*r));
    printf("\n");
    if (bpf_map_update_elem(fd, &slot, r, BPF_ANY) != 0)
        perror("bpf_map_update_elem");
}

int main(void)
{
    struct bpf_object *obj = bpf_object__open_file("hide.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open_file failed\n"); return 1; }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "hide_rules");
    if (!map) { fprintf(stderr, "map not found\n"); return 1; }
    int fd = bpf_map__fd(map);

    struct bpf_map_info info;
    uint32_t len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) { perror("get_info"); return 1; }
    uint32_t id = info.id;

    // The hide-list. memset first so fname padding is deterministic zeros.
    struct hide_rule r;

    memset(&r, 0, sizeof(r));
    r.pid = 1337; strncpy(r.fname, "backdoor.sh", sizeof(r.fname) - 1);
    plant(fd, id, 0, &r);

    memset(&r, 0, sizeof(r));
    r.pid = 6666; strncpy(r.fname, "rootkit.ko", sizeof(r.fname) - 1);
    plant(fd, id, 1, &r);

    // Attach the program so it is a realistic loaded+attached rootkit component.
    // If attach fails (kernel/permissions), carry on — the map still lives.
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "hide_dents");
    struct bpf_link *link = prog ? bpf_program__attach(prog) : NULL;
    if (!link)
        fprintf(stderr, "attach failed or skipped (map is still live)\n");

    printf("PLANTED-OK\n");
    fflush(stdout);

    pause();   // hold the object (and its map) alive until Ctrl+C

    if (link) bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
