// hide.bpf.c — a realistic eBPF "rootkit-style" component for Cartographer.
//
// It keeps its hide-list (which PID and which filename to hide) in a BTF-typed
// hash map. A real rootkit following the TripleCross technique would read this
// list inside a getdents64 hook and filter matching directory entries out of
// what userspace sees. This version wires up the same structure — the program
// is attached to getdents64 and looks the list up — but does not implement the
// full filtering; that is a separate stretch goal. The point for the project is
// that the hide-list lives in a hash map, which Cartographer recovers and
// decodes from a memory image even though a live `bpftool` view could be
// subverted by the rootkit.
//
// Build:
//   clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c hide.bpf.c -o hide.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// One hide rule: a process to hide and a filename to hide.
struct hide_rule {
    __u32 pid;          // offset 0
    char  fname[32];    // offset 4  (struct is 36 bytes, no padding)
};

// The hide-list, keyed by rule slot. BTF-typed so Cartographer can decode it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct hide_rule);
} hide_rules SEC(".maps");

// Attached to getdents64 entry. It consults the hide-list on every call — this
// makes the program->map reference real (so bpf_listprogs links them) — and
// then returns. A full rootkit would filter the returned dirents here.
SEC("tracepoint/syscalls/sys_enter_getdents64")
int hide_dents(void *ctx)
{
    __u32 slot = 0;
    struct hide_rule *rule = bpf_map_lookup_elem(&hide_rules, &slot);
    if (rule) {
        // a real rootkit would hide entries matching rule->pid / rule->fname here
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
