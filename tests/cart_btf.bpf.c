// cart_btf.bpf.c — a BTF-carrying hash map for testing Cartographer's decoder.
//
// Unlike plant_maps.c (which creates maps with raw bpf() syscalls and so has
// NO type info), this map is defined with named types. Compiled with clang -g,
// the object carries BTF; libbpf passes that to the kernel at load, which then
// records btf_key_type_id / btf_value_type_id on the map — the fields map.py
// already reads. That is what turns a hex dump into decoded fields.
//
// Build:
//   clang -O2 -g -target bpf -c cart_btf.bpf.c -o cart_btf.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// The value type we want the decoder to reconstruct. Three different shapes to
// exercise the decoder: two integers of different widths, and a char array.
struct cart_evt {
    __u32 pid;        // offset 0
    char  comm[16];   // offset 4
    __u64 count;      // offset 24 (compiler pads 20..24 for 8-byte alignment)
};

// The map, defined the BTF-aware way. __type(key,...) / __type(value,...) are
// what cause the key/value type ids to be recorded on the map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct cart_evt);
} cart_btf SEC(".maps");

// A no-op program. It never has to run or be attached for the BTF test — its
// job is just to make this a well-formed loadable object. Later, for the
// anti-forensic demo, this is where a real hiding program would go.
SEC("tracepoint/syscalls/sys_enter_getpid")
int noop(void *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
