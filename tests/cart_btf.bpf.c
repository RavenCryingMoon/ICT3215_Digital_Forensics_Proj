// cart_btf.bpf.c — a BTF-carrying hash map for testing Cartographer's decoder.
//
// The map is defined with named types and compiled with clang -g, so the
// object carries BTF; libbpf passes that to the kernel at load, which records
// the key/value type ids on the map. The value is a struct that now also
// carries an enum field, to exercise enum decoding.
//
// Build:
//   clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c cart_btf.bpf.c -o cart_btf.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// A small enum, so the decoder can turn a stored number back into its name.
enum evt_kind {
    EVT_NONE  = 0,
    EVT_LOGIN = 1,
    EVT_EXEC  = 2,
    EVT_HIDE  = 3,
};

// The value type the decoder reconstructs: two integers, a char array, and an
// enum. The enum is 4 bytes (an int), so the struct is 40 bytes with padding.
struct cart_evt {
    __u32 pid;            // offset 0
    char  comm[16];       // offset 4
    __u64 count;          // offset 24 (20..24 is padding)
    enum  evt_kind kind;  // offset 32 (36..40 is padding)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct cart_evt);
} cart_btf SEC(".maps");

// A no-op program. It never has to run or be attached for the BTF test — its
// job is just to make this a well-formed loadable object.
SEC("tracepoint/syscalls/sys_enter_getpid")
int noop(void *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
