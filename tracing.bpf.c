//go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct nf_conn_tstamp {
	uint64_t start;
	uint64_t stop;
};

struct nf_conn_counter {
	s64 packets;
	s64 bytes;
};

struct nf_conn_acct {
	struct nf_conn_counter counter[2];
};

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10
#define EXE_NAME_LEN 256
#define CMDLINE_LEN 256

char __license[] SEC("license") = "Dual MIT/GPL";

// execve tracing

#define ARGLEN 32
#define ARGSIZE 1024

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} execve_events SEC(".maps");

struct execve_event {
    u64 timestamp_ns;

    u32 user_id;
    u32 group_id;

    u32 process_id;
    u32 parent_process_id;
    u8 process_title[TASK_COMM_LEN];

	u8  filename[ARGSIZE];
	u8  argv[ARGLEN][ARGSIZE];
	// set to ARGLEN + 1 if there were more than ARGLEN arguments
	u32 argc;

    u8 parent_executable_name[EXE_NAME_LEN];
    u8 parent_command_line[CMDLINE_LEN];
};
struct execve_event *unused2 __attribute__((unused));

static struct execve_event zero_execve_event SEC(".rodata") = {
    .timestamp_ns = 0,

    .user_id = 0,
    .group_id = 0,

    .process_id = 0,
    .parent_process_id = 0,
    .process_title = {0},

    .filename = {0},
    .argv = {},
    .argc = 0,

    .parent_executable_name = {0},
    .parent_command_line = {0},
};

struct exec_info {
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	s32 common_pid;

	s32 syscall_nr;
	u32 pad;
	const u8 *filename;
	const u8 *const *argv;
	const u8 *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
s32 enter_execve(struct exec_info *execve_ctx) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct execve_event *event;
    event = bpf_ringbuf_reserve(&execve_events, sizeof(struct execve_event), 0);
    if (!event) {
        return 1;
    }

    s32 ret = bpf_probe_read_kernel(event, sizeof(*event), &zero_execve_event);
    if (ret) {
        bpf_ringbuf_discard(event, 0);
        return 1;
    }

    event->timestamp_ns = timestamp_ns;

    u64 uid_gid = bpf_get_current_uid_gid();
    event->user_id = (u32) uid_gid;
    event->group_id = uid_gid >> 32;

    event->process_id = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = BPF_CORE_READ(task, real_parent, pid);
    bpf_get_current_comm(&event->process_title, TASK_COMM_LEN);

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct mm_struct *parent_mm = BPF_CORE_READ(parent, mm);
    if (parent_mm) {
        const u8 *parent_exe = BPF_CORE_READ(parent_mm, exe_file, f_path.dentry, d_name.name);
        bpf_probe_read_kernel_str(&event->parent_executable_name, sizeof(event->parent_executable_name), parent_exe);

        unsigned long parent_arg_start = BPF_CORE_READ(parent_mm, arg_start);
        unsigned long parent_arg_end = BPF_CORE_READ(parent_mm, arg_end);
        unsigned long parent_arg_len = parent_arg_end - parent_arg_start;
        if (parent_arg_len > sizeof(event->parent_command_line)) {
            parent_arg_len = sizeof(event->parent_command_line);
        }
        parent_arg_len &= (sizeof(event->parent_command_line) - 1);
        bpf_probe_read_user(&event->parent_command_line, parent_arg_len, (void *)parent_arg_start);
    }

    // Write the filename in addition to argv[0] because the filename contains the full path to the file which could
    // be more useful in some situations.
    ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), execve_ctx->filename);
    if (ret < 0) {
        bpf_ringbuf_discard(event, 0);
        return 1;
    }

    for (u32 i = 0; i < ARGLEN; i++) {
        if (!(&execve_ctx->argv[i])) {
            goto done;
        }

        const u8 *argp = NULL;
        ret = bpf_probe_read_user(&argp, sizeof(argp), &execve_ctx->argv[i]);
        if (ret || !argp) {
            goto done;
        }

        ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
        if (ret < 0) {
            goto done;
        }

        event->argc++;
    }

    // This won't get hit if we `goto done` in the loop above. This is to signify
    // to userspace that we couldn't copy all of the arguments because it
    // exceeded ARGLEN.
    event->argc++;

done:
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// connect tracing


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

// Per-socket connect start info, populated in tcp_connect and consumed in
// tcp_rcv_state_process to compute three-way-handshake latency. Keyed by the
// address of the struct sock (cast to u64). LRU so stale entries from failed
// connects are automatically evicted.
struct connect_start_info {
    u64 timestamp_ns;
    u32 user_id;
    u32 group_id;
    u32 process_id;
    u32 parent_process_id;
    u8 process_title[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct connect_start_info);
    __uint(max_entries, 10240);
} connect_start_infos SEC(".maps");

struct connect_event {
    u64 timestamp_ns;

    u32 user_id;
    u32 group_id;

    u32 process_id;
    u32 parent_process_id;
    u8 process_title[TASK_COMM_LEN];

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    u8 transport_protocol;

    u8 executable_name[EXE_NAME_LEN];
    u8 command_line[CMDLINE_LEN];

    u8 parent_executable_name[EXE_NAME_LEN];
    u8 parent_command_line[CMDLINE_LEN];
};
struct connect_event *unused __attribute__((unused));

static struct connect_event zero_connect_event SEC(".rodata") = {};

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct connect_event *event;
    event = bpf_ringbuf_reserve(&connect_events, sizeof(struct connect_event), 0);
    if (!event) {
        return 0;
    }

    s32 zero_ret = bpf_probe_read_kernel(event, sizeof(*event), &zero_connect_event);
    if (zero_ret) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->timestamp_ns = timestamp_ns;

    u64 uid_gid = bpf_get_current_uid_gid();
	event->user_id = (u32) uid_gid;
    event->group_id = uid_gid >> 32;

    event->process_id = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = BPF_CORE_READ(task, real_parent, pid);
	bpf_get_current_comm(&event->process_title, TASK_COMM_LEN);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        const u8 *exe_name = BPF_CORE_READ(mm, exe_file, f_path.dentry, d_name.name);
        bpf_probe_read_kernel_str(&event->executable_name, sizeof(event->executable_name), exe_name);

        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long arg_len = arg_end - arg_start;
        if (arg_len > sizeof(event->command_line)) {
            arg_len = sizeof(event->command_line);
        }
        arg_len &= (sizeof(event->command_line) - 1);
        bpf_probe_read_user(&event->command_line, arg_len, (void *)arg_start);
    }

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct mm_struct *parent_mm = BPF_CORE_READ(parent, mm);
    if (parent_mm) {
        const u8 *parent_exe = BPF_CORE_READ(parent_mm, exe_file, f_path.dentry, d_name.name);
        bpf_probe_read_kernel_str(&event->parent_executable_name, sizeof(event->parent_executable_name), parent_exe);

        unsigned long parent_arg_start = BPF_CORE_READ(parent_mm, arg_start);
        unsigned long parent_arg_end = BPF_CORE_READ(parent_mm, arg_end);
        unsigned long parent_arg_len = parent_arg_end - parent_arg_start;
        if (parent_arg_len > sizeof(event->parent_command_line)) {
            parent_arg_len = sizeof(event->parent_command_line);
        }
        parent_arg_len &= (sizeof(event->parent_command_line) - 1);
        bpf_probe_read_user(&event->parent_command_line, parent_arg_len, (void *)parent_arg_start);
    }

    if (sk->__sk_common.skc_family == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_daddr);
    } else if (sk->__sk_common.skc_family == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

	event->source_port = sk->__sk_common.skc_num;
	event->destination_port = bpf_ntohs(sk->__sk_common.skc_dport);

    event->address_family = sk->__sk_common.skc_family;
    bpf_probe_read_kernel(&event->transport_protocol, sizeof(event->transport_protocol), &sk->sk_protocol);

    // Record connect-start info for latency measurement at tcp_rcv_state_process.
    // Only track TCP sockets; tcp_rcv_state_process is TCP-only but this avoids
    // polluting the map with UDP/other sockets that also traverse tcp_connect
    // would not (tcp_connect itself is TCP-only, so this is effectively a no-op
    // guard but kept for clarity).
    u64 sk_key = (u64)sk;
    struct connect_start_info start_info = {};
    start_info.timestamp_ns = timestamp_ns;
    start_info.user_id = event->user_id;
    start_info.group_id = event->group_id;
    start_info.process_id = event->process_id;
    start_info.parent_process_id = event->parent_process_id;
    __builtin_memcpy(&start_info.process_title, &event->process_title, TASK_COMM_LEN);
    bpf_map_update_elem(&connect_start_infos, &sk_key, &start_info, BPF_ANY);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// TCP connect latency
//
// tcp_finish_connect runs from tcp_rcv_synsent_state_process after a valid
// SYN-ACK has been accepted, immediately before the socket is promoted to
// TCP_ESTABLISHED. It only runs on successful handshake completion: SYN
// timeouts never reach it (timer path), nor do refused connects (RST handling
// bypasses tcp_finish_connect). Failed connects still show up separately via
// the SYN_SENT -> CLOSE transition in the inet_sock_set_state handler above.
// The LRU hash evicts stale start-info entries for any connect that doesn't
// finish.

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} connect_latency_events SEC(".maps");

struct connect_latency_event {
    u64 timestamp_ns;
    u64 duration_ns;

    u32 user_id;
    u32 group_id;

    u32 process_id;
    u32 parent_process_id;
    u8 process_title[TASK_COMM_LEN];

    unsigned __int128 source_address;
    unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
};
struct connect_latency_event *unused_connect_latency_event __attribute__((unused));

SEC("fentry/tcp_finish_connect")
int BPF_PROG(tcp_finish_connect, struct sock *sk) {
    if (!sk)
        return 0;

    u64 sk_key = (u64)sk;
    struct connect_start_info *info = bpf_map_lookup_elem(&connect_start_infos, &sk_key);
    if (!info)
        return 0;

    u64 now = bpf_ktime_get_boot_ns();

    struct connect_latency_event *event;
    event = bpf_ringbuf_reserve(&connect_latency_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&connect_start_infos, &sk_key);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = now;
    event->duration_ns = now - info->timestamp_ns;
    event->user_id = info->user_id;
    event->group_id = info->group_id;
    event->process_id = info->process_id;
    event->parent_process_id = info->parent_process_id;
    __builtin_memcpy(&event->process_title, &info->process_title, TASK_COMM_LEN);

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->address_family = family;

    if (family == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&connect_start_infos, &sk_key);

    return 0;
}

// TCP error: connection terminated with an error (timeout / tcp_abort / ...).
//
// tcp_done_with_error is the kernel helper (introduced mid-6.x, replacing the
// older static tcp_write_err) that is called from every TCP error-termination
// path: retransmission timeout, user-triggered abort, etc. It sets sk->sk_err
// and calls tcp_done. err is typically ETIMEDOUT for RTO expiry and
// EPIPE/ECONNRESET for others. Fires in softirq or process context depending
// on the path, so process-context helpers can't be trusted.

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_error_events SEC(".maps");

struct tcp_error_event {
    u64 timestamp_ns;

    unsigned __int128 source_address;
    unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u16 state;
    __s32 err;
};
struct tcp_error_event *unused_tcp_error_event __attribute__((unused));

SEC("fentry/tcp_done_with_error")
int BPF_PROG(tcp_done_with_error, struct sock *sk, int err) {
    if (!sk)
        return 0;

    struct tcp_error_event *event;
    event = bpf_ringbuf_reserve(&tcp_error_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->err = err;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->address_family = family;
    event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

    if (family == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// TCP RST received. tcp_reset runs when a RST is delivered to an existing
// socket. sk_err is set to ECONNRESET or ECONNREFUSED depending on state
// (ECONNREFUSED during handshake, ECONNRESET afterwards). We capture state at
// fentry so the caller can tell which of those happened.

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_reset_events SEC(".maps");

struct tcp_reset_event {
    u64 timestamp_ns;

    unsigned __int128 source_address;
    unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u16 state;
};
struct tcp_reset_event *unused_tcp_reset_event __attribute__((unused));

SEC("fentry/tcp_reset")
int BPF_PROG(tcp_reset, struct sock *sk, struct sk_buff *skb) {
    if (!sk)
        return 0;

    struct tcp_reset_event *event;
    event = bpf_ringbuf_reserve(&tcp_reset_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_boot_ns();

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->address_family = family;
    event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

    if (family == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ICMP errors delivered to TCP. tcp_v{4,6}_err are the entry points used by
// the ICMP layer to notify TCP of destination/host/port unreachable, fragmentation
// needed, etc. The skb passed in is the ICMP packet with skb->data already
// advanced to the encapsulated (inner) IP header of the packet that triggered
// the ICMP. We parse that inner packet to extract the 5-tuple of the affected
// flow. The socket hasn't been looked up yet at fentry, which is fine — we
// care about which flow errored, not which struct sock holds it.

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_icmp_error_events SEC(".maps");

struct tcp_icmp_error_event {
    u64 timestamp_ns;

    unsigned __int128 source_address;
    unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u8 icmp_type;
    __u8 icmp_code;
    __u32 info;
};
struct tcp_icmp_error_event *unused_tcp_icmp_error_event __attribute__((unused));

SEC("fentry/tcp_v4_err")
int BPF_PROG(tcp_v4_err, struct sk_buff *skb, u32 info) {
    if (!skb)
        return 0;

    struct tcp_icmp_error_event *event;
    event = bpf_ringbuf_reserve(&tcp_icmp_error_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->address_family = AF_INET;
    event->info = info;

    unsigned char *data = BPF_CORE_READ(skb, data);

    // Inner IPv4 header at skb->data (the packet that triggered the ICMP).
    struct iphdr iph;
    if (data && bpf_probe_read_kernel(&iph, sizeof(iph), data) == 0) {
        __builtin_memcpy(&event->source_address, &iph.saddr, sizeof(iph.saddr));
        __builtin_memcpy(&event->destination_address, &iph.daddr, sizeof(iph.daddr));

        u32 ihl = (u32)iph.ihl * 4;
        if (ihl >= sizeof(struct iphdr) && ihl <= 60) {
            struct tcphdr tcph;
            if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + ihl) == 0) {
                event->source_port = bpf_ntohs(tcph.source);
                event->destination_port = bpf_ntohs(tcph.dest);
            }
        }
    }

    // Outer ICMP header remains accessible via skb->head + skb->transport_header.
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    if (head && transport_header != (__u16)~0U) {
        struct icmphdr icmph;
        if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header) == 0) {
            event->icmp_type = icmph.type;
            event->icmp_code = icmph.code;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("fentry/tcp_v6_err")
int BPF_PROG(tcp_v6_err, struct sk_buff *skb, void *opt, u8 type, u8 code, int offset, __be32 info) {
    if (!skb)
        return 0;

    struct tcp_icmp_error_event *event;
    event = bpf_ringbuf_reserve(&tcp_icmp_error_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->address_family = AF_INET6;
    event->icmp_type = type;
    event->icmp_code = code;
    event->info = bpf_ntohl(info);

    unsigned char *data = BPF_CORE_READ(skb, data);

    struct ipv6hdr ip6h;
    if (data && bpf_probe_read_kernel(&ip6h, sizeof(ip6h), data) == 0) {
        __builtin_memcpy(&event->source_address, &ip6h.saddr, sizeof(ip6h.saddr));
        __builtin_memcpy(&event->destination_address, &ip6h.daddr, sizeof(ip6h.daddr));
    }

    // offset is the kernel-computed distance from skb->data to the inner TCP
    // header (past any IPv6 extension headers). Clamp to a sane range so the
    // verifier can prove the read.
    if (data && offset >= (int)sizeof(struct ipv6hdr) && offset < 256) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + offset) == 0) {
            event->source_port = bpf_ntohs(tcph.source);
            event->destination_port = bpf_ntohs(tcph.dest);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// TCP set state

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tcp_set_state_events SEC(".maps");

struct tcp_set_state_event {
    u64 timestamp_ns;

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u16 old_state;
    __u16 new_state;
};
struct tcp_set_state_event *unused_tcp_set_state_event __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    // Only emit transitions that signal an error condition. The normal close
    // progression (ESTABLISHED -> FIN_WAIT1 -> FIN_WAIT2 -> CLOSE for active
    // close, ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSE for passive close,
    // anything -> TIME_WAIT, etc.) is filtered out.
    //
    // - SYN_SENT  -> CLOSE: connect() failed (timeout / refused / RST during handshake)
    // - SYN_RECV  -> CLOSE: server-side handshake aborted
    // - ESTABLISHED -> CLOSE: abortive close, typically RST received mid-connection
    if (ctx->newstate != TCP_CLOSE)
        return 0;
    if (ctx->oldstate != TCP_SYN_SENT &&
        ctx->oldstate != TCP_SYN_RECV &&
        ctx->oldstate != TCP_ESTABLISHED)
        return 0;

    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct tcp_set_state_event *event;
    event = bpf_ringbuf_reserve(&tcp_set_state_events, sizeof(struct tcp_set_state_event), 0);
    if (!event) {
        return 1;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    if (ctx->family == AF_INET) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr);
    } else if (ctx->family == AF_INET6) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr_v6);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr_v6);
    }

    event->source_port = ctx->sport;
    event->destination_port = ctx->dport;
    event->address_family = ctx->family;
    event->old_state = (__u16)ctx->oldstate;
    event->new_state = (__u16)ctx->newstate;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} destroy_connection_events SEC(".maps");

struct destroy_connection_event {
    u64 timestamp_ns;

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    u8 transport_protocol;

    u32 conntrack_status_mask;
    u32 timeout;
    u64 start;
    u64 stop;
    u8 tcp_state;
    u8 tcp_last_direction;

    u64 source_packets;
    u64 source_bytes;
    u64 destination_packets;
    u64 destination_bytes;
};
struct destroy_connection_event *unused4 __attribute__((unused));

SEC("fentry/nf_ct_helper_destroy")
int BPF_PROG(nf_ct_helper_destroy, struct nf_conn *ct) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct nf_conntrack_tuple *tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

    struct destroy_connection_event *event;
    event = bpf_ringbuf_reserve(&destroy_connection_events, sizeof(struct destroy_connection_event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    event->address_family = tuple->src.l3num;

    if (tuple->src.l3num == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &tuple->src.u3.ip);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &tuple->dst.u3.ip);
    } else if (tuple->src.l3num == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &tuple->src.u3.ip6);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &tuple->dst.u3.ip6);
    }

    event->transport_protocol = tuple->dst.protonum;

    if (tuple->dst.protonum == 6) {
        event->source_port = bpf_ntohs(tuple->src.u.tcp.port);
        event->destination_port = bpf_ntohs(tuple->dst.u.tcp.port);

        struct ip_ct_tcp *tcp = &ct->proto.tcp;
        event->tcp_state = tcp->state;
        event->tcp_last_direction = tcp->last_dir;
    } else if (tuple->dst.protonum == 17) {
        event->source_port = bpf_ntohs(tuple->src.u.udp.port);
        event->destination_port = bpf_ntohs(tuple->dst.u.udp.port);
    }

    event->conntrack_status_mask = ct->status;
    event->timeout = ct->timeout;

    struct nf_ct_ext ext;
    bpf_probe_read_kernel(&ext, sizeof(ext), (void*) ct->ext);

    struct nf_conn_tstamp ct_ts;
    bpf_probe_read_kernel(&ct_ts, sizeof(ct_ts), (void*) ct->ext + ext.offset[NF_CT_EXT_TSTAMP]);

    event->start = ct_ts.start;
    event->stop = ct_ts.stop;

    if (ext.offset[NF_CT_EXT_ACCT]) {
        struct nf_conn_acct ct_acct;
        bpf_probe_read_kernel(&ct_acct, sizeof(ct_acct), (void*) ct->ext + ext.offset[NF_CT_EXT_ACCT]);

        event->source_packets = ct_acct.counter[0].packets;
        event->source_bytes = ct_acct.counter[0].bytes;
        event->destination_packets = ct_acct.counter[1].packets;
        event->destination_bytes = ct_acct.counter[1].bytes;
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// TCP retransmissions

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tcp_retransmission_events SEC(".maps");

struct tcp_retransmit_skb_ctx {
    __u64 _pad0;
    void *skbaddr;
    void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct tcp_retransmission_event {
    u64 timestamp_ns;

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u16 state;
};
struct tcp_retransmission_event *unused5 __attribute__((unused));

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct tcp_retransmit_skb_ctx *ctx) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct tcp_retransmission_event *event;
    event = bpf_ringbuf_reserve(&tcp_retransmission_events, sizeof(struct tcp_retransmission_event), 0);
    if (!event) {
        return 1;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    if (ctx->family == AF_INET) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr);
    } else if (ctx->family == AF_INET6) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr_v6);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr_v6);
    }

    event->source_port = ctx->sport;
    event->destination_port = ctx->dport;
    event->address_family = ctx->family;
    event->state = (__u16)ctx->state;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// TCP retransmission SYN/ACK

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tcp_retransmission_synack_events SEC(".maps");

struct tcp_retransmission_synack_event {
    u64 timestamp_ns;

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
};
struct tcp_retransmission_synack_event *unused6 __attribute__((unused));

SEC("tp/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct tcp_retransmission_synack_event *event;
    event = bpf_ringbuf_reserve(&tcp_retransmission_synack_events, sizeof(struct tcp_retransmission_synack_event), 0);
    if (!event) {
        return 1;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    if (ctx->family == AF_INET) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr);
    } else if (ctx->family == AF_INET6) {
        bpf_probe_read(&event->source_address, sizeof(event->source_address), ctx->saddr_v6);
        bpf_probe_read(&event->destination_address, sizeof(event->destination_address), ctx->daddr_v6);
    }

    event->source_port = ctx->sport;
    event->destination_port = ctx->dport;
    event->address_family = ctx->family;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// Packet drop reason

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} packet_drop_events SEC(".maps");

// Allowlist of skb_drop_reason values that we want to emit events for.
// Populated from userspace at startup using kernel BTF, since the numeric
// enum values are not stable across kernel versions.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u8);
	__uint(max_entries, 256);
} packet_drop_reason_filter SEC(".maps");

struct packet_drop_event {
    u64 timestamp_ns;

    __u16 reason;
    u64 location;

	unsigned __int128 source_address;
	unsigned __int128 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u16 address_family;
    __u8 transport_protocol;
};
struct packet_drop_event *unused7 __attribute__((unused));

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    __u16 reason = ctx->reason;

    __u8 *keep = bpf_map_lookup_elem(&packet_drop_reason_filter, &reason);
    if (!keep)
        return 0;

    struct packet_drop_event *event;
    event = bpf_ringbuf_reserve(&packet_drop_events, sizeof(struct packet_drop_event), 0);
    if (!event) {
        return 1;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;
    event->reason = reason;
    event->location = (u64)ctx->location;

    struct sk_buff *skb;
    bpf_core_read(&skb, sizeof(skb), &ctx->skbaddr);
    if (!skb) {
        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    __u16 eth_protocol = bpf_ntohs(ctx->protocol);

    // skb->protocol can be unset for locally-generated packets dropped
    // before the protocol field is assigned (e.g. IP_OUTNOROUTES). Fall
    // back to sniffing the IP version from the network header's version
    // nibble.
    if (eth_protocol != ETH_P_IP && eth_protocol != ETH_P_IPV6 &&
        network_header != (__u16)~0U) {
        __u8 first_byte = 0;
        if (bpf_probe_read_kernel(&first_byte, 1, head + network_header) == 0) {
            __u8 version = first_byte >> 4;
            if (version == 4)
                eth_protocol = ETH_P_IP;
            else if (version == 6)
                eth_protocol = ETH_P_IPV6;
        }
    }

    __u8 transport_protocol = 0;

    if (eth_protocol == ETH_P_IP) {
        event->address_family = AF_INET;
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) == 0) {
            __builtin_memcpy(&event->source_address, &iph.saddr, sizeof(iph.saddr));
            __builtin_memcpy(&event->destination_address, &iph.daddr, sizeof(iph.daddr));
            transport_protocol = iph.protocol;
            // Compute transport_header from the IP header when not set.
            if (transport_header == (__u16)~0U)
                transport_header = network_header + (iph.ihl * 4);
        }
    } else if (eth_protocol == ETH_P_IPV6) {
        event->address_family = AF_INET6;
        struct ipv6hdr ip6h;
        if (bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + network_header) == 0) {
            __builtin_memcpy(&event->source_address, &ip6h.saddr, sizeof(ip6h.saddr));
            __builtin_memcpy(&event->destination_address, &ip6h.daddr, sizeof(ip6h.daddr));
            transport_protocol = ip6h.nexthdr;
            // IPv6 fixed header is always 40 bytes.
            if (transport_header == (__u16)~0U)
                transport_header = network_header + 40;
        }
    }

    event->transport_protocol = transport_protocol;

    if (transport_header != (__u16)~0U) {
        if (transport_protocol == IPPROTO_TCP) {
            struct tcphdr tcph;
            if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header) == 0) {
                event->source_port = bpf_ntohs(tcph.source);
                event->destination_port = bpf_ntohs(tcph.dest);
            }
        } else if (transport_protocol == IPPROTO_UDP) {
            struct udphdr udph;
            if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header) == 0) {
                event->source_port = bpf_ntohs(udph.source);
                event->destination_port = bpf_ntohs(udph.dest);
            }
        }
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// File open

#define FILENAME_LEN 256

struct file_open_event {
    u64 timestamp_ns;
    u32 user_id;
    u32 group_id;
    u32 process_id;
    u32 parent_process_id;
    u8 process_title[TASK_COMM_LEN];
    u8 filename[FILENAME_LEN];
    int flags;
    int mode;
};
struct file_open_event *unused_file_open_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_open_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter* ctx) {
    u64 timestamp_ns = bpf_ktime_get_boot_ns();

    struct file_open_event *event;
    event = bpf_ringbuf_reserve(&file_open_events, sizeof(*event), 0);
    if (!event)
        return 1;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    u64 uid_gid = bpf_get_current_uid_gid();
    event->user_id = (u32) uid_gid;
    event->group_id = uid_gid >> 32;

    event->process_id = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = BPF_CORE_READ(task, real_parent, pid);

    bpf_get_current_comm(&event->process_title, TASK_COMM_LEN);

    const char *filename = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    int mode = (int)ctx->args[3];
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    event->flags = flags;
    event->mode = mode;

    bpf_ringbuf_submit(event, 0);

    return 0;
}
