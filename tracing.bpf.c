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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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
    event->user_id = bpf_htonl((u32) uid_gid);
    event->group_id = bpf_htonl(uid_gid >> 32);

    event->process_id = bpf_htonl(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));
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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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
	event->user_id = bpf_htonl((u32) uid_gid);
    event->group_id = bpf_htonl(uid_gid >> 32);

    event->process_id = bpf_htonl(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));
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

	event->source_port = bpf_htons(sk->__sk_common.skc_num);
	event->destination_port = sk->__sk_common.skc_dport;

    event->address_family = bpf_htons(sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&event->transport_protocol, sizeof(event->transport_protocol), &sk->sk_protocol);

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

    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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

    event->source_port = bpf_htons(ctx->sport);
    event->destination_port = bpf_htons(ctx->dport);
    event->address_family = bpf_htons(ctx->family);
    event->old_state = bpf_htons((__u16)ctx->oldstate);
    event->new_state = bpf_htons((__u16)ctx->newstate);

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
};
struct destroy_connection_event *unused4 __attribute__((unused));

SEC("fentry/nf_ct_helper_destroy")
int BPF_PROG(nf_ct_helper_destroy, struct nf_conn *ct) {
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

    struct nf_conntrack_tuple *tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

    if (tuple->dst.protonum == 6) {
        struct ip_ct_tcp *tcp = &ct->proto.tcp;
        if (tcp->state == TCP_CONNTRACK_CLOSE || tcp->state == TCP_CONNTRACK_TIME_WAIT) {
            return 0;
        }
    } else if (tuple->dst.protonum == 17) {
        if (ct->status & (1 << IPS_SEEN_REPLY_BIT)) {
            return 0;
        }
    } else {
        return 0;
    }

    struct destroy_connection_event *event;
    event = bpf_ringbuf_reserve(&destroy_connection_events, sizeof(struct destroy_connection_event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    event->address_family = bpf_htons(tuple->src.l3num);

    if (tuple->src.l3num == AF_INET) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &tuple->src.u3.ip);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &tuple->dst.u3.ip);
    } else if (tuple->src.l3num == AF_INET6) {
        bpf_probe_read_kernel(&event->source_address, sizeof(event->source_address), &tuple->src.u3.ip6);
        bpf_probe_read_kernel(&event->destination_address, sizeof(event->destination_address), &tuple->dst.u3.ip6);
    }

    event->transport_protocol = tuple->dst.protonum;

    if (tuple->dst.protonum == 6) {
        event->source_port = tuple->src.u.tcp.port;
        event->destination_port = tuple->dst.u.tcp.port;

        struct ip_ct_tcp *tcp = &ct->proto.tcp;
        event->tcp_state = tcp->state;
        event->tcp_last_direction = tcp->last_dir;
    } else if (tuple->dst.protonum == 17) {
        event->source_port = tuple->src.u.udp.port;
        event->destination_port = tuple->dst.u.udp.port;
    }

    event->conntrack_status_mask = bpf_htonl(ct->status);
    event->timeout = bpf_htonl(ct->timeout);

    struct nf_ct_ext ext;
    bpf_probe_read_kernel(&ext, sizeof(ext), (void*) ct->ext);

    struct nf_conn_tstamp ct_ts;
    bpf_probe_read_kernel(&ct_ts, sizeof(ct_ts), (void*) ct->ext + ext.offset[NF_CT_EXT_TSTAMP]);

    event->start = bpf_cpu_to_be64(ct_ts.start);
    event->stop = bpf_cpu_to_be64(ct_ts.stop);

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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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

    event->source_port = bpf_htons(ctx->sport);
    event->destination_port = bpf_htons(ctx->dport);
    event->address_family = bpf_htons(ctx->family);
    event->state = bpf_htons((__u16)ctx->state);

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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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

    event->source_port = bpf_htons(ctx->sport);
    event->destination_port = bpf_htons(ctx->dport);
    event->address_family = bpf_htons(ctx->family);

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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

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
    event->reason = bpf_htons(reason);
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
        event->address_family = bpf_htons(AF_INET);
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
        event->address_family = bpf_htons(AF_INET6);
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
                event->source_port = tcph.source;
                event->destination_port = tcph.dest;
            }
        } else if (transport_protocol == IPPROTO_UDP) {
            struct udphdr udph;
            if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header) == 0) {
                event->source_port = udph.source;
                event->destination_port = udph.dest;
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
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

    struct file_open_event *event;
    event = bpf_ringbuf_reserve(&file_open_events, sizeof(*event), 0);
    if (!event)
        return 1;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    u64 uid_gid = bpf_get_current_uid_gid();
    event->user_id = bpf_htonl((u32) uid_gid);
    event->group_id = bpf_htonl(uid_gid >> 32);

    event->process_id = bpf_htonl(bpf_get_current_pid_tgid() >> 32);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));

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
