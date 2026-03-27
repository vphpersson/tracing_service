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
//		LOG0("could not reserve events ringbuf memory");
		return 1;
	}

    // Zero out the event for safety. If we don't do this, we risk sending random kernel memory back to userspace.
    s32 ret = bpf_probe_read_kernel(event, sizeof(*event), &zero_execve_event);
    if (ret) {
//        LOG1("zero out event: %d", ret);
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

    // Write the filename in addition to argv[0] because the filename contains the full path to the file which could
    // be more useful in some situations.
    ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), execve_ctx->filename);
    if (ret < 0) {
//        LOG1("could not read filename into event struct: %d", ret);
        bpf_ringbuf_discard(event, 0);
        return 1;
    }

    for (u32 i = 0; i < ARGLEN; i++) {
        if (!(&execve_ctx->argv[i])) {
            goto out;
        }

        const u8 *argp = NULL;
        ret = bpf_probe_read_user(&argp, sizeof(argp), &execve_ctx->argv[i]);
        if (ret || !argp) {
            goto out;
        }

        ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
        if (ret < 0) {
//            LOG2("read argv %u: %d", i, ret);
            goto out;
        }

        event->argc++;
    }

    // This won't get hit if we `goto out` in the loop above. This is to signify
    // to userspace that we couldn't copy all of the arguments because it
    // exceeded ARGLEN.
    event->argc++;

out:
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
};
struct connect_event *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

    struct connect_event *event;
    event = bpf_ringbuf_reserve(&connect_events, sizeof(struct connect_event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;

    u64 uid_gid = bpf_get_current_uid_gid();
	event->user_id = bpf_htonl((u32) uid_gid);
    event->group_id = bpf_htonl(uid_gid >> 32);

    event->process_id = bpf_htonl(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->parent_process_id = bpf_htonl(BPF_CORE_READ(task, real_parent, pid));
	bpf_get_current_comm(&event->process_title, TASK_COMM_LEN);

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

// TCP state

//struct {
//	__uint(type, BPF_MAP_TYPE_RINGBUF);
//	__uint(max_entries, 1 << 24);
//} tcp_state_events SEC(".maps");
//
//struct tcp_state_event {
////	unsigned __int128 saddr;
////	unsigned __int128 daddr;
//    __u32 saddr_v4;
//    __u8 saddr_v6[16];
//    __u32 daddr_v4;
//    __u8 daddr_v6[16];
//
//	u16 sport;
//	u16 dport;
//	u16 af;
//
//    u64 ts_ns;
//
//	int old_state;
//	int new_state;
//};
//struct tcp_state_event *unused3 __attribute__((unused));

//SEC("tracepoint/sock/inet_sock_set_state")
//int sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
//    u64 timestamp = bpf_cpu_to_be64(bpf_ktime_get_ns());
//
//    if (ctx->protocol != IPPROTO_TCP)
//        return 0;
//
//    struct tcp_state_event *event;
//    event = bpf_ringbuf_reserve(&tcp_state_events, sizeof(struct tcp_state_event), 0);
//    if (!event) {
//        return 0;
//    }
//
//    event->ts_ns = timestamp;
//
//    struct sock *sk = (struct sock *)ctx->skaddr;
//    event->sport = bpf_htons(ctx->sport);
//    event->dport = bpf_htons(ctx->dport);
//    event->af = bpf_htons(ctx->family);
//
//    event->old_state = bpf_htonl(ctx->oldstate);
//    event->new_state = bpf_htonl(ctx->newstate);
//
//    if (ctx->family == AF_INET) {
//        bpf_probe_read_kernel(&event->saddr_v4, sizeof(event->saddr_v4), &sk->__sk_common.skc_rcv_saddr);
//        bpf_probe_read_kernel(&event->daddr_v4, sizeof(event->daddr_v4), &sk->__sk_common.skc_daddr);
//    } else {
////        BPF_CORE_READ_INTO(event->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
////        BPF_CORE_READ_INTO(event->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
//    }
//
////    if (family == AF_INET) {
////        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
////        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
////    } else { /* family == AF_INET6 */
////        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
////        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
////    }
//
//	bpf_ringbuf_submit(event, 0);
//
//    return 0;
//}

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

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
    u64 timestamp_ns = bpf_cpu_to_be64(bpf_ktime_get_boot_ns());

    __u16 reason = ctx->reason;

    int reason_not_specified = bpf_core_enum_value(enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);
    if (reason_not_specified == 0)
        return 1;

    if (reason <= reason_not_specified)
        return 1;

    struct packet_drop_event *event;
    event = bpf_ringbuf_reserve(&packet_drop_events, sizeof(struct packet_drop_event), 0);
    if (!event) {
        return 1;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = timestamp_ns;
    event->reason = bpf_ntohs(reason);
    event->location = (u64)ctx->location;

    struct sk_buff *skb;
    bpf_core_read(&skb, sizeof(skb), &ctx->skbaddr);

	struct sock *sk = BPF_CORE_READ(skb, sk);

    if (sk) {
        event->address_family = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_family));

        if (event->address_family == AF_INET) {
            event->source_address = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            event->destination_address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else if (event->address_family == AF_INET6) {
            BPF_CORE_READ_INTO(&event->source_address, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&event->destination_address, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }

        event->source_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
        event->destination_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

        event->transport_protocol = BPF_CORE_READ(sk, sk_protocol);
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
