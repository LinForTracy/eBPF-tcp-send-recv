from bcc import BPF
import time

# eBPF 程序代码
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

//定义采集的指标存储结构key
struct key_t {
    u32 pid;
    u16 type;
};

//定义采集的指标存储结构value
BPF_HASH(net_map, struct key_t, u64);

//获取tcp_sendms函数的返回值 所以监听kretprobe类型事件
int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (FILTER_PID) return 0;
    int size = PT_REGS_RC(ctx);

    if (size <= 0)
        return 0;

    struct key_t key = {};
    key.pid = pid;
    key.type = 1;
    u64 zero = 0;
    u64 *val = net_map.lookup_or_init(&key, &zero);
     
    zero = *val + size;

    net_map.update(&key, &zero);
    return 0;
}

//获取数据包，hook对函数入参进行处理
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (FILTER_PID) return 0;

    if (copied <= 0) return 0;

    struct key_t key = {};
    key.pid = pid;
    key.type = 2;
    u64 zero = 0;
    u64 *val = net_map.lookup_or_init(&key, &zero);
    zero = *val + copied;

    net_map.update(&key, &zero);
    return 0;
}
"""


# 用于ebpf代码程序中的pid替换
def str_replace(code, pid):
    filter_pid = "pid != {}".format(pid)
    return code.replace("FILTER_PID", filter_pid)


# 主程序
if __name__ == "__main__":
    import sys
    from datetime import datetime

    if len(sys.argv) < 2:
        print("Usage: {} <pid>".format(sys.argv[0]))
        sys.exit(1)

    pid = int(sys.argv[1])
    print("start, pid = {}".format(pid))

    code = str_replace(bpf_source, pid)
    print("str_replace remove ok")

    # 初始化BPF
    b = BPF(text=code)
    print("BPF initialization success")

    # 探测tcp_sendmsg
    b.attach_kretprobe(event="tcp_sendmsg", fn_name="kretprobe__tcp_sendmsg")
    print("Attached kretprobe for tcp_sendmsg")

    # 探测tcp_cleanup_rbuf
    b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="kprobe__tcp_cleanup_rbuf")
    print("Attached kprobe for tcp_cleanup_rbuf")

    # 主循环读取并打印每秒的值
    while True:
        try:
            time.sleep(1)
            net_map = b.get_table("net_map")
            for key, value in net_map.items():
                pid = key.pid
                type = "sendMsg" if key.type == 1 else "recvMsg"

                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")

                print("pid: {} time: {} type: {} size: {}".format(pid, formatted_time, type, value.value))
        except KeyboardInterrupt:
            print("\n主动退出.")
            break

    sys.exit(0)
