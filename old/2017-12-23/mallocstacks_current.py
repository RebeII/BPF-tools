#!/usr/bin/python
#
# mallocstacks    Trace libc malloc() and show stacks and total bytes.
#                 For Linux, uses BCC, eBPF.
#
# USAGE: mallocstacks [-h] [-p PID | -t TID] [-f]
#                     [--stack-storage-size STACK_STORAGE_SIZE]
#                     [-m MIN_BLOCK_TIME] [-M MAX_BLOCK_TIME]
#                     [duration]
#
# This is a proof-of-concept tool that only traces libc malloc().
# To be developed further, it should also trace realloc(), calloc(), and
# other libc allocator routines.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016   Brendan Gregg   Created this (offcputime).
# 22-Dec-2017      "     "      Converted this into mallocstacks.

from __future__ import print_function
from bcc import BPF
from sys import stderr
from time import sleep, strftime
import argparse
import errno
import signal
import time
import threading
import os

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

# arguments
examples = """examples:
    ./mallocstacks             # trace libc malloc() bytes until Ctrl-C
    ./mallocstacks 5           # trace for 5 seconds only
    ./mallocstacks -f 5        # 5 seconds, and output in folded format
    ./mallocstacks -m 1000     # only trace I/O more than 1000 usec
    ./mallocstacks -M 10000    # only trace I/O less than 10000 usec
    ./mallocstacks -p 185      # only trace threads for PID 185
    ./mallocstacks -t 188      # only trace thread 188
"""
parser = argparse.ArgumentParser(
    description="Summarize libc malloc() bytes by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
# Note: this script provides --pid and --tid flags but their arguments are
# referred to internally using kernel nomenclature: TGID and PID.
thread_group.add_argument("-p", "--pid", metavar="PID", dest="tgid",
    help="trace this PID only", type=positive_int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="pid",
    help="trace this TID only", type=positive_int)
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=4096,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 2048)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
args = parser.parse_args()
if args.pid and args.tgid:
    parser.error("specify only one of -p and -t")
folded = args.folded
duration = int(args.duration)
debug = 0

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};

struct key_thread {
    u32 pid;
    u32 tgid;
};

struct stack_info {
    int user_stack_id;
    char name[TASK_COMM_LEN];
};

BPF_HASH(thread2stack, struct key_thread, struct stack_info);
BPF_HASH(keyt2size, struct key_t, size_t);

// 使用这个哈希表记录每个分配内存的地址（键）和分配大小（值）
BPF_HASH(addr2size, u64, size_t);

BPF_HASH(addr2key, u64, struct key_t);

BPF_HASH(bytes, struct key_t, u64);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int trace_malloc_return(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    u64 addr = (u64)PT_REGS_RC(ctx); // 获取malloc的返回地址

    u64 zeros = 0, *vals;
    size_t zero = 0, *val;
    struct key_t key = {};
    struct key_thread k_thread = {};
    struct stack_info info_zero = {};
    info_zero.user_stack_id = 0;
    bpf_probe_read_str(info_zero.name, sizeof(info_zero.name), "error");

    k_thread.pid = pid;
    k_thread.tgid = tgid;
    struct stack_info *info = thread2stack.lookup_or_init(&k_thread, &info_zero);

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = info->user_stack_id;
    bpf_probe_read_kernel(key.name, sizeof(info->name), info->name);

    val = keyt2size.lookup_or_init(&key, &zero);s

    addr2size.update(&addr, val);

    addr2key.update(&addr, &key);

    vals = bytes.lookup_or_init(&key, &zeros);
    (*vals) += (u64) (*val);

    return 0;
}

int trace_malloc_entry(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!(THREAD_FILTER)) {
        return 0;
    }

    // create map key
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = USER_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    struct key_thread k_thread = {};
    struct stack_info info = {};
    k_thread.pid = pid;
    k_thread.tgid = tgid;
    info.user_stack_id = key.user_stack_id;
    bpf_probe_read_kernel(info.name, sizeof(key.name), key.name);

    keyt2size.update(&key, &size);
    thread2stack.update(&k_thread, &info);

    return 0;
}

int trace_free(struct pt_regs *ctx, void *ptr) {
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!(THREAD_FILTER)) {
        return 0;
    }
    u64 addr = (u64)ptr;
    u64 zeros = 0;
    size_t zero = 0;

    // 通过地址找对应key,通过key找到内存分配
    struct key_t *key = addr2key.lookup(&addr);
    
    // 获取该地址分配内存大小
    size_t *free_size = addr2size.lookup_or_init(&addr, &zero);

    if (key && free_size) {
        size_t size = *free_size;
        u64 *val = bytes.lookup_or_init(key, &zeros);
        if (val) {
            if (*val >= size) {
                *val -= size;
            } else {
                *val = 0;
            }
        }
        addr2size.delete(&addr);
        addr2key.delete(&addr);
    }
    return 0;
}

"""

# set thread filter
thread_context = ""
if args.tgid is not None:
    thread_context = "PID %d" % args.tgid
    thread_filter = 'tgid == %d' % args.tgid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'pid == %d' % args.pid
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# handle stack args
user_stack_get = \
    "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
stack_context = "user"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)

if (debug):
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
if args.pid is not None:
    tpid = args.pid
else:
    tpid = -1
b.attach_uprobe(name="tcmalloc_path", sym="malloc", fn_name="trace_malloc_entry", pid=tpid)
b.attach_uretprobe(name="tcmalloc_path", sym="malloc", fn_name="trace_malloc_return", pid=tpid)
b.attach_uprobe(name="tcmalloc_path", sym="free", fn_name="trace_free", pid=tpid)
matched = b.num_open_uprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

# header
if not folded:
    print("Tracing libc malloc() bytes (us) of %s by %s stack" %
        (thread_context, stack_context), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")


thread_kill = False

def generate(b):
    text = ""
    count_unkwnown = 0
    missing_stacks = 0
    has_enomem = False
    # mm = b.get_table("addr2size")
    # for k, v in mm.items():
    #     print(k, ": \t", v)
    # print("sssssssss")

    bytemap = b.get_table("bytes")
    stack_traces = b.get_table("stack_traces")
    for k, v in sorted(bytemap.items(), key=lambda bytemap: bytemap[1].value):
        # handle get_stackid erorrs
        if (k.user_stack_id < 0 and k.user_stack_id != -errno.EFAULT):
            missing_stacks += 1
            # check for an ENOMEM error
            if k.user_stack_id == -errno.ENOMEM:
                has_enomem = True
            continue

        # user stacks will be symbolized by tgid, not pid, to avoid the overhead
        # of one symbol resolver per thread
        try:
            user_stack = list(stack_traces.walk(k.user_stack_id))
        except:
            continue


        if folded:
            # print folded stack output
            line = [k.name.decode("utf-8")] + \
                [b.sym(addr, k.tgid).decode("utf-8") for addr in reversed(user_stack)]
            line_str = ";".join(line)
            if "unknown" in line_str:
                count_unkwnown += 1
            text += line_str
            text += " "
            text += str(v.value)
            text += "\n"
        else:
            # print default multi-line stack output
            for addr in user_stack:
                print("    %s" % b.sym(addr, k.tgid))
            print("    %-16s %s (%d)" % ("-", k.name.decode(), k.pid))
            print("        %d\n" % v.value)

    if missing_stacks > 0:
        enomem_str = "" if not has_enomem else \
            " Consider increasing --stack-storage-size."
        print("WARNING: %d stack traces could not be displayed.%s" %
            (missing_stacks, enomem_str),
            file=stderr)
    return text, count_unkwnown

# 定义保存 BPF 表的函数
def save_bpf_data(b):
    finally_text = ""
    while True:
        sleep(0.3)
        if thread_kill:
            break
        text, count_unkwnown = generate(b)
        if count_unkwnown > 20:
            break
        else:
            finally_text = text
    print(finally_text)


# 添加一个线程，定期检查表状态并保存
bpf_monitor_thread = threading.Thread(target=save_bpf_data, args=(b,))
bpf_monitor_thread.start()


try:
    sleep(duration)
    thread_kill = True
except KeyboardInterrupt:
    # as cleanup can take many seconds, trap Ctrl-C:
    thread_kill = True
    signal.signal(signal.SIGINT, signal_ignore)

if not folded:
    print()

bpf_monitor_thread.join()
