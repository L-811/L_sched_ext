/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_simple.bpf.skel.h"

#include <sched.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "self_prio_scx_simple.bpf.skel.h"
#include <sys/time.h> 
#include <sys/resource.h>

/* Defined in UAPI */
#define SCHED_EXT 7
#define ARRAY_SIZE 5

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-p]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -p            Switch only tasks on SCHED_EXT policy intead of all\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;
int map_fd;//2024-1-17

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct self_prio_scx_simple *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

// 设置调度器并打印优先级信息的函数
void set_scheduler_and_print_priority(int priority) {
    pid_t pid = getpid();
    struct sched_param sched_param = {
        .sched_priority = sched_get_priority_max(SCHED_EXT),
    };
    int err;
    err = syscall(__NR_sched_setscheduler, pid, SCHED_EXT, &sched_param);
    SCX_BUG_ON(err, "Failed to set scheduler to SCHED_EXT");

    int my_prio = getpriority(PRIO_PROCESS, pid);
    printf("before set prio : %d \n", my_prio);

    setpriority(PRIO_PROCESS, getpid(), priority);

    my_prio = getpriority(PRIO_PROCESS, getpid());
    printf("after set prio : %d \n", my_prio);

	bpf_map_update_elem(map_fd, &pid, &priority, BPF_ANY);//优先级信息存入map

    while (1) {
        printf("I'm task%d my pid: %d\n", priority, pid);
        sleep(5);
    }
}

// 执行任务1的函数
void perform_task1() {
    set_scheduler_and_print_priority(15);//数字越大优先级越低
}

// 执行任务2的函数
void perform_task2() {
    set_scheduler_and_print_priority(15);
}

// 执行任务3的函数
void perform_task3() {
    set_scheduler_and_print_priority(8);
}

// 执行任务4的函数
void perform_task4() {
    set_scheduler_and_print_priority(8);
}

int main(int argc, char **argv)
{
	struct self_prio_scx_simple *skel;
	struct bpf_link *link;
	__u32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = self_prio_scx_simple__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	while ((opt = getopt(argc, argv, "fph")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'p':
			skel->rodata->switch_partial = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(self_prio_scx_simple__load(skel), "Failed to load skel");

	link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	//2024-1-17
	printf("****************创建进程并将将优先级的值注入map*******************\n");

	map_fd = bpf_map__fd(skel->maps.my_map);


	s32 pid1, pid2, pid3, pid4;

    pid1 = fork();
    if (pid1 == 0) {
        // 子进程1
        set_scheduler_and_print_priority(15);
        exit(0);
    }

    pid2 = fork();
    if (pid2 == 0) {
        // 子进程2
        set_scheduler_and_print_priority(15);
        exit(0);
    }

    pid3 = fork();
    if (pid3 == 0) {
        // 子进程3
        set_scheduler_and_print_priority(8);
        exit(0);
    }

    pid4 = fork();
    if (pid4 == 0) {
        // 子进程4
        set_scheduler_and_print_priority(8);
        exit(0);
    }

    
	//2024-1-17

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		__u64 stats[2];

		read_stats(skel, stats);
		printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	self_prio_scx_simple__destroy(skel);
	// 父进程等待子进程结束
    for (int i = 0; i < 4; ++i) {
        wait(NULL);
    }
	return 0;
}
