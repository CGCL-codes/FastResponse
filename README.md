# FastResponse

**FastResponse** is a holistic approach that reduces the co-location interference between throughput-oriented and latency-sensitive workloads on ULL SSDs, with the goal of optimizing the performance of latency-sensitive workloads.
We make the following contributions:
+ We apply a new journaling scheme, which commits file-level transactions that only consist of file metadata information for latency-sensitive processes;
+ We design and implement a new scheduler to fully utilize the characteristics of ULL SSDs. Large I/O requests are split into smaller ones which are dispatched in parallel;
+ We modify the kernel's \textit{Complete Fair Scheduler} (CFS) to promote the priority of latency-sensitive processes.

## Configuration
1. We modify the system call table(`arch/x86/entry/syscalls/syscall 64.tbl`) and implement two system calls(No.436, No.437). You can write an script to invoke the two system call.
2. Compile the kernel with the config MQ_IOSCHED_LIMITED_DEPTH enabled. To use LD I/O scheduler. First, you should choose the LD to be the I/O scheduler of the target device by `echo 'limited-depth' > /sys/block/nvme0n1/queue/scheduler`. Second, you can limit the depth of the ULL SSD by `echo 8 > /sys/block/nvme0n1/queue/iosched/depth`.
