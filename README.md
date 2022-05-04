# FastResponse
Towards Low-Latency I/O Services for Mixed Workloads Using Ultra-Low Latency SSDs

## Introduction
**FastResponse** is a holistic approach that reduces the co-location interference between throughput-oriented and latency-sensitive workloads on ULL SSDs, with the goal of optimizing the performance of latency-sensitive workloads.
We make the following contributions:
+ We identify the root causes of I/O interference on ULL SSDs for co-running workloads, including compound transaction committed in the file system layer, resource contention in the block device layer, and costly  process scheduling;
+ In the block layer, we split large I/O requests into small ones to mitigate their impact on latency-sensitive I/Os. We also throttle I/O requests of throughput-oriented workloads moderately to mitigate the interference on latency-sensitive workloads;
+ In the file system layer, we develop a lightweight journaling scheme for latency-sensitive workloads particularly, and commit file-level transactions for latency-sensitive individually to mitigate the I/O interference. Since transactions committed by latency-sensitive processes only contain file metadata, the latency of compound transactions are significantly reduced;
+ We redesign Complete Fair Scheduler (CFS) to fully exploit the feature of ULL SSDs. The new process scheduler promotes the priority of latency-sensitive processes to minimize the waiting time after critical processes are woken up.

## How to use
1. Compile the kernel with the config MQ_IOSCHED_LIMITED_DEPTH enabled.
   + Choose the **LD** to be the I/O scheduler of the target device by `echo 'limited-depth' > /sys/block/nvme0n1/queue/scheduler`. (Assume the ULL SSD is `nvme0n1`)
   + Limit the depth of the ULL SSD to 8 by `echo 8 > /sys/block/nvme0n1/queue/iosched/depth`.
2. We modify the system call table(`arch/x86/entry/syscalls/syscall 64.tbl`) and implement two system calls(*set_io_critical*, *clear_io_critical*). You can write an script to invoke these two system call.
3. Co-run latency-sensitive applications (such as *RocksDB*) and throughput-oriented applications (such as *Bayes* running on Hadoop). 
4. Measure the response time of *RocksDB* and  throughput of *Bayes*. Compare these metrics with that of vanilla Linux.
