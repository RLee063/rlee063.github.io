---
layout: post
category: source_read
title: ebpf-fuzzer 源码分析
---
前几天看到有人 release 了一个 [ebpf-fuzzer](https://github.com/snorez/ebpf-fuzzer)，正好自己在学习这方面的东西，就看了一下这个东西的源码，稍微做一点记录。

## 简介

总体由三个部分构成：
* [qemu fuzzlib](https://github.com/snorez/clib/blob/master/src/qemu_fuzzlib.c): 可能是作者自己实现的一个框架？有点类似 syzkaller 但是是用 C 语言实现的，主要就是管理 qemu 实例、控制整个 fuzz 流程。
* ebpf sample generator: 可以看作是基于 qemu_fuzzlib 的 custom mutator，算法受 [这篇文章](https://scannell.io/posts/ebpf-fuzzing/) 的启发（我记得原文章作者也说要开源项目来着）。
* exception handler in the linux kernel: ？

## qemu_fuzzlib

大致是想设计来作为一个 lib，开放三个 API：
* qemu_fuzzlib_env_setup: 类似 syzkaller 设置各种参数，在这里把 custom_mutator 传进去。
* qemu_fuzzlib_env_run: 执行 fuzzing 过程。
* qemu_fuzzlib_env_destroy

### qemu_fuzzlib_env_setup

调用 `env_validate_arg` 验证参数的合法性，主要是一些文件是否存在的验证。调用 `env_init` 初始化 `env` 结构体，主要是记录运行时的参数和一些路径名。调用 `env_prepare` 执行具体的初始化操作，例如创建工作目录，初始化 instance 的工作目录和结构体。

### qemu_fuzzlib_env_run

整体的运行架构可以分为四个部分：
* Host 主线程: 负责控制整个 fuzzing 过程
* Host 子线程: 对于每一个 instance 都会在 Host 上创建一个线程来对其进行控制。
* VM 管理进程: VM 上运行有一个管理程序负责与 Host 同步及通讯，运行具体的样本实例，回传样本的运行结果。
* VM 样本进程

#### Host 主线程

`qemu_fuzzlib_env_run` 中就是一个大 while 死循环，调用 `env_run_one` 完成一次 fuzzing 过程。

`env_run_one`: 
1. 遍历 instance 数组，查找空闲的 instance，通过互斥锁实现。
2. 调用 `env_check_inst_res` 查看上一次 fuzzing 的结果，更新对应的记录（为什么不在函数末尾？）。
3. 接着调用 `env_reuse_not_tested` 查找是否有没有测试到的样本（在 fuzzing 期间出错的话就会导致样本被写入 not_tested 文件夹）。
4. 如果没有 not_tested 的样本，则从现有样本中突变生成新的样本，突变使用 setup 中传入的 custom_mutator 函数。
5. 最后调用 `env_run_inst`，在函数内部创建 `run_inst_in_thread` 线程负责控制 qemu 实例完成 fuzzing。

#### Host 子线程

主要流程都在 `inst_run` 函数里实现：
1. 判断当前 instance 是否有运行中的 qemu 实例，如果没有就调用 `inst_launch_qemu` 来创建。判断创建是否成功是通过读 qemu log，查对应的字符串来实现的。然后做一些创建目录、清理 log 的准备工作。
2. 上传管理进程的文件、上传待测试的样本文件。
3. 运行 vm 中的管理进程，这里的同步方案同时使用了 socket 和读 log 日志两种方式。Host 读 qemu log 判断进程是否启动，vm 中通过 socket 等待 Host 进程。
4. 从 socket 中读出 vm 中样本的测试结果，这里实现了四种结果：
    * INVALID: 生成的指令没有通过 bpf 验证器的验证
    * VALID
    * NOT_TESTED: fuzzing 过程出错，样本没有被测试
    * BOOM: 样本的运行出现了某种意料之外的结果（关注）

#### VM 管理进程 (default_guest.c)

这个程序是用字符串写在 .c 文件里的，非常不优雅了属于是。先往 `/dev/kmsg` 写数据告诉 Host 等待连接，然后调用 `connect` 向 Host 发起连接。建立连接后 `fork` 一个进程来执行样本，对样本的执行结果进行监控，主要就是看是否超时还有程序的 exit number。

## ebpf sample generator

算法和引用博客里的算法大致相同吧，样本主要分为了 header, body, tail 三个部分。
* header: 写死的代码，不参与 mutate，主要是创建两个 map，一个名为 corrupt(fd=0xa-暂不明白作用)，一个名为 storage(fd=0xb)
* body: 按框架生成随机的指令
    1. `insn_get_map_ptr` 将两个 map 的指针对应存入 R9 和 R8 两个寄存器
    2. `insn_body` 中先对 special reg(7) 通过 branch 指令限制 bound；然后使用 generators 生成许多随机的指令，需要关注的是其中会对 INVALID_P_REG(6) 进行操作
    3. `insn_alu_map_ptr` 使用 INVALID_P_REG（已随机化）对 CORRUPT_REG 进行 alu（SUB）操作
    4. `insn_write_mem` 使用运算后的 CORRUPT_REG 读入数据，然后存到 storage map 里（这里是关键，如果 corrupt reg 违法了而没被检测到，就会读入一个非 corrupt map 的数值写入 storage map，之后检测错误就是看写入的这个值是个啥）
    5. `insn_exit`
* tail: 写死的代码，不参与 mutate，运行程序，检查 verifier 结果和 OOB 错误。（special value 暂不明白其用意）

一个例子：
```c
struct bpf_insn __insns[] = {
        /* insn_get_map_ptr REG_8(storage), REG_9(corrupt) */
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 0xfffffffc),
        BPF_LD_MAP_FD(BPF_REG_1, 0xa),
        BPF_EMIT_CALL(0x1),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0x0, 1),
        BPF_EXIT_INSN(),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        //
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 0xfffffffc),
        BPF_LD_MAP_FD(BPF_REG_1, 0xb),
        BPF_EMIT_CALL(0x1),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0x0, 1),
        BPF_EXIT_INSN(),
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
        BPF_MOV64_IMM(BPF_REG_0, 0x0),

        /* insn_body */
        // load storage to special(R7) 
        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0), BPF_MOV64_IMM(BPF_REG_0, 0x0), 
        // max bound
        BPF_MOV32_IMM(BPF_REG_4, 0x20000),
        BPF_JMP32_REG(BPF_JSLT, BPF_REG_7, BPF_REG_4, 1),
        BPF_EXIT_INSN(),
        // min bound
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_JMP_IMM(BPF_JSGT, BPF_REG_7, 0xffffe860, 1), // neg
        BPF_EXIT_INSN(),
        // random instructions
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_LD_IMM64(BPF_REG_3, 0xffffffffd4d77376),
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_ALU64_REG(BPF_DIV, BPF_REG_3, BPF_REG_7),
        BPF_MOV64_IMM(BPF_REG_3, 0xe5101ff1),
        BPF_MOV32_IMM(BPF_REG_3, 0x9486952f),
        BPF_ALU32_REG(BPF_MOD, BPF_REG_7, BPF_REG_3),
        BPF_MOV32_IMM(BPF_REG_7, 0xe28aa4aa),
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_LD_IMM64(BPF_REG_6, 0xffffffffc42f5a26),
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
        BPF_JMP_IMM(BPF_JGE, BPF_REG_7, 0xbdc0c97c, 1),
        BPF_EXIT_INSN(),
        BPF_JMP_REG(BPF_JNE, BPF_REG_3, BPF_REG_6, 1),
        BPF_EXIT_INSN(),
        BPF_JMP32_IMM(BPF_JLE, BPF_REG_3, 0x56bd482b, 1),
        BPF_EXIT_INSN(),
        BPF_ALU32_IMM(BPF_XOR, BPF_REG_3, 0x3e70cd7a),
        BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_3, 1),
        BPF_EXIT_INSN(),
        BPF_ALU32_IMM(BPF_NEG, BPF_REG_7, 0x8494e7a3),
        BPF_MOV64_IMM(BPF_REG_0, 0x0),
        BPF_JMP32_REG(BPF_JGE, BPF_REG_6, BPF_REG_3, 1),
        BPF_EXIT_INSN(),

        /* insn_alu_map_ptr: alu SUB to corrupt reg(9) */
        BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_6),

        /* insn_write_mem */
        BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_9, 0),
        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_5, 8),

        /* insn_exit */
        BPF_MOV64_IMM(BPF_REG_0, 0x1),
        BPF_EXIT_INSN(),
}
```

## 想法

* 速度还是比较慢，我不知道作者实现自己的库的目的是什么，不知道 syzkaller 框架能否带来性能的提升，也不知道是否有价值在 vm 层面进行 fuzz（现有的方案中有将 ebpf 模块编译成库文件在用户态直接进行 fuzz）。可能还是得用库做 fuzzing，用 vm 做验证。
* 突变策略还是很原始，并且没有结合到反馈率，验证通过率也很低*。或许可以把这种 grammar fuzzing 模型结合到 syzkaller 上，生成语法更丰富，语义更合法的样本*？
* 检测错误是 eBPF verifier fuzzing 的核心，最原始的博客中的方法检测的是 OOB write （通过计算后的指针写入一个值到 map，如果没把值写进去则判断为写越界写到其他内存去了），但这个好像是 OOB read？（通过计算后的指针去读 corrupt map 的一个值，然后写到 storage map 里，如果写入的数值不是 corrupt map 里的数值，则判定 OOB）。PS: 这里很可能是我没理解到作者的用意，感觉是能检测 RW 的错误。
* 感觉限于不能对参数设置语法，除了对 verifier 的 fuzzing 外，对 eBPF subsystem 本身的 fuzzing 也有待提高？