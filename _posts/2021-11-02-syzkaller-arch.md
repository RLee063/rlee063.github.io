---
layout: post
category: source_read
title: "syzkaller internals: architecture"
---
## TOC
- [Overview](#overview)
- [syz-manager <-> VM](#syz-manager---vm)
- [syz-manager <-> syz-fuzzer](#syz-manager---syz-fuzzer)
- [syz-fuzzer <-> syz-executor](#syz-fuzzer---syz-executor)

## Overview
![process_structures](images/syzkaller/process_structure.png)

官方文档已经描述得比较详细，这里直接摘抄过来：
* The syz-manager process starts, monitors and restarts several VM instances, and starts a syz-fuzzer process inside of the VMs. syz-manager is responsible for persistent corpus and crash storage. It runs on a host with stable kernel which does not experience white-noise fuzzer load.
* The syz-fuzzer process runs inside of presumably unstable VMs. The syz-fuzzer guides fuzzing process (input generation, mutation, minimization, etc.) and sends inputs that trigger new coverage back to the syz-manager process via RPC. It also starts transient syz-executor processes.
* Each syz-executor process executes a single input (a sequence of syscalls). It accepts the program to execute from the syz-fuzzer process and sends results back. It is designed to be as simple as possible (to not interfere with fuzzing process), written in C++, compiled as static binary and uses shared memory for communication.

接下来简要分析各个模块之间管理与通信的实现细节。

## syz-manager <-> VM



## syz-manager <-> syz-fuzzer

## syz-fuzzer <-> syz-executor