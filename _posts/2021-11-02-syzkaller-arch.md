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

---

| 接下来简要分析各个模块之间的关系，本文的目的是暂时去掉多余的细节，把各个组件之间管理与通信的实现细节抽离出来，方便和我一样的初学者快速理解。本文假设读者已经[搭建 syzkaller 所需环境并成功运行](https://github.com/google/syzkaller/blob/master/docs/setup.md)。

## syz-manager <-> VM

在 syz-manager 中，载入配置文件后，首先会在 RunManager() 中调用 vm.Create() 创建 vmPool，这是一个用于管理 vm 的结构体。其中 impl 指向代表了具体 vm 实现的结构体（例如 qemu，kvm 等）。Create 函数主要还是做一些配置和检查的初始化工作。

```
type Pool struct {
    impl     vmimpl.Pool
    workdir  string
    template string
    timeouts targets.Timeouts
}

type Pool struct { //vmimpl.Pool
    env        *vmimpl.Env
    cfg        *Config
    target     *targets.Target
    archConfig *archConfig
    version    string
}

func Create(cfg *mgrconfig.Config, debug bool) (*Pool, error) {
    typ, ok := vmimpl.Types[cfg.Type]
    if !ok {
        return nil, fmt.Errorf("unknown instance type '%v'", cfg.Type)
    }
    env := &vmimpl.Env{
        Name:     cfg.Name,
        OS:       cfg.TargetOS,
        Arch:     cfg.TargetVMArch,
        Workdir:  cfg.Workdir,
        Image:    cfg.Image,
        SSHKey:   cfg.SSHKey,
        SSHUser:  cfg.SSHUser,
        Timeouts: cfg.Timeouts,
        Debug:    debug,
        Config:   cfg.VM,
    }
    impl, err := typ.Ctor(env)
    if err != nil {
        return nil, err
    }
    return &Pool{
        impl:     impl,
        workdir:  env.Workdir,
        template: cfg.WorkdirTemplate,
        timeouts: cfg.Timeouts,
    }, nil
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
    archConfig := archConfigs[env.OS+"/"+env.Arch]
    cfg := &Config{
        Count:       1,
        CPU:         1,
        Mem:         1024,
        ImageDevice: "hda",
        Qemu:        archConfig.Qemu,
        QemuArgs:    archConfig.QemuArgs,
        NetDev:      archConfig.NetDev,
        Snapshot:    true,
    }
    if err := config.LoadData(env.Config, cfg); err != nil {
        return nil, fmt.Errorf("failed to parse qemu vm config: %v", err)
    }
    if cfg.Count < 1 || cfg.Count > 128 {
        return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
    }
    if env.Debug && cfg.Count > 1 {
        log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
        cfg.Count = 1
    }
    if _, err := exec.LookPath(cfg.Qemu); err != nil {
        return nil, err
    }
    if env.Image == "9p" {
        if env.OS != targets.Linux {
            return nil, fmt.Errorf("9p image is supported for linux only")
        }
        if cfg.Kernel == "" {
            return nil, fmt.Errorf("9p image requires kernel")
        }
    } else {
        if !osutil.IsExist(env.Image) {
            return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
        }
    }
    if cfg.CPU <= 0 || cfg.CPU > 1024 {
        return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.CPU)
    }
    if cfg.Mem < 128 || cfg.Mem > 1048576 {
        return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
    }
    cfg.Kernel = osutil.Abs(cfg.Kernel)
    cfg.Initrd = osutil.Abs(cfg.Initrd)

    output, err := osutil.RunCmd(time.Minute, "", cfg.Qemu, "--version")
    if err != nil {
        return nil, err
    }
    version := string(bytes.Split(output, []byte{'\n'})[0])

    pool := &Pool{
        env:        env,
        cfg:        cfg,
        version:    version,
        target:     targets.Get(env.OS, env.Arch),
        archConfig: archConfig,
    }
    return pool, nil
}
```

之后会进入 vmLoop() 函数，通过 for 循环来持续运行 vm 实例。其中使用 instances 数组来维护可用的 instance 数量。有三种情况会往 instances 里 append：
1. 在程序初次运行时，会通过 bootInstance channel 来控制按一定速率往 instances 里 append。
2. 当 vm crash 过后会往 isntances 里 append。
3. 当 repro 过程结束后。（代表当前 vm 生命周期结束；之后再补充）

当发现有可用 instance 时，就会调用 mgr.runInstance(idx) 来运行一个实例。
```
func (mgr *Manager) vmLoop() {
    log.Logf(0, "booting test machines...")
    log.Logf(0, "wait for the connection from test machine...")
    instancesPerRepro := 4
    vmCount := mgr.vmPool.Count()
    if instancesPerRepro > vmCount {
        instancesPerRepro = vmCount
    }
    bootInstance := make(chan int)
    go func() {
        for i := 0; i < vmCount; i++ {
            bootInstance <- i
            time.Sleep(10 * time.Second * mgr.cfg.Timeouts.Scale)
        }
    }()
    var instances []int
    for shutdown != nil || len(instances) != vmCount {
        if shutdown != nil {
            for !canRepro() && len(instances) != 0 {
                last := len(instances) - 1
                idx := instances[last]
                instances = instances[:last]
                log.Logf(1, "loop: starting instance %v", idx)
                go func() {
                    crash, err := mgr.runInstance(idx)
                    runDone <- &RunResult{idx, crash, err}
                }()
            }
        }

        select {
        case idx := <-bootInstance:
            instances = append(instances, idx)
        case res := <-runDone:
            log.Logf(1, "loop: instance %v finished, crash=%v", res.
            instances = append(instances, res.idx)
            ...
        case res := <-reproDone:
            log.Logf(1, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'",
                res.instances, res.report0.Title, res.res != nil, crepro, title)
            delete(reproducing, res.report0.Title)
            instances = append(instances, res.instances...)
        }
    }
}
```

会通过 runInstance() -> runInstanceInner() -> mgr.vmPool.Craete() -> pool.impl.Create() 调用到不同类型 vm 实现的 Create() 函数，这里以 qemu 为例。qemu 主要在 Create() 中重复尝试调用 ctor() 来创建虚拟机实例，每个实例都由 instance 结构体来维护，记录了当前实例的一些参数和配置，ctor() 中简单的初始化这个结构体然后进入 inst.boot() 完成具体的启动流程。inst.boot() 则是根据 config 对 qemu 的启动参数进行构造，然后将启动命令的 stdout 和 stderr 重定向到管道，以便当 boot 失败时，获得失败的原因。最后会通过 WaitForSSH() 来检验虚拟机是否正常启动，其内部通过 ssh 来控制虚拟机执行一次 pwd 命令。

```
type instance struct {
    index       int
    cfg         *Config
    target      *targets.Target
    archConfig  *archConfig
    version     string
    args        []string
    image       string
    debug       bool
    os          string
    workdir     string
    sshkey      string
    sshuser     string
    timeouts    targets.Timeouts
    port        int
    monport     int
    forwardPort int
    mon         net.Conn
    monEnc      *json.Encoder
    monDec      *json.Decoder
    rpipe       io.ReadCloser
    wpipe       io.WriteCloser
    qemu        *exec.Cmd
    merger      *vmimpl.OutputMerger
    files       map[string]string
    diagnose    chan bool
}

func (inst *instance) boot() error {
    inst.port = vmimpl.UnusedTCPPort()
    inst.monport = vmimpl.UnusedTCPPort()
    args := []string{
        "-m", strconv.Itoa(inst.cfg.Mem),
        "-smp", strconv.Itoa(inst.cfg.CPU),
        "-chardev", fmt.Sprintf("socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=%v", inst.monport),
        "-mon", "chardev=SOCKSYZ,mode=control",
        "-display", "none",
        "-serial", "stdio",
        "-no-reboot",
        "-name", fmt.Sprintf("VM-%v", inst.index),
    }
    if inst.archConfig.RngDev != "" {
        args = append(args, "-device", inst.archConfig.RngDev)
    }
    templateDir := filepath.Join(inst.workdir, "template")
    args = append(args, splitArgs(inst.cfg.QemuArgs, templateDir, inst.index)...)
    args = append(args,
        "-device", inst.cfg.NetDev+",netdev=net0",
        "-netdev", fmt.Sprintf("user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:%v-:22", inst.port))
    if inst.image == "9p" {
        args = append(args,
            "-fsdev", "local,id=fsdev0,path=/,security_model=none,readonly",
            "-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=/dev/root",
        )
    } else if inst.image != "" {
        if inst.archConfig.UseNewQemuImageOptions {
            args = append(args,
                "-device", "virtio-blk-device,drive=hd0",
                "-drive", fmt.Sprintf("file=%v,if=none,format=raw,id=hd0", inst.image),
            )
        } else {
            // inst.cfg.ImageDevice can contain spaces
            imgline := strings.Split(inst.cfg.ImageDevice, " ")
            imgline[0] = "-" + imgline[0]
            if strings.HasSuffix(imgline[len(imgline)-1], "file=") {
                imgline[len(imgline)-1] = imgline[len(imgline)-1] + inst.image
            } else {
                imgline = append(imgline, inst.image)
            }
            args = append(args, imgline...)
        }
        if inst.cfg.Snapshot {
            args = append(args, "-snapshot")
        }
    }
    if inst.cfg.Initrd != "" {
        args = append(args,
            "-initrd", inst.cfg.Initrd,
        )
    }
    if inst.cfg.Kernel != "" {
        cmdline := append([]string{}, inst.archConfig.CmdLine...)
        if inst.image == "9p" {
            cmdline = append(cmdline,
                "root=/dev/root",
                "rootfstype=9p",
                "rootflags=trans=virtio,version=9p2000.L,cache=loose",
                "init="+filepath.Join(inst.workdir, "init.sh"),
            )
        }
        cmdline = append(cmdline, inst.cfg.Cmdline)
        args = append(args,
            "-kernel", inst.cfg.Kernel,
            "-append", strings.Join(cmdline, " "),
        )
    }
    if inst.cfg.EfiCodeDevice != "" {
        args = append(args,
            "-drive", "if=pflash,format=raw,readonly=on,file="+inst.cfg.EfiCodeDevice,
        )
    }
    if inst.cfg.EfiVarsDevice != "" {
        args = append(args,
            "-drive", "if=pflash,format=raw,readonly=on,file="+inst.cfg.EfiVarsDevice,
        )
    }
    if inst.cfg.AppleSmcOsk != "" {
        args = append(args,
            "-device", "isa-applesmc,osk="+inst.cfg.AppleSmcOsk,
        )
    }
    if inst.debug {
        log.Logf(0, "running command: %v %#v", inst.cfg.Qemu, args)
    }
    inst.args = args
    qemu := osutil.Command(inst.cfg.Qemu, args...)
    qemu.Stdout = inst.wpipe
    qemu.Stderr = inst.wpipe
    if err := qemu.Start(); err != nil {
        return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Qemu, args, err)
    }
    inst.wpipe.Close()
    inst.wpipe = nil
    inst.qemu = qemu
    // Qemu has started.

    // Start output merger.
    var tee io.Writer
    if inst.debug {
        tee = os.Stdout
    }
    inst.merger = vmimpl.NewOutputMerger(tee)
    inst.merger.Add("qemu", inst.rpipe)
    inst.rpipe = nil

    var bootOutput []byte
    bootOutputStop := make(chan bool)
    go func() {
        for {
            select {
            case out := <-inst.merger.Output:
                bootOutput = append(bootOutput, out...)
            case <-bootOutputStop:
                close(bootOutputStop)
                return
            }
        }
    }()
    if err := vmimpl.WaitForSSH(inst.debug, 10*time.Minute*inst.timeouts.Scale, "localhost",
        inst.sshkey, inst.sshuser, inst.os, inst.port, inst.merger.Err); err != nil {
        bootOutputStop <- true
        <-bootOutputStop
        return vmimpl.MakeBootError(err, bootOutput)
    }
    bootOutputStop <- true
    return nil
}
```

之后都不会通过任何方式直接监控 vm 的运行状态了，会监控 syz-fuzzer 的运行状态判断当前 vm 是否 crash。

## syz-manager <-> syz-fuzzer

上一节提到 runInstanceInner() 中调用 mgr.vmPool.Create() 来创建 vm 实例，在创建实例之后就会通过 inst.Copy() 把 syz-fuzzer 和 syz-executor 拷贝进虚拟机中，对于 qemu 这个过程是通过 scp 命令实现的。

之后调用 instance.FUzzerCmd() 构造 syz-fuzzer 的启动参数，大多是根据 cfg 解析生成的，需要关注的主要是 fwdAddr 参数，其为 manager 启动 RPC 服务的地址。syz-fuzzer 和 syz-manager 主要通过 RPC 进行通信。

紧接着调用 inst.Run() 启动 syz-fuzzer，在 qemu 中使用 ssh 实现。用管道接管 cmd 的 stdout 和 stderr，传入 MonitorExecution() 对运行状态进行监控。

```
func (mgr *Manager) runInstanceInner(index int, instanceName string) (*report.Report, []byte, error) {
    inst, err := mgr.vmPool.Create(index)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create instance: %v", err)
    }
    defer inst.Close()

    fwdAddr, err := inst.Forward(mgr.serv.port)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to setup port forwarding: %v", err)
    }

    fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to copy binary: %v", err)
    }

    // If ExecutorBin is provided, it means that syz-executor is already in the image,
    // so no need to copy it.
    executorBin := mgr.sysTarget.ExecutorBin
    if executorBin == "" {
        executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to copy binary: %v", err)
        }
    }

    fuzzerV := 0
    procs := mgr.cfg.Procs
    if *flagDebug {
        fuzzerV = 100
        procs = 1
    }

    // Run the fuzzer binary.
    start := time.Now()
    atomic.AddUint32(&mgr.numFuzzing, 1)
    defer atomic.AddUint32(&mgr.numFuzzing, ^uint32(0))

    cmd := instance.FuzzerCmd(fuzzerBin, executorBin, instanceName,
        mgr.cfg.TargetOS, mgr.cfg.TargetArch, fwdAddr, mgr.cfg.Sandbox, procs, fuzzerV,
        mgr.cfg.Cover, *flagDebug, false, false, true, mgr.cfg.Timeouts.Slowdown)
    outc, errc, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.vmStop, cmd)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to run fuzzer: %v", err)
    }

    var vmInfo []byte
    rep := inst.MonitorExecution(outc, errc, mgr.reporter, vm.ExitTimeout)
    if rep == nil {
        // This is the only "OK" outcome.
        log.Logf(0, "%s: running for %v, restarting", instanceName, time.Since(start))
    } else {
        vmInfo, err = inst.Info()
        if err != nil {
            vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
        }
    }

    return rep, vmInfo, nil
}
```

（之后补充）


```
func (inst *Instance) MonitorExecution(outc <-chan []byte, errc <-chan error,
    reporter *report.Reporter, exit ExitCondition) (rep *report.Report) {
    mon := &monitor{
        inst:     inst,
        outc:     outc,
        errc:     errc,
        reporter: reporter,
        exit:     exit,
    }
    lastExecuteTime := time.Now()
    ticker := time.NewTicker(tickerPeriod * inst.timeouts.Scale)
    defer ticker.Stop()
    for {
        select {
        case err := <-errc:
            switch err {
            case nil:
                // The program has exited without errors,
                // but wait for kernel output in case there is some delayed oops.
                crash := ""
                if mon.exit&ExitNormal == 0 {
                    crash = lostConnectionCrash
                }
                return mon.extractError(crash)
            case ErrTimeout:
                if mon.exit&ExitTimeout == 0 {
                    return mon.extractError(timeoutCrash)
                }
                return nil
            default:
                // Note: connection lost can race with a kernel oops message.
                // In such case we want to return the kernel oops.
                crash := ""
                if mon.exit&ExitError == 0 {
                    crash = lostConnectionCrash
                }
                return mon.extractError(crash)
            }
        case out, ok := <-outc:
            if !ok {
                outc = nil
                continue
            }
            lastPos := len(mon.output)
            mon.output = append(mon.output, out...)
            if bytes.Contains(mon.output[lastPos:], executingProgram1) ||
                bytes.Contains(mon.output[lastPos:], executingProgram2) {
                lastExecuteTime = time.Now()
            }
            if reporter.ContainsCrash(mon.output[mon.matchPos:]) {
                return mon.extractError("unknown error")
            }
            if len(mon.output) > 2*beforeContext {
                copy(mon.output, mon.output[len(mon.output)-beforeContext:])
                mon.output = mon.output[:beforeContext]
            }
            // Find the starting position for crash matching on the next iteration.
            // We step back from the end of output by maxErrorLength to handle the case
            // when a crash line is currently split/incomplete. And then we try to find
            // the preceding '\n' to have a full line. This is required to handle
            // the case when a particular pattern is ignored as crash, but a suffix
            // of the pattern is detected as crash (e.g. "ODEBUG:" is trimmed to "BUG:").
            mon.matchPos = len(mon.output) - maxErrorLength
            for i := 0; i < maxErrorLength; i++ {
                if mon.matchPos <= 0 || mon.output[mon.matchPos-1] == '\n' {
                    break
                }
                mon.matchPos--
            }
            if mon.matchPos < 0 {
                mon.matchPos = 0
            }
        case <-ticker.C:
            // Detect both "no output whatsoever" and "kernel episodically prints
            // something to console, but fuzzer is not actually executing programs".
            if time.Since(lastExecuteTime) > inst.timeouts.NoOutput {
                return mon.extractError(noOutputCrash)
            }
        case <-Shutdown:
            return nil
        }
    }
} 
```

用于和 syz-fuzzer 通信的 RPC 服务在 runManager() 中调用 startRPCServer() 初始化，依靠 golang 自带的 rpc 模块实现。目前主要有以下功能（之后补充说明）：
* Connect
* rotateCorpus
* selectInputs
* Check
* NewInput
* Poll
* shutdownInstance

## syz-fuzzer <-> syz-executor

syz-fuzzer 的 main 函数中有一个 for 循环，负责生成 flagProcs 个 fuzzer processes。其调用 proc.loop() 进入每个 process 的 fuzz 主循环。Proc 是用来管理 fuzzer processes 的结构体。

```
type Proc struct {
    fuzzer            *Fuzzer
    pid               int
    env               *ipc.Env
    rnd               *rand.Rand
    execOpts          *ipc.ExecOpts
    execOptsCover     *ipc.ExecOpts
    execOptsComps     *ipc.ExecOpts
    execOptsNoCollide *ipc.ExecOpts
}

func main() {
    ...
    log.Logf(0, "starting %v fuzzer processes", *flagProcs)
    for pid := 0; pid < *flagProcs; pid++ {
        proc, err := newProc(fuzzer, pid)
        if err != nil {
            log.Fatalf("failed to create proc: %v", err)
        }
        fuzzer.procs = append(fuzzer.procs, proc)
        go proc.loop()
    }
    ...
}
```

proc.loop() 则是一个 while 循环不断执行 fuzz 的各个阶段，具体的过程在之后的文章中补充，这里主要关注 syz-fuzzer 和 syz-executor 的管理和通信方式的实现。proc.loop() 会调用 proc.execute() 来启动 syz-executor 执行具体的样本。

通过 proc.execute() -> proc.executeRaw() 来尝试启动 syz-executor。在 executeRaw() 内部也会 try 很多次，通过 proc.env.Exec() 来尝试启动 syz-executor。

在 proc.env.Exec() 中首先调用 makeCommand() 创建 env.cmd，command 结构体可以看作是 syz-fuzzer 和 syz-executor 的 session（如果没有启用 FORK_SERVER 则这个 session 会在每次执行完后清除，反之则会一直存在）。之后通过这个 session 调用 env.cmd.exec() 控制 syz-executor 执行具体的系统调用，最后 parseOutput() 对结果进行解析。

```
type command struct {
    pid      int
    config   *Config
    timeout  time.Duration
    cmd      *exec.Cmd
    dir      string
    readDone chan []byte
    exited   chan struct{}
    inrp     *os.File
    outwp    *os.File
    outmem   []byte
}

func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info *ProgInfo, hanged bool, err0 error) {
    // Copy-in serialized program.
    progSize, err := p.SerializeForExec(env.in)
    if err != nil {
        err0 = err
        return
    }
    var progData []byte
    if !env.config.UseShmem {
        progData = env.in[:progSize]
    }
    // Zero out the first two words (ncmd and nsig), so that we don't have garbage there
    // if executor crashes before writing non-garbage there.
    for i := 0; i < 4; i++ {
        env.out[i] = 0
    }

    atomic.AddUint64(&env.StatExecs, 1)
    if env.cmd == nil {
        if p.Target.OS != targets.TestOS && targets.Get(p.Target.OS, p.Target.Arch).HostFuzzer {
            // The executor is actually ssh,
            // starting them too frequently leads to timeouts.
            <-rateLimit.C
        }
        tmpDirPath := "./"
        atomic.AddUint64(&env.StatRestarts, 1)
        env.cmd, err0 = makeCommand(env.pid, env.bin, env.config, env.inFile, env.outFile, env.out, tmpDirPath)
        if err0 != nil {
            return
        }
    }
    output, hanged, err0 = env.cmd.exec(opts, progData)
    if err0 != nil {
        env.cmd.close()
        env.cmd = nil
        return
    }

    info, err0 = env.parseOutput(p)
    if info != nil && env.config.Flags&FlagSignal == 0 {
        addFallbackSignal(p, info)
    }
    if !env.config.UseForkServer {
        env.cmd.close()
        env.cmd = nil
    }
    return
}

```

makeCommand() 主要也是通过 osutil.Command() 来启动 syz-executor（这里的 Command() 的是指在 shell 中执行的命令，注意与作为 session 的 command 结构体作区分）。这里创建了三个管道对 Command 的 stdin，stdout 和 stderr 进行了替换。替换 stdin，stdout 的管道主要是用来交换命令和数据；替换 stderr 的主要是用来做错误处理。除此之外，如果设置了 SYZ_EXECUTOR_USES_SHMEM 则会创建两个文件作为 shm，并通过 cmd.ExtraFiles 传递文件描述符。

```
func makeCommand(pid int, bin []string, config *Config, inFile, outFile *os.File, outmem []byte,
    tmpDirPath string) (*command, error) {
    dir, err := ioutil.TempDir(tmpDirPath, "syzkaller-testdir")
    if err != nil {
        return nil, fmt.Errorf("failed to create temp dir: %v", err)
    }
    dir = osutil.Abs(dir)

    timeout := config.Timeouts.Program
    if config.UseForkServer {
        // Executor has an internal timeout and protects against most hangs when fork server is enabled,
        // so we use quite large timeout. Executor can be slow due to global locks in namespaces
        // and other things, so let's better wait than report false misleading crashes.
        timeout *= 10
    }

    c := &command{
        pid:     pid,
        config:  config,
        timeout: timeout,
        dir:     dir,
        outmem:  outmem,
    }
    defer func() {
        if c != nil {
            c.close()
        }
    }()

    if err := os.Chmod(dir, 0777); err != nil {
        return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
    }

    // Output capture pipe.
    rp, wp, err := os.Pipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create pipe: %v", err)
    }
    defer wp.Close()

    // executor->ipc command pipe.
    inrp, inwp, err := os.Pipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create pipe: %v", err)
    }
    defer inwp.Close()
    c.inrp = inrp

    // ipc->executor command pipe.
    outrp, outwp, err := os.Pipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create pipe: %v", err)
    }
    defer outrp.Close()
    c.outwp = outwp

    c.readDone = make(chan []byte, 1)
    c.exited = make(chan struct{})

    cmd := osutil.Command(bin[0], bin[1:]...)
    if inFile != nil && outFile != nil {
        cmd.ExtraFiles = []*os.File{inFile, outFile}
    }
    cmd.Dir = dir
    // Tell ASAN to not mess with our NONFAILING.
    cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
    cmd.Stdin = outrp
    cmd.Stdout = inwp
    if config.Flags&FlagDebug != 0 {
        close(c.readDone)
        cmd.Stderr = os.Stdout
    } else {
        cmd.Stderr = wp
        go func(c *command) {
            // Read out output in case executor constantly prints something.
            const bufSize = 128 << 10
            output := make([]byte, bufSize)
            var size uint64
            for {
                n, err := rp.Read(output[size:])
                if n > 0 {
                    size += uint64(n)
                    if size >= bufSize*3/4 {
                        copy(output, output[size-bufSize/2:size])
                        size = bufSize / 2
                    }
                }
                if err != nil {
                    rp.Close()
                    c.readDone <- output[:size]
                    close(c.readDone)
                    return
                }
            }
        }(c)
    }
    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("failed to start executor binary: %v", err)
    }
    c.cmd = cmd
    wp.Close()
    // Note: we explicitly close inwp before calling handshake even though we defer it above.
    // If we don't do it and executor exits before writing handshake reply,
    // reading from inrp will hang since we hold another end of the pipe open.
    inwp.Close()

    if c.config.UseForkServer {
        if err := c.handshake(); err != nil {
            return nil, err
        }
    }
    tmp := c
    c = nil // disable defer above
    return tmp, nil
}
```
