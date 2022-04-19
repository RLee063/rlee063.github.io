---
layout: post
title: "fork on WINDOWS"
tag: note
---
- [Introduction](#introduction)
- [Methodology](#methodology)
- [Implementation](#implementation)
	- [forkserver](#forkserver)
	- [fullspeed](#fullspeed)

## Introduction

Winnie-AFL is a fork of WinAFL that supports fuzzing using a fork()-like API.

> 笔者对 CSRSS 了解较少，目前没有能力分析到关键的部分，随意贴贴代码，以后有机会再来补充
> 

## Methodology

![f](./images/winnie/fork.png)

Fork 确实存在于 Windows 系统上，但[现有工作](https://gist.github.com/Cr4sh/126d844c28a7fbfd25c6)未能提供稳定的实现。

我们的 Windows fork 实现纠正了与 CSRSS 相关的问题，CSRSS 是控制 Windows 环境底层的用户模式进程，这个守护进程负责分配控制台窗口和关闭进程。如果进程未连接到 CSRSS，则在尝试访问 Win32 API时会崩溃。

对于分叉进程来说，连接到CSRSS并非易事：为了使调用成功，我们必须在子进程连接之前手动取消初始化几个未记录的变量。

![f](./images/winnie/fork_code.png)

1. 父进程使用适当的标志调用 NtCreateUserProcess，创建一个挂起的子进程，其中包含父地址空间的 CoW 副本（第 1 行）
2. 我们保持子进程挂起，直到父进程调用 CsrClientCallServer 通知 CSRSS 一个新进程已创建（第 12 行）。
3. 父级现在恢复子级，子级继续进行自我初始化（第 17 行）。 然后，父进程从 fork 中返回（第 14 行）。
4. 在子进程中，由于地址空间与父进程匹配，因此已经设置了几个对于新进程为零的全局变量（例如，ntdll.dll 中的 CsrServerApiRoutine）。 孩子必须通过将它们归零（第 18 行）手动取消初始化它们，以避免在下一步中崩溃。
5. 现在，孩子通过调用 CsrClientConnectToServer（第 20 行）连接到 CSRSS。 此步骤对于子进程正常运行至关重要。
6. CSRSS 最终确认新创建的进程和线程，子进程从 fork 返回（第21行）。

## Implementation

![f](./images/winnie/forkserver.png)

代理首先钩住 harness（target program）中的关键 function，一旦应用程序到达钩子，它就会停止，模糊代理会启动fork服务器。

### forkserver

- afl/forkserver.c: 拉起子进程并注入 agent.dll
    
    ```cpp
    CLIENT_ID spawn_child_with_injection(char* cmd, INJECTION_MODE injection_type, uint32_t timeout, uint32_t init_timeout)
    {
    	// 以 CREATE_SUSPENDED 创建子进程，现在还不能注入，需要等进程完成初始化，所以之后会在其到达 entrypoint 之后注入
    	start_process(cmd);
    	CONTEXT context;
    	context.ContextFlags = CONTEXT_INTEGER;
    	GetThreadContext(child_thread_handle, &context);
    	uintptr_t pebAddr;
    #ifdef _WIN64
    	// peb 地址初始保存在 rdx 中
    	pebAddr = context.Rdx;
    	ReadProcessMemory(child_handle, (PVOID)(pebAddr + 0x10), &base_address, sizeof(base_address), NULL);
    #else
    	pebAddr = context.Ebx;
    	ReadProcessMemory(child_handle, (PVOID)(pebAddr + 8), &base_address, sizeof(base_address), NULL);
    #endif
    	debug_printf("  PEB=0x%p, Base address=0x%p\n", pebAddr, base_address);
    	// 解析 pe 文件，获得 EP
    	uintptr_t oep = get_entry_point(binary_name);
    	debug_printf("  Binname: %s, OEP: %p\n", binary_name, oep);
    
    	uintptr_t pEntryPoint = oep + base_address;
    	if (!pEntryPoint)
    	{
    		dank_perror("GetEntryPoint");
    	}
    	debug_printf("  Entrypoint = %p\n", pEntryPoint);
    
    	// 把 EP patch 为无限循环
    	DWORD dwOldProtect;
    	VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    	BYTE oepBytes[2];
    	ReadProcessMemory(child_handle, (PVOID)pEntryPoint, oepBytes, 2, NULL);
    	WriteProcessMemory(child_handle, (PVOID)pEntryPoint, "\xEB\xFE", 2, NULL);
    	FlushInstructionCache(child_handle, (PVOID)pEntryPoint, 2);
    	ResumeThread(child_thread_handle);
    
    	// 等到程序执行到 EP
    	for (int i = 0; context.INSTRUCTION_POINTER != pEntryPoint; Sleep(100))
    	{
    		if (++i > 50)
    		{
    			FATAL("Entrypoint trap trimed out: the forkserver injection failed, or the target process never reached its entrypoint.\n");
    		}
    		context.ContextFlags = CONTEXT_CONTROL;
    		GetThreadContext(child_thread_handle, &context);
    	}
    	debug_printf("  Entrypoint trap hit, injecting the dll now!\n");
    	SuspendThread(child_thread_handle);
    
    	// 通过 pid 来构建管道名称
    	DWORD pid = GetProcessId(child_handle);
    	debug_printf("  PID is %d\n", pid);
    	afl_pipe = alloc_printf(AFL_FORKSERVER_PIPE "-%d", pid);
    
    	debug_printf("  Pipe name: %s\n", afl_pipe);
    
    	// CreateRemoteThread 将 agent 注入到目标
    	char* injectedDll = FORKSERVER_DLL;
    	char szDllFilename[MAX_PATH];
    	GetModuleFileNameA(NULL, szDllFilename, sizeof(szDllFilename));
    	PathRemoveFileSpecA(szDllFilename);
    	strncat(szDllFilename, "\\", max(0, MAX_PATH - strlen(szDllFilename) - 1));
    	strncat(szDllFilename, injectedDll, max(0, MAX_PATH - strlen(szDllFilename) - 1));
    	debug_printf("  Injecting %s\n", szDllFilename);
    	hModule = InjectDll(child_handle, szDllFilename);
    	if (!hModule)
    	{
    		FATAL("InjectDll");
    	}
    	debug_printf("  Forkserver dll injected, base address = %p\n", hModule);
    
    	// 很长一段都是把参数信息传递给 agent
    	HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
    	BYTE* lpBase = NULL;
    	PIMAGE_NT_HEADERS ntHeader = map_pe_file(szDllFilename, (LPVOID*)&lpBase, &hMapping, &hFile);
    	if (!ntHeader)
    		FATAL("Failed to parse PE header of %s", injectedDll);
    
    	DWORD off_fuzzer_settings = get_proc_offset((char*)lpBase, "fuzzer_settings");
    	DWORD off_forkserver_state = get_proc_offset((char*)lpBase, "forkserver_state");
    	DWORD off_call_target = get_proc_offset((char*)lpBase, "call_target");
    
    	if (!off_fuzzer_settings || !off_call_target)
    		FATAL("Fail to locate forkserver exports!\n");
    	debug_printf("  fuzzer_settings offset = %08x, call_target offset = %08x\n", off_fuzzer_settings, off_call_target);
    
    	size_t nWritten;
    	pFuzzer_settings = (LPVOID)((uintptr_t)hModule + off_fuzzer_settings);
    	pForkserver_state = (LPVOID)((uintptr_t)hModule + off_forkserver_state);
    	pCall_offset = (LPVOID)((uintptr_t)hModule + off_call_target);
    	debug_printf("  fuzzer_settings = %p, forkserver_state = %p, call target = %p\n", pFuzzer_settings, pForkserver_state, pCall_offset);
    
    	LPVOID pCovInfo;
    	if (use_fullspeed) // Fullspeed mode
    	{
    		LPVOID pModuleNames;
    		{
    			size_t module_names_size;
    			cov_modules_list module_names = serialize_coverage_modules(&module_names_size);
    			pModuleNames = VirtualAllocEx(child_handle, NULL, module_names_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    			if (!pModuleNames)
    			{
    				dank_perror("Allocating coverage modules list into child");
    			}
    			if (!WriteProcessMemory(child_handle, pModuleNames, module_names, module_names_size, &nWritten) || nWritten < module_names_size)
    			{
    				dank_perror("Writing coverage modules list into child");
    			}
    			free(module_names);
    		}
    		size_t cov_info_size;
    		AFL_COVERAGE_INFO* cov_info = serialize_breakpoints(pModuleNames, &cov_info_size);
    		pCovInfo = VirtualAllocEx(child_handle, NULL, cov_info_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    		if (!pCovInfo)
    		{
    			dank_perror("Allocating basic blocks list into child");
    		}
    		if (!WriteProcessMemory(child_handle, pCovInfo, cov_info, cov_info_size, &nWritten) || nWritten < cov_info_size)
    		{
    			dank_perror("Writing basic blocks list into child");
    		}
    		free(cov_info);
    	}
    	else if (use_intelpt)
    	{
    		// Intelpt mode uses external tracing for coverage
    		pCovInfo = NULL;
    	}
    	else
    	{
    		FATAL("Unsupported coverage mode");
    	}
    
    	AFL_SETTINGS fuzzer_settings;
    	strncpy(fuzzer_settings.harness_name, options.fuzz_harness, sizeof(fuzzer_settings.harness_name));
    	strncpy(fuzzer_settings.minidump_path, options.minidump_path, sizeof(fuzzer_settings.minidump_path));
    	fuzzer_settings.timeout = timeout;
    	fuzzer_settings.mode = injection_type;
    	fuzzer_settings.cov_info = pCovInfo;
    	fuzzer_settings.enableWER = options.enable_wer;
    	fuzzer_settings.cpuAffinityMask = cpu_aff;
    	fuzzer_settings.debug = options.debug_mode;
    	if (!WriteProcessMemory(child_handle, pFuzzer_settings, &fuzzer_settings, sizeof(AFL_SETTINGS), &nWritten) || nWritten < sizeof(AFL_SETTINGS))
    	{
    		dank_perror("Writing fuzzer settings into child");
    	}
    	
    	if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
    	if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
    	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    
    	// 参数复制完毕，告诉 agent 完成 forkserver 初始化
    	FORKSERVER_STATE ready = FORKSERVER_READY;
    	if (!WriteProcessMemory(child_handle, pForkserver_state, &ready, sizeof(FORKSERVER_STATE), &nWritten) || nWritten < sizeof(FORKSERVER_STATE))
    	{
    		dank_perror("Writing fuzzer settings into child");
    	}
    
    	// afl_pipe 会在 agent 完成初始化后创建，等待 agent 完成初始化
    	debug_printf("Connecting to forkserver...\n");
    	DWORD timeElapsed = 0;
    	do
    	{
    		hPipeChild = CreateFileA(afl_pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    		if (hPipeChild == INVALID_HANDLE_VALUE)
    		{
    			if (GetLastError() == ERROR_FILE_NOT_FOUND)
    			{
    				Sleep(10);
    				timeElapsed += 10;
    				if (timeElapsed > init_timeout)
    				{
    					FATAL("Forkserver failed to initialize!\n");
    				}
    				continue;
    			}
    			dank_perror("CreateFileA");
    		}
    	} while (hPipeChild == INVALID_HANDLE_VALUE);
    	DWORD dwMode = PIPE_READMODE_MESSAGE;
    	if (!SetNamedPipeHandleState(hPipeChild, &dwMode, NULL, NULL))
    	{
    		dank_perror("SetNamedPipeHandleState");
    	}
    	debug_printf("Connected to forkserver\n");
    	debug_printf("Ok, the forkserver is ready. Resuming the main thread now.\n");
    
    	debug_printf("Entrypoint: %p | OEP stolen bytes: %02x %02x\n", pEntryPoint, oepBytes[0], oepBytes[1]);
    
    	// 恢复入口的原始字节，让目标得以开始执行
    	MEMORY_BASIC_INFORMATION memInfo;
    	VirtualQueryEx(child_handle, (PVOID)pEntryPoint, &memInfo, sizeof(memInfo));
    	if (memInfo.Protect & PAGE_GUARD) {
    		VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    		debug_printf("VirtualProtectEx : temporarily removed guard page on entrypoint\n");
    	}
    	WriteProcessMemory(child_handle, (PVOID)pEntryPoint, oepBytes, 2, NULL);
    	FlushInstructionCache(child_handle, (PVOID)pEntryPoint, 2);
    	DWORD trash;
    	VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2, dwOldProtect, &trash);
    	
    	return (CLIENT_ID){ child_handle, child_thread_handle };
    }
    ```
    
- injected-harness/dllmain.cpp 在目标侧管理模糊进程和 forkserver 的 agent
    
    首先初始化部分加载了用户提供的 harness.dll，这个 dll 主要是确定 forkserver 开始的地址。然后给这个地址设置 PAGE_GUARD，程序到达目标地址之后再跳转到初始化程序。
    
    ```cpp
    DWORD CALLBACK cbThreadStart(LPVOID hModule)
    {
    	// Create a console for printf
    	AllocConsole();
    	fuzzer_stdout = fopen("CONOUT$", "w+");
    	fuzzer_stdin = fopen("CONIN$", "r");
    	setvbuf(fuzzer_stdout, NULL, _IONBF, 0);
    	setvbuf(fuzzer_stdin, NULL, _IONBF, 0);
    	SetConsoleTitleA("Winnie -- Forkserver");
    
    	// 等待 afl 侧把参数拷贝过来
    	while (forkserver_state == FORKSERVER_NOT_READY)
    		Sleep(10);
    
    	MemoryBarrier();
    	
    	switch(fuzzer_settings.mode)
    	{
    	case DRYRUN:
    		report_coverage = afl_report_coverage;
    		report_crashed = afl_report_crashed;
    		report_end = afl_report_end;
    		fuzzer_printf("Forkserver loaded - dryrun mode\n");
    		break;
    	case FORK:
    		report_coverage = fork_report_coverage;
    		report_crashed = fork_report_crashed;
    		report_end = fork_report_end;
    		fuzzer_printf("Forkserver loaded - forkserver mode\n");
    		break;
    	case PERSISTENT:
    		report_coverage = afl_report_coverage;
    		report_crashed = afl_report_crashed;
    		report_end = persistent_report_end;
    		fuzzer_printf("Forkserver loaded - persistent mode\n");
    		break;
    	default:
    		FATAL("Invalid fuzzer mode");
    	}
    
    	// Get the name of pipe/event
    	DWORD pid = GetCurrentProcessId();
    	fuzzer_printf("Forkserver PID: %d\n", pid);
    	snprintf(afl_pipe, sizeof(afl_pipe), AFL_FORKSERVER_PIPE "-%d", pid);
    	debug_printf("afl_pipe: %s\n", afl_pipe);
    	
    	SYSTEM_INFO sys_info = { 0 };
    	GetSystemInfo(&sys_info);
    	DWORD cpu_core_count = sys_info.dwNumberOfProcessors;
    
    	if (fuzzer_settings.mode == FORK) {
    		snprintf(forkserver_child_pipe, sizeof(forkserver_child_pipe), "\\\\.\\pipe\\forkserver-children-%d", pid);
    		childCpuAffinityMask = ~fuzzer_settings.cpuAffinityMask & ((1ULL << cpu_core_count) - 1ULL);
    	}
    
    	fuzzer_printf("Timeout: %dms\n", fuzzer_settings.timeout);
    	fuzzer_printf("Minidumps (WER): %s\n", fuzzer_settings.enableWER ? "enabled" : "disabled");
    	fuzzer_printf("Processor affinity: 0x%llx (%d cores)\n", fuzzer_settings.cpuAffinityMask, cpu_core_count);
    	if (fuzzer_settings.enableWER) {
    		fuzzer_printf("Will look for minidumps in %s\n", fuzzer_settings.minidump_path);
    	}
    
    	if (!SetProcessAffinityMask(GetCurrentProcess(), fuzzer_settings.cpuAffinityMask)) {
    		FATAL("Failed to set process affinity");
    	}
    	
    	// 装载用户的 harness.dll，内部会填充 target_method 和 fuzz_iter_func
    	fuzzer_printf("Loading harness: %s\n", fuzzer_settings.harness_name);
    	hHarness = LoadLibraryA((LPSTR) fuzzer_settings.harness_name);
    	if (!hHarness)
    	{
    		FATAL("Failed to load harness");
    	}
    	harness_info = (PHARNESS_INFO) GetProcAddress(hHarness, HARNESS_INFO_PROC);
    	if (!harness_info)
    	{
    		FATAL("Missing harness info block!");
    	}
    
    	fuzzer_printf("Waiting for the harness...\n");
    	// 等待 harnees.dll 执行完毕
    	while (!(harness_info->ready))
    		Sleep(10);
    
    	MemoryBarrier();
    
    	target_address = (BYTE*)harness_info->target_method;
    	fuzz_iter_address = harness_info->fuzz_iter_func;
    	fuzzer_printf("Target address: 0x%p | Iter address: 0x%p\n", target_address, fuzz_iter_address);
    
        // Network fuzzing mode
    	if (harness_info->network == TRUE) {
    		// ...
    	}
    
    	// 用 PAGE_GUARD 保护目标地址，从而可以捕获执行到目标地址
    	MEMORY_BASIC_INFORMATION targetPageInfo;
    	DWORD dwOldProtect;
    	VirtualQuery(target_address, &targetPageInfo, sizeof(targetPageInfo));
    	VirtualProtect(target_address, 1, targetPageInfo.Protect | PAGE_GUARD, &dwOldProtect);
    
    	// get NtCreateFile address
    	pCreateFile = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
    
    	// get TerminateProcess address
    	pTerminateProcess = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");
    	pRtlExitUserProcess = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExitUserProcess");
    
    	pNtProtectVirtualMemory = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    	pRtlAddVectoredExceptionHandler = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddVectoredExceptionHandler");
    
    	// 在 SuperEarlyExceptionHandler 中捕获 target address 是否到达
    	GetSystemInfo(&systemInfo); // get the page size
    	superEarlyHandler = AddVectoredExceptionHandler(TRUE, SuperEarlyExceptionHandler);
    	// 一些为了保证成功捕获 target address 的细节
    	fuzzer_printf("Early hooking critical functions...\n");
    	InlineHook(pNtProtectVirtualMemory, MyNtProtectVirtualMemory, (PVOID*)& pOrgNtProtectVirtualMemory, THUNK_SIZE);
    	InlineHook(pRtlAddVectoredExceptionHandler, MyRtlAddVectoredExceptionHandler, (PVOID*)& pOrgRtlAddVectoredExceptionHandler, THUNK_SIZE);
    	fuzzer_printf("-> OK!\n");
    
    	// 告诉 afl 准备好了，让其恢复程序执行
    	hPipeAfl = CreateNamedPipeA(afl_pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    	if (hPipeAfl == INVALID_HANDLE_VALUE)
    	{
    		FATAL("CreateNamedPipe");
    	}
    
    	fuzzer_printf("Connecting to AFL and returning control to main binary!\n");
    	fflush(fuzzer_stdout);
    
    	if (!ConnectNamedPipe(hPipeAfl, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) // This will block!
    	{
    		FATAL("ConnectNamedPipe");
    	}
    
    	return 0;
    }
    ```
    
    程序执行到 target address 后会跳转到 harness_main() 执行，调用 forkserver() 完成 forkserver 的创建。forkserver() 内部也是一个循环，不断接受 afl 的命令，完成 fork 子进程使用样例执行的过程。
    
    ```cpp
    _declspec(noreturn) void forkserver()
    {
    	SetupChildPipe();
    	
    	fuzzer_printf("Okay, spinning up the forkserver now.\n");
    
    	// forkserver
    	int forkCount = 0;
    	int done = false;
    	PROCESS_INFORMATION curChildInfo = {0};
    	int childPending = 0;
    	while (!done)
    	{
    		AFL_FORKSERVER_REQUEST aflRequest;
    		DWORD nRead;
    		if (!ReadFile(hPipeAfl, &aflRequest, sizeof(aflRequest), &nRead, NULL) || nRead != sizeof(aflRequest))
    		{
    			FATAL("Broken AFL pipe, ReadFile (forkserver)");
    		}
    		switch (aflRequest.Operation)
    		{
    		case AFL_CREATE_NEW_CHILD: {
    			trace_printf("Fuzzer asked me to create new child\n");
    			if (childPending)
    			{
    				FATAL("Invalid request; a forked child is already standby for execution");
    			}
    			forkCount++;
    			curChildInfo = do_fork();
    			AFL_FORKSERVER_RESULT aflResponse;
    			aflResponse.StatusCode = AFL_CHILD_CREATED;
    			aflResponse.ChildInfo.ProcessId = curChildInfo.dwProcessId;
    			aflResponse.ChildInfo.ThreadId = curChildInfo.dwThreadId;
    			DWORD nWritten;
    			if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
    			{
    				FATAL("Broken AFL pipe, WriteFile");
    			}
    			childPending = 1;
    			break;
    		}
    		case AFL_RESUME_CHILD: {
    			if (!childPending)
    			{
    				FATAL("Invalid request; no forked child to resume");
    			}
    			trace_printf("Fuzzer asked me to resume the child\n");
    			// Wait for the forked child to suspend itself, then we will resume it. (In order to synchronize)
    			while (1) {
    				DWORD exitCode = 0;
    				// If the fork fails somehow, the child will unexpectedly die without suspending itself.
    				if (!GetExitCodeProcess(curChildInfo.hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
    					fuzzer_printf("The forked child died before we resumed it! Exit code: %d\n", exitCode);
    					suicide();
    				}
    				DWORD dwWaitResult = WaitForSingleObject(curChildInfo.hThread, 0);
    				if (dwWaitResult == WAIT_OBJECT_0) { // Thread object is signaled -- thread died
    					fuzzer_printf("The forked child thread died before we resumed it!\n");
    					suicide();
    				}
    				DWORD dwResult = ResumeThread(curChildInfo.hThread);
    				if (dwResult == (DWORD)-1)
    					FATAL("Failed to resume the child");
    				if (dwResult == 0) { // Hasn't suspended itself yet
    					Sleep(1);
    					continue;
    				}
    				else if (dwResult == 1)
    					break;
    				else
    					FATAL("Unexpected suspend count %d", dwResult);
    			}
    			AFL_FORKSERVER_RESULT aflResponse;
    			CHILD_FATE childStatus = do_parent(curChildInfo); // return child's status from parent.
    			CloseHandle(curChildInfo.hProcess);
    			CloseHandle(curChildInfo.hThread);
    			RtlZeroMemory(&curChildInfo, sizeof(curChildInfo));
    			switch (childStatus)
    			{
    			case CHILD_SUCCESS:
    				aflResponse.StatusCode = AFL_CHILD_SUCCESS;
    				break;
    			case CHILD_CRASHED:
    				aflResponse.StatusCode = AFL_CHILD_CRASHED;
    				break;
    			case CHILD_TIMEOUT:
    				aflResponse.StatusCode = AFL_CHILD_TIMEOUT;
    				break;
    			default:
    				FATAL("Child exited in an unexpected way?");
    			}
    			DWORD nWritten;
    			if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
    			{
    				FATAL("Broken AFL pipe, WriteFile");
    			}
    			childPending = 0;
    			break;		
    		}
    		case AFL_TERMINATE_FORKSERVER:
    			debug_printf("Fuzzer asked me to kill the forkserver\n");
    			done = true;
    			break;
    		}
    	}
    
    	DisconnectNamedPipe(hPipeChild);
    	DisconnectNamedPipe(hPipeAfl);
    	CloseHandle(hPipeAfl);
    	CloseHandle(hPipeChild);
    	fuzzer_printf("Bye.\n");
    	suicide();
    }
    ```
    
- forklib/fork.cpp: fork 调用的实现部分
    
    > 对 CSRSS 不太了解，以后再来补充，现在就感受代码吧。
    > 
    
    ```cpp
    extern "C" DWORD fork(LPPROCESS_INFORMATION lpProcessInformation) {
    	printf("FORKLIB: Before the fork, my pid is %d\n", GetProcessId(GetCurrentProcess()));
    
    	PS_CREATE_INFO procInfo;
    	RtlZeroMemory(&procInfo, sizeof(procInfo));
    	HANDLE hProcess = NULL;
    	HANDLE hThread = NULL;
    	procInfo.Size = sizeof(PS_CREATE_INFO);
    
    #ifndef _WIN64
    	// WTF???? Discard *BIZARRE* segfault in ntdll from read fs:[0x18] that you can ignore???
    	LPTOP_LEVEL_EXCEPTION_FILTER oldFilter = SetUnhandledExceptionFilter(DiscardException);
    #endif
    
    	// This is the part that actually does the forking. Everything else is just
    	// to clean up after the mess that's created afterwards
    	NTSTATUS result = NtCreateUserProcess(
    		&hProcess, &hThread,
    		MAXIMUM_ALLOWED, MAXIMUM_ALLOWED,
    		NULL,
    		NULL,
    		PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT | PROCESS_CREATE_FLAGS_INHERIT_HANDLES, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
    		NULL,
    		&procInfo,
    		NULL);
    
    #ifndef _WIN64
    	// Clear the exception handler installed earlier.
    	SetUnhandledExceptionFilter(oldFilter);
    #endif
    
    	if (!result)
    	{
    		// Parent process
    		printf("FORKLIB: I'm the parent\n");
    		printf("FORKLIB: hThread = %p, hProcess = %p\n", hThread, hProcess);
    		printf("FORKLIB: Thread ID = %x\n", GetThreadId(hThread));
    		printf("FORKLIB: Result = %d\n", result);
    
    		// Not needed??
    		if (!NotifyCsrssParent(hProcess, hThread))
    		{
    			printf("FORKLIB: NotifyCsrssParent failed\n");
    			TerminateProcess(hProcess, 1);
    			return -1;
    		}
    
    		if (lpProcessInformation)
    		{
    			lpProcessInformation->hProcess = hProcess;
    			lpProcessInformation->hThread = hThread;
    			lpProcessInformation->dwProcessId = GetProcessId(hProcess);
    			lpProcessInformation->dwThreadId = GetThreadId(hThread);
    		}
    
    		ResumeThread(hThread); // allow the child to connect to Csr.
    		return GetProcessId(hProcess);
    	}
    	else
    	{
    		// Child process
    		FreeConsole();
    		// Remove these calls to improve performance, at the cost of losing stdio.
    #ifdef _DEBUG
    		AllocConsole();
    		SetStdHandle(STD_INPUT_HANDLE, stdin);
    		SetStdHandle(STD_OUTPUT_HANDLE, stdout);
    		SetStdHandle(STD_ERROR_HANDLE, stderr);
    #endif
    		printf("I'm the child\n");
    
    		if (!ConnectCsrChild())
    		{
    			DebugBreak();
    			ExitProcess(1);
    		}
    
    #ifdef _DEBUG
    		// Not safe to do fopen until after ConnectCsrChild
    		ReopenStdioHandles();
    #endif
    		
    		return 0;
    	}
    }
    ```
    
    ```cpp
    BOOL NotifyCsrssParent(HANDLE hProcess, HANDLE hThread)
    {
    	PROCESS_BASIC_INFORMATION info;
    	if (!NT_SUCCESS(NtQueryInformationProcess(hProcess,
    		ProcessBasicInformation, &info,
    		sizeof(info), 0))) {
    		printf("FORKLIB: NtQueryInformationProcess failed!\n");
    		return FALSE;
    	}
    
    	BOOL bIsWow64;
    	if (!IsWow64Process(GetCurrentProcess(), &bIsWow64))
    	{
    		printf("FORKLIB: IsWow64Process failed!\n");
    		return FALSE;
    	}
    
    	NTSTATUS result;
    	if (bIsWow64)
    	{
    		CSR_API_MSG64 csrmsg;
    		RtlZeroMemory(&csrmsg, sizeof(csrmsg));
    		csrmsg.CreateProcessRequest.PebAddressNative = (ULONGLONG)info.PebBaseAddress;
    		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    		csrmsg.CreateProcessRequest.ProcessHandle = (ULONGLONG)hProcess;
    		csrmsg.CreateProcessRequest.ThreadHandle = (ULONGLONG)hThread;
    		csrmsg.CreateProcessRequest.ClientId.UniqueProcess = GetProcessId(hProcess);
    		csrmsg.CreateProcessRequest.ClientId.UniqueThread = GetThreadId(hThread);
    		//result = CsrClientCallServer64(&csrmsg, NULL, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess), sizeof(csrmsg.CreateProcessRequest));
    	}
    	else
    	{
    		CSR_API_MSG csrmsg;
    		RtlZeroMemory(&csrmsg, sizeof(csrmsg));
    		csrmsg.CreateProcessRequest.PebAddressNative = info.PebBaseAddress;
    #ifdef _WIN64
    		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    #else
    		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    #endif
    		csrmsg.CreateProcessRequest.ProcessHandle = hProcess;
    		csrmsg.CreateProcessRequest.ThreadHandle = hThread;
    		csrmsg.CreateProcessRequest.ClientId.UniqueProcess = (HANDLE)GetProcessId(hProcess);
    		csrmsg.CreateProcessRequest.ClientId.UniqueThread = (HANDLE)GetThreadId(hThread);
    		//result = CsrClientCallServer(&csrmsg, NULL, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess), sizeof(csrmsg.CreateProcessRequest));
    	}
    
    	/*
    	if (!NT_SUCCESS(result))
    	{
    		printf("CsrClientCallServer(BasepCreateThread) failed!\n");
    		return FALSE;
    	}
    	*/
    
    	printf("FORKLIB: Successfully notified Csr of child!\n");
    	return TRUE;
    }
    ```
    
    ```cpp
    BOOL ConnectCsrChild()
    {
    	BOOL bIsWow64;
    	if (!IsWow64Process(GetCurrentProcess(), &bIsWow64))
    	{
    		printf("FORKLIB: IsWow64Process failed!\n");
    		return FALSE;
    	}
    
    	// Zero Csr fields???
    	// Required or else Csr calls will crash
    	printf("FORKLIB: De-initialize ntdll csr data\n");
    	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    #ifdef _WIN64
    	void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRva_x64); // HARDCODED OFFSET, see csrss_offsets.h
    	printf("FORKLIB: Csr data = %p\n", pCsrData);
    	memset(pCsrData, 0, csrDataSize_x64);
    #else
    	void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRva_x86); // HARDCODED OFFSET,  see csrss_offsets.h
    	printf("FORKLIB: Csr data = %p\n", pCsrData);
    	memset(pCsrData, 0, csrDataSize_x86);
    
    	if (bIsWow64)
    	{
    		DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
    		printf("FORKLIB: ntdll 64 = %llx\n", ntdll64);
    		char mem[csrDataSize_wow64];
    		memset(mem, 0, sizeof(mem));
    		DWORD64 pCsrData64 = ntdll64 + csrDataRva_wow64; // HARDCODED OFFSET, see csrss_offsets.h
    		printf("FORKLIB: Csr data 64 = %llx\n", ntdll64);
    		setMem64(pCsrData64, mem, sizeof(mem));
    	}
    #endif
    
    	DWORD session_id;
    	wchar_t ObjectDirectory[100];
    	ProcessIdToSessionId(GetProcessId(GetCurrentProcess()), &session_id);		
    	swprintf(ObjectDirectory, 100, L"\\Sessions\\%d\\Windows", session_id);		
    	printf("FORKLIB: Session_id: %d\n", session_id);
    
    	// Not required?
    	printf("FORKLIB: Link Console subsystem...\n");
    	void* pCtrlRoutine = (void*)GetProcAddress(GetModuleHandleA("kernelbase"), "CtrlRoutine");
    	BOOLEAN trash;
    	//if (!NT_SUCCESS(CsrClientConnectToServer(L"\\Sessions\\" CSRSS_SESSIONID L"\\Windows", 1, &pCtrlRoutine, 8, &trash)))
    	if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, 1, &pCtrlRoutine, 8, &trash)))
    	{
    		printf("FORKLIB: CsrClientConnectToServer failed!\n");
    		return FALSE;
    	}
    
    	printf("FORKLIB: Link Windows subsystem...\n");
    	// passing &gfServerProcess is not necessary, actually? passing &trash is okay?
    	char buf[0x240]; // this seem to just be all zero everytime?
    	memset(buf, 0, sizeof(buf));
    	//if (!NT_SUCCESS(CsrClientConnectToServer(L"\\Sessions\\" CSRSS_SESSIONID L"\\Windows", 3, buf, 0x240, &trash)))
    	if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, 3, buf, 0x240, &trash)))
    	{
    		printf("FORKLIB: CsrClientConnectToServer failed!\n");
    		return FALSE;
    	}
    
    	printf("FORKLIB: Connect to Csr...\n");
    	if (!NT_SUCCESS(RtlRegisterThreadWithCsrss()))
    	{
    		printf("FORKLIB: RtlRegisterThreadWithCsrss failed!\n");
    		return FALSE;
    	}
    
    	printf("FORKLIB: Connected to Csr!\n");
    	return TRUE;
    }
    ```
    

### fullspeed