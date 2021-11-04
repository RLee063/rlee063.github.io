---
layout: post
category: source_read
title: "syzkaller internals: grammar system"
---

作为 API fuzzer，syzkaller 有一套自己的 [syscall descriptions](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)，你也可以在这里查看其[语法](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md)。

本文简要分析 syzkaller 整个语法系统的实现细节，包括描述文件（.txt）的解析、规则文件（.go）的生成和使用、内存中 AST 的结构以及 generate 和 mutate 的实现等。希望对和我一样的初学者能有帮助，便于自己编写描述文件异或是对语法系统进行改进。

本文假设读者已经阅读上面两篇官方文档；如无特殊说明，后文均以 linux amd64 下 bpf 相关 syscall （尤其是 bpf$PROG_LOAD）作为例子。

## TOC
- [Syntax](#syntax)
- [Compilation](#Compilation)
- [Grammar in fuzzing](#grammar-in-fuzzing)

## Syntax

语法规则的描述，官方文档里已经写的非常详细，这里不再赘述。下面通过官方仓库中对 bpf$PROG_LOAD syscall 的描述作为实例学习如何编写描述文件。

系统调用的描述基本就是把模板从 C 翻译为 syscall description syntax，因为返回值作为 fd 会被其他系统调用使用，所以需要为其创建一个 resource。

```
int bpf(int cmd[BPF_PROG_LOAD], union bpf_attr *attr, unsigned int size);
---
resource fd_bpf_prog[fd]
bpf$PROG_LOAD(cmd const[BPF_PROG_LOAD], arg ptr[in, bpf_prog], size len[arg]) fd_bpf_prog
```

原系统调用中 attr 作为 union 类型，描述文件中为了方便直接为其创建了一个对应的结构体类型。（不过这里为啥要用 Type Templates ？）

```
type bpf_prog_t[TYPE, ATTACH_TYPE, BTF_ID, PROG_FD] {
	type			TYPE
	ninsn			bytesize8[insns, int32]
	insns			ptr64[in, bpf_instructions]
	license			ptr64[in, string[bpf_licenses]]
	loglev			int32
	logsize			len[log, int32]
	log			ptr64[out, array[int8], opt]
	kern_version		flags[bpf_kern_version, int32]
	flags			flags[bpf_prog_load_flags, int32]
	prog_name		array[const[0, int8], BPF_OBJ_NAME_LEN]
	prog_ifindex		ifindex[opt]
	expected_attach_type	ATTACH_TYPE
	btf_fd			fd_btf[opt]
	func_info_rec_size	const[BPF_FUNC_INFO_SIZE, int32]
	func_info		ptr64[in, bpf_func_info]
	func_info_cnt		len[func_info, int32]
	line_info_rec_size	const[BPF_LINE_INFO_SIZE, int32]
	line_info		ptr64[in, bpf_line_info]
	line_info_cnt		len[line_info, int32]
	attach_btf_id		BTF_ID
	attach_prog_fd		PROG_FD
}

type bpf_prog bpf_prog_t[flags[bpf_prog_type, int32], flags[bpf_attach_type, int32], bpf_btf_id[opt], fd_bpf_prog[opt]]
```

重点关注一下结构体中的 insns 字段，其直接决定了 bpf_prog 的行为。这里实用了 union 来表示这个类型，代表这里设计了两种生成方式，一种是生成任意数量任意类型的 raw；一种是基于特定模板生成指令的 framed。前者显然是比较粗糙的方法，而后者需要编写者对系统调用的使用方法有认知。bpf_framed_program 被设计为一个结构体，可以保证生成的 insns 包含 initr0，body 和 exit 三个部分。**在这里如果编写更细致的规则就可以使得生成的 insns 拥有更丰富的语义。**

```
bpf_instructions [
	raw	array[bpf_insn]
	framed	bpf_framed_program
] [varlen]

bpf_insn [
	generic	bpf_insn_generic
	ldst	bpf_insn_ldst
	alu	bpf_insn_alu
	jmp	bpf_insn_jmp
	call	bpf_insn_call_helper
	func	bpf_insn_call_func
	exit	bpf_insn_exit
	initr0	bpf_insn_init_r0
	map	bpf_insn_map
	map_val	bpf_insn_map_value
	btf_id	bpf_insn_btf_id
] [varlen]

bpf_framed_program {
	initr0	bpf_insn_init_r0
	body	array[bpf_insn]
	exit	bpf_insn_exit
} [packed]
```

## Compilation

解析手工编写的描述文件（.txt），生成机器可用形式的规则文件（.go）的过程被称为 Description compilation。其包含两个步骤，官方文档描述的很详细，这里直接摘抄过来：
1. The first step is extraction of values of symbolic constants from kernel sources using syz-extract utility. syz-extract generates a small C program that includes kernel headers referenced by include directives, defines macros as specified by define directives and prints values of symbolic constants. Results are stored in .const files, one per arch. For example, sys/linux/dev_ptmx.txt is translated into sys/linux/dev_ptmx.txt.const.
2. The second step is translation of descriptions into Go code using syz-sysgen utility (the actual compiler code lives in pkg/ast and pkg/compiler). This step uses syscall descriptions and the const files generated during the first step and produces instantiations of Syscall and Type types defined in prog/types.go. You can see an example of the compiler output for Akaros in sys/akaros/gen/amd64.go. This step also generates some minimal syscall metadata for C++ code in executor/syscalls.h.

### syz-extract internals

| placeholder

comp.extractConsts() 里用一个 for 循环遍历 parseGlobs() 解析出的 Node 数组，分别从 Define、Call、Struct、Int 等 Node 类型中提取出引用的常数名称。此外 syscall name 也会作为常数被放到 consts 数组中；且对于每个描述文件中 Include 和 Incdir 类型的 Node ，其指示了定义该描述文件涉及常量的文件和目录，所以其对应的路径也会被分别记录下来，帮助后面获得常量的具体数值；Define 宏定义类型的 Node 也会被记录。

```
func (comp *compiler) extractConsts() map[string]*ConstInfo {
	infos := make(map[string]*constInfo)
	for _, decl := range comp.desc.Nodes {
		pos, _, _ := decl.Info()
		info := getConstInfo(infos, pos)
		switch n := decl.(type) {
		case *ast.Include:
			info.includeArray = append(info.includeArray, n.File.Value)
		case *ast.Incdir:
			info.incdirArray = append(info.incdirArray, n.Dir.Value)
		case *ast.Define:
			v := fmt.Sprint(n.Value.Value)
			switch {
			case n.Value.CExpr != "":
				v = n.Value.CExpr
			case n.Value.Ident != "":
				v = n.Value.Ident
			}
			name := n.Name.Name
			if _, builtin := comp.builtinConsts[name]; builtin {
				comp.error(pos, "redefining builtin const %v", name)
			}
			info.defines[name] = v
			comp.addConst(infos, pos, name)
		case *ast.Call:
			if comp.target.SyscallNumbers && !strings.HasPrefix(n.CallName, "syz_") {
				comp.addConst(infos, pos, comp.target.SyscallPrefix+n.CallName)
			}
			for _, attr := range n.Attrs {
				if callAttrs[attr.Ident].HasArg {
					comp.addConst(infos, attr.Pos, attr.Args[0].Ident)
				}
			}
		case *ast.Struct:
			for _, attr := range n.Attrs {
				if structOrUnionAttrs(n)[attr.Ident].HasArg {
					comp.addConst(infos, attr.Pos, attr.Args[0].Ident)
				}
			}
		}
		switch decl.(type) {
		case *ast.Call, *ast.Struct, *ast.Resource, *ast.TypeDef:
			comp.extractTypeConsts(infos, decl)
		}
	}
	comp.desc.Walk(ast.Recursive(func(n0 ast.Node) {
		if n, ok := n0.(*ast.Int); ok {
			comp.addConst(infos, n.Pos, n.Ident)
		}
	}))
	return convertConstInfo(infos)
}
```

prepareArch() 在 extractConsts() 基本就结束返回到 worker() 函数继续执行，遍历参数中给出的描述文件名称，按 filename 从 infos 数组中提取对应的 info，把处理好的 file job 放入 jobC，下一个消费者线程获得该 job 后就会调用 processFile() 对其进行处理。

processFile() 内部通过 extractor.processFile() 调用到具体操作系统的接口实现。在 linux 中，常量的数值是借助 gcc 编译器来确定的。

processFile() 首先根据上一步提取的 Incdirs 构建编译选项，然后进入到 extract() -> compile() 执行。compile() 中首先调用 srcTemplate.Execute() ，根据提供的常量标识符、Define 宏定义和 include 文件，通过模板生成确定常量的 C 语言代码，再使用 gcc 编译生成二进制文件，最后返回到 extract() 执行二进制文件获得所有常量标识符对应的数值。

```
func (*linux) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	if strings.HasSuffix(info.File, "_kvm.txt") &&
		(arch.target.Arch == targets.ARM || arch.target.Arch == targets.RiscV64) {
		// Hack: KVM is not supported on ARM anymore. We may want some more official support
		// for marking descriptions arch-specific, but so far this combination is the only
		// one. For riscv64, KVM is not supported yet but might be in the future.
		// Note: syz-sysgen also ignores this file for arm and riscv64.
		return nil, nil, nil
	}
	headerArch := arch.target.KernelHeaderArch
	sourceDir := arch.sourceDir
	buildDir := arch.buildDir
	args := []string{
		// This makes the build completely hermetic, only kernel headers are used.
		"-nostdinc",
		"-w", "-fmessage-length=0",
		"-O3", // required to get expected values for some __builtin_constant_p
		"-I.",
		"-D__KERNEL__",
		"-DKBUILD_MODNAME=\"-\"",
		"-I" + sourceDir + "/arch/" + headerArch + "/include",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-malta",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-generic",
		"-I" + buildDir + "/include",
		"-I" + sourceDir + "/include",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + sourceDir + "/include/uapi",
		"-I" + buildDir + "/include/generated/uapi",
		"-I" + sourceDir,
		"-I" + sourceDir + "/include/linux",
		"-I" + buildDir + "/syzkaller",
		"-include", sourceDir + "/include/linux/kconfig.h",
	}
	args = append(args, arch.target.CFlags...)
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+sourceDir+"/"+incdir)
	}
	if arch.includeDirs != "" {
		for _, dir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+dir)
		}
	}
	params := &extractParams{
		AddSource:      "#include <asm/unistd.h>",
		ExtractFromELF: true,
		TargetEndian:   arch.target.HostEndian,
	}
	cc := arch.target.CCompiler
	res, undeclared, err := extract(info, cc, args, params)
	if err != nil {
		return nil, nil, err
	}
	if arch.target.PtrSize == 4 {
		// mmap syscall on i386/arm is translated to old_mmap and has different signature.
		// As a workaround fix it up to mmap2, which has signature that we expect.
		// pkg/csource has the same hack.
		const mmap = "__NR_mmap"
		const mmap2 = "__NR_mmap2"
		if res[mmap] != 0 || undeclared[mmap] {
			if res[mmap2] == 0 {
				return nil, nil, fmt.Errorf("%v is missing", mmap2)
			}
			res[mmap] = res[mmap2]
			delete(undeclared, mmap)
		}
	}
	return res, undeclared, nil
}

func compile(cc string, args []string, data *CompileData) (string, []byte, error) {
	src := new(bytes.Buffer)
	if err := srcTemplate.Execute(src, data); err != nil {
		return "", nil, fmt.Errorf("failed to generate source: %v", err)
	}
	binFile, err := osutil.TempFile("syz-extract-bin")
	if err != nil {
		return "", nil, err
	}
	args = append(args, []string{
		"-x", "c", "-",
		"-o", binFile,
		"-w",
	}...)
	if data.ExtractFromELF {
		args = append(args, "-c")
	}
	cmd := osutil.Command(cc, args...)
	cmd.Stdin = src
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binFile)
		return "", out, err
	}
	return binFile, nil, nil
}
```

srcTemplate.Execute() 模板样例如下（考虑未定义 ExtractFromELF），根据上一步解析的 Includes 数组引入对应的头文件，再根据 Defines 数组写上所有的宏定义。在 main() 函数中，把所有需要确定数值的变量标识符写入 vals 数组，再用一个 for 循环输出所有数值，在编译期间 gcc 会从头文件中查找出所有的常量的数值并进行替换，运行编译所得到的程序即可得到所有常量对应的数值。

```
#ifndef __GLIBC_USE
#	define __GLIBC_USE(X) 0
#endif

#include <uapi/linux/bpf.h>
#include <uapi/linux/btf.h>

{{range $name, $val := $.Defines}}
#ifndef {{$name}}
#	define {{$name}} {{$val}}
#endif
{{end}}

#ifndef BPF_ABS0
#	define BPF_ABS0 BPF_ABS >> 5
#endif

#ifndef BPF_ADD0
#	define BPF_ADD0 BPF_ADD >> 4
#endif

#ifndef BPF_AND0
#	define BPF_AND0 BPF_AND >> 4
#endif

...

#ifndef BPF_ARSH0
#	define BPF_ARSH0 BPF_ARSH >> 4
#endif

int main() {
	int i;
	unsigned long long vals[] = {
            (unsigned long long)BPF_ABS0,
            (unsigned long long)BPF_ADD0,
            (unsigned long long)BPF_ALU,
            (unsigned long long)BPF_ALU64,
            (unsigned long long)BPF_AND0,
            ...
	};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}

```

worker() 运行结束后返回到 main() 函数，将结果写入 .txt.const 文件，样例如下，主要也就是常量和 syscall 系统调用号。

```
# Code generated by syz-sysgen. DO NOT EDIT.
arches = 386, amd64, arm, arm64, mips64le, ppc64le, riscv64, s390x
BPF_ABS0 = 1
BPF_ADD0 = 0
BPF_ALU = 4
BPF_ALU64 = 7
...
__NR_bpf = 280
```

### syz-sysgen internals

| 突然觉得这个系列写得有点无聊，等有想法再回来继续吧。

## Grammar in fuzzing

| todo

### analyze
### Generate
### Mutate
### minimize
### validate