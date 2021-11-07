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
- [Compilation](#compilation)
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
    type            TYPE
    ninsn            bytesize8[insns, int32]
    insns            ptr64[in, bpf_instructions]
    license            ptr64[in, string[bpf_licenses]]
    loglev            int32
    logsize            len[log, int32]
    log            ptr64[out, array[int8], opt]
    kern_version        flags[bpf_kern_version, int32]
    flags            flags[bpf_prog_load_flags, int32]
    prog_name        array[const[0, int8], BPF_OBJ_NAME_LEN]
    prog_ifindex        ifindex[opt]
    expected_attach_type    ATTACH_TYPE
    btf_fd            fd_btf[opt]
    func_info_rec_size    const[BPF_FUNC_INFO_SIZE, int32]
    func_info        ptr64[in, bpf_func_info]
    func_info_cnt        len[func_info, int32]
    line_info_rec_size    const[BPF_LINE_INFO_SIZE, int32]
    line_info        ptr64[in, bpf_line_info]
    line_info_cnt        len[line_info, int32]
    attach_btf_id        BTF_ID
    attach_prog_fd        PROG_FD
}

type bpf_prog bpf_prog_t[flags[bpf_prog_type, int32], flags[bpf_attach_type, int32], bpf_btf_id[opt], fd_bpf_prog[opt]]
```

重点关注一下结构体中的 insns 字段，其直接决定了 bpf_prog 的行为。这里实用了 union 来表示这个类型，代表这里设计了两种生成方式，一种是生成任意数量任意类型的 raw；一种是基于特定模板生成指令的 framed。前者显然是比较粗糙的方法，而后者需要编写者对系统调用的使用方法有认知。bpf_framed_program 被设计为一个结构体，可以保证生成的 insns 包含 initr0，body 和 exit 三个部分。**在这里如果编写更细致的规则就可以使得生成的 insns 拥有更丰富的语义。**

```
bpf_instructions [
    raw    array[bpf_insn]
    framed    bpf_framed_program
] [varlen]

bpf_insn [
    generic    bpf_insn_generic
    ldst    bpf_insn_ldst
    alu    bpf_insn_alu
    jmp    bpf_insn_jmp
    call    bpf_insn_call_helper
    func    bpf_insn_call_func
    exit    bpf_insn_exit
    initr0    bpf_insn_init_r0
    map    bpf_insn_map
    map_val    bpf_insn_map_value
    btf_id    bpf_insn_btf_id
] [varlen]

bpf_framed_program {
    initr0    bpf_insn_init_r0
    body    array[bpf_insn]
    exit    bpf_insn_exit
} [packed]
```

## Compilation

解析手工编写的描述文件（.txt），生成机器可用形式的规则文件（.go）的过程被称为 Description compilation。其包含两个步骤，官方文档描述的很详细，这里直接摘抄过来：
1. The first step is extraction of values of symbolic constants from kernel sources using syz-extract utility. syz-extract generates a small C program that includes kernel headers referenced by include directives, defines macros as specified by define directives and prints values of symbolic constants. Results are stored in .const files, one per arch. For example, sys/linux/dev_ptmx.txt is translated into sys/linux/dev_ptmx.txt.const.
2. The second step is translation of descriptions into Go code using syz-sysgen utility (the actual compiler code lives in pkg/ast and pkg/compiler). This step uses syscall descriptions and the const files generated during the first step and produces instantiations of Syscall and Type types defined in prog/types.go. You can see an example of the compiler output for Akaros in sys/akaros/gen/amd64.go. This step also generates some minimal syscall metadata for C++ code in executor/syscalls.h.

### syz-extract internals

使用 syz-extract 的一般方式如下

```
make bin/syz-extract
bin/syz-extract -os $OS -arch $ARCH -sourcedir $KSRC -builddir $LINUXBLD <new>.txt
```

进入 main 函数后首先会调用 flag.Parse() 解析参数，根据指定的 subsystem 和 arch 找到对应的配置，定位到包含所有该架构下系统调用描述文件的目录。做了一些准备和检查的工作后，会启用多个线程分别对指定的所有架构进行处理。

```
func main(){
    ...
    jobC := make(chan interface{}, len(archArray)*len(files))
    for _, arch := range arches {
        jobC <- arch
    }

    for p := 0; p < runtime.GOMAXPROCS(0); p++ {
        go worker(extractor, jobC)
    }
    ...
}
```

提取常量的步骤分为两步：
1. 对于每一个指定的架构，会首先调用 processArch() 提取出所有的常量；
2. 对于每一个指定的描述文件，会调用 processFile() 来确定常量的具体数值。

这里采用了生产者消费者的工作模式，除了 main() 函数中会往 jobC 里加入 arch 作为 job 之外，在每个 arch 处理结束后会把 file 加入 jobC 中。

```
func worker(extractor Extractor, jobC chan interface{}) {
    for job := range jobC {
        switch j := job.(type) {
        case *Arch:
            infos, err := processArch(extractor, j)
            j.err = err
            close(j.done)
            if j.err == nil {
                for _, f := range j.files {
                    f.info = infos[filepath.Join("sys", j.target.OS, f.name)]
                    jobC <- f
                }
            }
        case *File:
            j.consts, j.undeclared, j.err = processFile(extractor, j.arch, j)
            close(j.done)
        }
    }
}
```

processArch() 的过程主要包含三个步骤：
1. ParseGlob() 解析 .txt 文件。
2. ExtractConsts() 提取出所有的常量。
3. prepareArch()

```
func processArch(extractor Extractor, arch *Arch) (map[string]*compiler.ConstInfo, error) {
	errBuf := new(bytes.Buffer)
	eh := func(pos ast.Pos, msg string) {
		fmt.Fprintf(errBuf, "%v: %v\n", pos, msg)
	}
	top := ast.ParseGlob(filepath.Join("sys", arch.target.OS, "*.txt"), eh)
	if top == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	infos := compiler.ExtractConsts(top, arch.target, eh)
	if infos == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	if err := extractor.prepareArch(arch); err != nil {
		return nil, err
	}
	return infos, nil
}
```

ParseGlob() 基本上是按原样把描述文件 .txt 中的规则解析为了一种 in-memory 的表示 Node 到一个数组中存储。主要流程会通过 ParseGlob()->Parse()->p.parseTopRecover()->p.parseTop() 处理。这一步主要是确定规则语句所对应语法的内置类型，parseTop() 根据扫描到的不同类型的 token，按照对应的方式解析生成对应类型的实例 Node。这一步还没有展开 syscall 中的参数，没有递归生成 AST。例如 bpf$PROG_LOAD 的第二个参数 arg ptr[in, bpf_prog]，解析结果只说明了是一个名为 arg，类型为有两个参数 [in, bpf_prog] 的 ptr 类型。

```
func (p *parser) parseTop() Node {
	switch p.tok {
	case tokNewLine:
		return &NewLine{Pos: p.pos}
	case tokComment:
		return p.parseComment()
	case tokDefine:
		return p.parseDefine()
	case tokInclude:
		return p.parseInclude()
	case tokIncdir:
		return p.parseIncdir()
	case tokResource:
		return p.parseResource()
	case tokIdent:
		name := p.parseIdent()
		if name.Name == "type" {
			return p.parseTypeDef()
		}
		switch p.tok {
		case tokLParen:
			return p.parseCall(name)
		case tokLBrace, tokLBrack:
			return p.parseStruct(name)
		case tokEq:
			return p.parseFlags(name)
		default:
			p.expect(tokLParen, tokLBrace, tokLBrack, tokEq)
		}
	case tokIllegal:
		// Scanner has already producer an error for this one.
		panic(errSkipLine)
	default:
		p.expect(tokComment, tokDefine, tokInclude, tokResource, tokIdent)
	}
	panic("not reachable")
}

```

ExtractConsts() 以第二个参数为 nil 调用 Compile() （这里注意一下，syz-sysgen() 核心也是调用到 Compile()，只不过第二个参数 consts 会传入 syz-extract 生成的结果。这里第二个参数不同，几乎是两条不同的路径）。对于 consts 传入 nil 的情况，Compile() 只是调用 comp.extracConsts() 来完成具体的提取常量的过程。
### syz-sysgen internals

## Grammar in fuzzing

### analyze
### Generate
### Mutate
### minimize
### validate, 

## References
- [https://xz.aliyun.com/t/5098](https://xz.aliyun.com/t/5098)