---
layout: post
category: write_up
title: "[dc29q] tiamat writeup"
---

[题目传送门](https://archive.ooo/c/tiamat/401/)



## TOC
- [qemu-user 简介](#1-qemu-user-简介)
- [题目初分析](#2-题目初分析)
- [人类代码可读计划](#3-人类代码阅读计划)
- [程序逻辑分析](#4-程序逻辑分析)
- [找到 BUG](#5-找到-bug)
- [还原 License](#6-还原-license)
- [错误的道路](#7-错误的道路)
- [最后的 Flag](#8-最后的-flag)
- [参考](#参考)

## 1 qemu-user 简介

简单介绍一点本题所涉及的 qemu 相关知识，需要声明的是这一节不是对 qemu 的源码分析，仅仅包含 qemu-user 执行过程的一个概括，省略了大量 qemu 的细节，甚至很多地方为了方便理解本题表述并不准确。

![qemu-user2](images/tiamat/qemu-user.png)

图中黄底为比较重要的函数，整体的执行流程大概是：从 main 函数出发，执行一些初始化操作之后进入 `cpu_loop` 函数，`cpu_loop` 函数循环调用 `cpu_exec` 。`cpu_exec` 也包含一个循环，负责一条一条（并不准确）反汇编 guest 程序的指令、生成能够在 host 主机执行的代码，并执行所生成的代码。当 `cpu_exec` 遇到中断时，会返回到 `cpu_loop` 交由 `cpu_loop` 进行处理。

在 `cpu_exec` 函数内部更详细的调用过程如图所示，需要注意的有 3 个函数：

- `gen_intermedia_code`：负责反汇编 guest instruction，生成中间代码（TCG operations），通常被称作前端。
- `tcg_gen_code`：负责把中间代码转换为在 host 机器上执行的代码，通常被称作后端。
- `tcg_qemu_tb_exec`：负责调用执行由 `tcg_gen_code` 生成的 host 代码。这里是调试的关键点，在这里下断点就可以知道 guest 指令被翻译成了什么样的 host 指令。

举个例子对于 mips 指令 `sw $zero, 8($sp)` 其得到的 host 指令可能是这个样子的：

```c
void __fastcall sub_7FD9F8000100()
{
  CPUArchState_2 *cpu;

  if ( SLODWORD(cpu[-1].cp0_count_ns) >= 0 )
  {
    __writegsdword(cpu->active_tc.gpr[29] + 8, 0); // <= [0]
    cpu->active_tc.PC = (unsigned int)&unk_100D4;
  }
  __asm { vzeroupper }
}
```

CPUArchState 类型就是 qemu 模拟的 target cpu 架构。[0] 处的代码是主要生效的代码，其将 0 写入 29 号寄存器指向的地址 + 8 的位置（在 mips 中 29 号寄存器就是 $sp）。

## 2 题目初分析

题目总共给了七个文件，首先查看 Dockerfile ，除了把现有的文件复制过去之外还新增了几个文件：

- /flag：flag
- /lic：flag 的 md5
- /1.mz-f.mz：同样的内容 "STRANGE GAME\nTHE ONLY WINNING MOVE IS\nNOT TO PLAY.\n"

其他文件大致的意思就是执行 `/qemooo /liccheck.bin` ，于是理所应当将 liccheck.bin 丢进 IDA，但是出了一点问题。

![ida-xd](images/tiamat/ida-xd.png)

IDA 只能反汇编几条指令，结合 qemooo 这个文件名字可以猜到作者魔改了 qemu。好在 qemooo 是带符号的，这个时候可以在 Functions 窗口看到一些奇怪的单词：aarch64、riscv。难道说那些指令不是 mips 指令？有了上一节的扫盲，现在我们知道或许应该去 tb_gen_code() 里面看看 qemooo 是怎么反汇编这些指令的。

```c
arch_index = (pc - base_pc) >> 2;
      cpu->kvm_fd = tmap_arch[arch_index];
      v11 = (tmap_arch[arch_index] & 1) != 0;
      if ( tmap_arch[arch_index] && tmap_arch[arch_index] != 1 )
      {
        switch ( tmap_arch[arch_index] )
        {
          case 2u:
          case 3u:
            gen_intermediate_code_riscv(cpu, (TranslationBlock_2 *)tb, max_insns, v11);
            break;
          case 4u:
          case 5u:
            gen_intermediate_code_arm(cpu, (TranslationBlock_2 *)tb, max_insns, v11);
            break;
          case 6u:
          case 7u:
            gen_intermediate_code(cpu, (TranslationBlock_2 *)tb, max_insns, v11);
            break;
        }
      }
      else
      {
        gen_intermediate_code_sparc((CPUState_0 *)cpu, tb, max_insns, v11);
      }
```

芜湖，我们好像发现了关键。不过这个看起来可不太妙，四种架构 X 大小端切换，让我想起了上个月做的我师傅 `yype` 的 gatesXgame 。简单通过交叉引用确定了 tmap_arch 数组没有在其他地方被修改之后，将数组 dump 下来开始写一个简单的反汇编程序。

> 这里有个小地方可能需要注意下：capstone 得切换到 next 分支才能反汇编 riscv。
> 

## 3 人类代码阅读计划

```c
0x100d0:        [MIPS_LE]               sw      $zero, 8($sp)
0x100d4:        [MIPS_BE]               sw      $zero, 0xc($sp)
0x100d8:        [MIPS_LE]               sw      $zero, 0x14($sp)
0x100dc:        [MIPS_BE]               sw      $zero, 0x18($sp)
0x100e0:        [MIPS_LE]               sw      $zero, 0x1c($sp)
0x100e4:        [MIPS_BE]               sw      $zero, 0x20($sp)
0x100e8:        [ARM_LE]                add     r2, pc, #0x2f0
0x100ec:        [RISCV_LE]              addi    s11, sp, 0x700
0x100f0:        [RISCV_BE]              addi    s11, s11, 0x600
0x100f4:        [Sparc_LE]              add     %g1, 0xd00, %i7
0x100f8:        [RISCV_LE]              mv      a4, zero
```

Emmm，虽然确实成功了但是我不确实太认为这个能够帮助我们理解程序逻辑。至少我们可以给所有寄存器换一下名，或许 r0-r32 是更好的表示。这里需要去查找各种架构的寄存器对应关系，手册、capstone 源码都会有帮助。

```c
0x100d0:        [MIPS_LE]               sw      r0, 8(r29)
0x100d4:        [MIPS_BE]               sw      r0, 0xc(r29)
0x100d8:        [MIPS_LE]               sw      r0, 0x14(r29)
0x100dc:        [MIPS_BE]               sw      r0, 0x18(r29)
0x100e0:        [MIPS_LE]               sw      r0, 0x1c(r29)
0x100e4:        [MIPS_BE]               sw      r0, 0x20(r29)
0x100e8:        [ARM_LE]                add     r2, r15, 0x2f0
0x100ec:        [RISCV_LE]              addi    r27, r2, 0x700
0x100f0:        [RISCV_BE]              addi    r27, r27, 0x600
```

我觉得好些了，但我突然觉得还想更好一些，所以稍微修改了反汇编器输出类似高级语言的代码。（事实上我最开始想生成 C 代码丢给 IDA 帮忙分析，但是后面踩坑太多就放弃了 XD）

```c
MEM[sp + 0x8] = r0;                    //0x100d0       [MIPS_LE]
MEM[sp + 0xc] = r0;                    //0x100d4       [MIPS_BE]
MEM[sp + 0x14] = r0;                   //0x100d8       [MIPS_LE]
MEM[sp + 0x18] = r0;                   //0x100dc       [MIPS_BE]
MEM[sp + 0x1c] = r0;                   //0x100e0       [MIPS_LE]
MEM[sp + 0x20] = r0;                   //0x100e4       [MIPS_BE]
r2 = r15 + 0x2f0;                      //0x100e8       [ARM_LE]
r27 = r2 + 0x700;                      //0x100ec       [RISCV_LE]
r27 = r27 + 0x600;                     //0x100f0       [RISCV_BE]
r31 = r1 + 0xd00;                      //0x100f4       [Sparc_LE]
```

看起来可以大干一场了，但是初始化之后的第一条指令就有点奇怪，r15 寄存器是个啥？我一调试发现这条指令生成的 host 代码甚至没有访问 r15 寄存器，我一回头看最开始的汇编，发现这里是对 pc 寄存器的操作，所以我这里有个未验证的猜测，前端 gen_intermedia_code（或许是）在反汇编生成 TCG 的时候，可能会对一些特殊寄存器有特殊的操作，例如 pc 寄存器会被硬编码为当前 pc 的数值常量。

知道这个后继续往下走，调试没几步寄存器的变化又和预想的不一样了，测试了一下发现是 sparc 这一类指令的问题，所以我回到 `cpu_tb_exec`来确认寄存器映射的情况，发现 sparc 类指令的寄存器映射和手册上的不一致，例如对于指令 `add     %g1, 0xd00, %i7` 生成的 host 代码如下所示。按照手册上的说法 g1 对应 r1，但是这里却取了 r2 和 r3 的数值（_QWORD）；i7 应该对应 r31，却存到了一个不属于通用寄存器的内存，并且也是 64 位的操作。

```c
// 0x100f4: [Sparc_LE] add     %g1, 0xd00, %i7
*((_QWORD *)cpu->active_tc.regwptr + 23) = *(_QWORD *)&cpu->active_tc.gpr[2] + 3328LL;
```

对 sparc 类指令的寄存器对应关系进行进一步分析之后可以发现行为大致是这样：

- 首先对 sparc 类寄存器的操作不同于其他架构，它是 64 位的。
- 对于 o0-o7、l0-l7、i0-i7，其被映射到了不属于通用寄存器内存的一块地方（regwptr），可以把它看作是扩展 cpu 的扩展寄存器，在本文中用 eR0-eR46 表示，为了一致性（其实没必要）把它们都定义是 32 位寄存器，所以相当于 o0 映射到了 eR0、eR1 两个 32 位寄存器。
- 对于 g0-g7，他们被映射到了 r0-r15，相当于 g0 映射到了 r0、r1 两个寄存器。

> 这里按理要修改一下反汇编器生成类似 (rx, rx) = (rx, rx) op (rx, rx) 类型的代码，但是我粗略看了一下，sparc 指令执行后高位的寄存器都是没有被使用的，所以我做题的时候偷了个懒只是把这个点记在脑子里，然后还是把 g0 映射到了 r0，给后面留下了一个隐患。
> 

几乎是最后，我们还需要为系统调用确定调用约定。本题中四种架构都有涉及系统调用的指令，前面提到过，在遇到中断的时候 qemu 会返回到 `cpu_loop` 进行处理，在 `cpu_loop` 中可以找到类似下面的调用：

```c
retv = do_syscall(//riscv
                   env,
                   env->active_tc.gpr[17] + 500,
                   env->active_tc.gpr[10],
                   env->active_tc.gpr[11],
                   env->active_tc.gpr[12],
                   env->active_tc.gpr[13],
                   env->active_tc.gpr[14],
                   env->active_tc.gpr[15],
                   0,
                   0);
        if ( retv == -512 )
        {
          env->active_tc.PC -= 4;
        }
        else if ( retv != -513 )
        {
          env->active_tc.gpr[10] = retv;
        }
```

找到所有的调用然后还原出所有的调用约定：

```c
r10 = ecall(r17,r10,r11,r12,r13,r14,r15);   //riscv
eR0 = ta(eR0, eR2, eR4, eR6, eR8, eR10);    //sparc
r0 = svc(r0,r1,r2,r3,r4,r5);                //arm
r2 = syscall(r2,r4,r5,r6,r7);               //mips
```

确定系统调用所对应的具体操作，还需要知道 syscall table。对于 syscall number，在 linux/Documentation/ABI/stable/syscalls 有写道："Note that this interface is different for every architecture that Linux supports. Please see the architecture-specific documentation for details on the syscall numbers that are to be mapped to each syscall."

所以对于不同的架构，我们需要在 qemu/linux-user/ 目录下面去寻找对应架构的 syscall table，用于确定系统调用所对应的具体操作，以便下一步程序执行逻辑的还原。这一步相当枯燥，且**相当容易出错**！

---

要生成一份准确的代码对我来说并非易事，除了上面提到的，还有一些细节需要注意，例如：

- sparc 的 dest 寄存器在最后一个操作数，而其他架构是第一个操作数。
- branch 类指令目标地址的确定，例如 riscv 的 j 指令和 mips 的 b 指令有所区别，b 是当前地址加上偏移，j 是当前地址减 4 加上偏移。
- call 类指令的特殊处理，作者为了恶心人用了两种方法来调用函数：jal 指令、手动存入返回地址到寄存器然后 jmp。retrun 指令也有两种表示：ret 指令，手动将寄存器赋值给 pc。最恶心的是有一个语义应该是 goto 的指令是用 call 来实现的。

## 4 程序逻辑分析

```c
      // Please ignore this, this is just a draft!
      if (r4 == r5) goto input_lic;           //0x10208
      r5 = r5 + 0x7;          //0x1020c
      // 'l'
      if (r4 == r5) goto game;            //0x10210
      r5 = r5 + 0x2;          //0x10214
      r1 = pc - 0x9c;         //0x10218
      // 'n'
      if (r4 == r5) get_random();         //0x1021c
      r5 = r5 + 0x2;          //0x10220
      if (r4 == r5) goto print_input;         //0x10224
      r5 = r5 + 0x2;          //0x10228
      if (r4 == r5) goto menu_loop;         //0x1022c
      r5 = r5 + 0x4;          //0x10230
      if (r4 == r5) goto check;           //0x10234
      goto faile_2;           //0x10238
```

有了上面的工作，我们可以比较轻松的着手分析程序的逻辑，不过这依旧是一个需要耐心的工作，特别是在我没有 IDA 帮助的情况下。我考虑过要不要给出分析过程，不过那样可能文章就太长了，在这里我只给出分析的结果。

程序是一个菜单题，初始化的时候主要会调用一个获得随机数的函数（见下面 'n' 对应的操作），之后就进入菜单选项。还原出来的选项和对应的操作如下：

- e：输入 input，并对 input 进行校验，要求值其在 ['0'-'f']。
- v：要求在输入 input 后调用。读入 license，用随机数对其进行异或加密，然后与 input 比较，若相同则输出 flag。（限制执行次数 0x8 ）
- n：从 /dev/random 读入四字节用于更新随机数，如果此时已经读入了 license，就用其对 license 进行异或加密。（限制执行次数 0x18）
- p：打印 input。
- joshua：打印一点没用的东西。
- l：对解题没有帮助的一个无聊的函数 XD。
- r：NOP。

在这一步确定全局变量寄存器以及内存数据的分布也很重要。

## 5 找到 BUG

### BUG1: r0 misuse

```c
print_input:
      r10 = mem[sp + 0x0];            //0x102b8
      r11 = r0 + 0x20;             //0x102bc  //real r0
      print_sth(r10, r11);         //0x102c0  // Leak here!
      goto menu_loop;         //0x102c4
```

’p‘ 操作对应的操作很短，实际有意义就三行，第一行将 input 的地址赋值给 r10 寄存器，第二行将 r0+0x20 赋值给 r11 寄存器，在 print_sth 函数中，r11 用来控制泄露的长度。通过上一节的分析可以知道加密后的 license 就存放在 input 后面，所以 r0 寄存器很可能可以控制然后用来泄露。

注意在 riscv 和 mips 中 r0 是 zero 寄存器，它和 pc 一样属于比较特殊的寄存器，（应该）会被直接翻译为常量 0，在程序中有很多 + zero 的无用操作来迷惑你。不过好在之前看到 pc 寄存器的时候就对 r0 寄存器留了一个心眼，我迅速定位了所有使用真 r0 寄存器的指令（所以我的反汇编代码里为什么不早点对 zero 特殊处理 XD），发现除了这条指令确实使用 r0 寄存器外，还有一个地方存在对 r0 寄存器的赋值。

```c
void get_random(){
      // ...
      r0 = open(r7, r0,r1,r2,r3,r4,r5);           //0x1063c
      // r0 = fd
      // open("/dev/random")
      // ...
      eR0 = read(r2, eR0, eR2, eR4, eR6, eR8, eR10);   //0x1065c
      // read(fd, , 0x4)
      // ...
      r2 = close(r2,r4,r5,r6,r7);         //0x10670
      // close(fd)
      r4 = MEM[sp + 0x4];         //0x10674
      r5 = (char)MEM[sp + 0xc];           //0x10678
      xor_lic();         //0x1067c
      return;
  }
```

赋值发生在 'n' 操作对应的 get_random 里，open 作为 svc 系统调用，返回值存到了 r0 寄存器里，后续返回到 menu_loop 之前也没有对 r0 寄存器的再赋值，意味着我们可以在 'n' 操作后马上调用 'p' 操作进行泄露。所以我们第一个 payload 就是 `"e"+"1"*0x20+"vnp"` ！

![strange-leak](images/tiamat/strange-leak.png)

### BUG2: syscall number misuse

芜湖，看起来我们已经摸到 flag 了！但是，等一下，为什么泄露了五个字节，fd 不是应该为 3 才对吗？再回头审计代码发现 'v' 操作里面读取 license 的时候，open 后没有 close，这确实会让 fd 加 1，但是只执行一次 ’v‘ 操作为什么 fd 会加 2？这里可以调试跟踪所有 open 和 close 系统调用的执行情况，最后会发现在 'n' 操作里，看似是 close 的操作其实根本没有执行 do_syscall，因为它传递了另一个架构的系统调用号！这里感受到了作者的恶意，在还原系统调用的时候真的很枯燥，看到 open、read 自然就觉得之后应该是 write。

> 事实上我在做题的时候没有发现这个漏洞，因为我还犯了另一个错误，我忘记在根目录创建 lic 文件，导致 'v' 操作的 open 不会成功，从而导致之后只能泄露出四个字节。
>

现在我们有两个可以让 fd 增加的函数，并且我们可以调用他们共计 0x20 次，加上 stdio 给我们贡献了 3 个文件描述符，足以让我们泄露所有的 license。是时候构建我们的第二个 payload： `"e"+"1"*32+"v"*7+"n"*0x16+"p"`

![leak-done](images/tiamat/leak-done.png)

## 6 还原 License

我们泄露的不是 license，是 license 与一个四字节随机数循环异或后的数值，不过这足以给我们很多信息了：异或是四字节进行的，意味着对于随机数的每一个字节，license 中都有 8 个字节都使用它来异或加密。而 license 每个字节取值区间为 [‘0‘-’f']，所以对于泄露的每个字节，可以确定一个长度为 16 的集合，包含了所有随机数字节可能的取值。而对于使用同一个随机数字节来加密的 8 个字节，这 8 个随机数字节集合得取个交集。这听起来可以把可能的 license 缩小到一个可以接受的范围，马上写一个脚本跑一下：

```
d64be88c7427f0255c5002f81a9350fb
d64ce88b7426f0245c5102f91a9250fc
c64bb88c0427a0252c5072f86a9320fb
c64cb88b0426a0242c5172f96a9220fc
764b688cd4275025fc50c2f8ba93f0fb
764c688bd4265024fc51c2f9ba92f0fc
064b188cc4272025ac50d2f8ea93a0fb
064c188bc4262024ac51d2f9ea92a0fc
```

OMG，难以相信真正的 license 就在这 8 字符串当中！我甚至可以接受手工测试的开销，我已经等不及了，我早就已经想好了怎么进行测试。

> 事实上我不确定这是否是预期解，因为对于其他的 flag，很可能候选的 license 数量在 3 位数以上，虽然暴力也花不了多少时间，但是总觉得有点奇怪。不过我确实知道有两个做出这道题的队伍也使用了这种解法。
> 

## 7 错误的道路

似乎我们只需要先输入 `ex...xvnp` 就可以泄露 `License ^ Rand0 ^ Rand1` 的数值，然后输入 `np` 就可以泄露 `License ^ Rand0 ^ Rand1 ^ Rand2` 的数值，两个泄露的数值异或就可以得到 `Rand2` 的数值。 `Rand2` 是最新的随机数，校验函数将用它来异或 License 然后与我们的输入做比较，那我们使用 Rand2 来异或我们可能的 Licese，将其输入然后调用验证函数，如果是正确的 License 就可以通过校验输出 `flag` 了？

我激动地写完脚本，然后发现所有的 License 全部校验失败。在确定正确的 License 一定在之中后，我突然意识到，输入的时候要求所有字符都是在 `'0'-'f'`！怎么可能？这意味着输入一定是正确的 License，但是与输入比较的数据是与随机数异或之后的 License。难道说有办法让读入的 License 不被随机数异或？

## 8 最后的 Flag

这个时候马上就想起来了，随机数是存在 r15 寄存器里的，虽然之前检查过所有对 r15 寄存器赋值的语句，但是遗漏了一点，sparc 的指令在对 r14 寄存器赋值的时候会把 r15 清零！所以我立马搜索所有对 r14 赋值的语句，最后在 `joshua` 操作里找到了它。

```c
joshua:
      //...
      r14 = eR44 + 0x14;          //0x10310
      eR2 = r14;          //0x10314
      eR4 = 0x6;          //0x10318
      // write(1, "oshua\n", 6)
      eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10); //0x1031c
```

虽然 r14 被伪装成了一个传参的临时变量，但在这个没用的函数里面它就是显得那么的突兀。

所以，我们只需要很简单地在校验之前调用一次这个函数： `ed64be88c7427f0255c5002f81a9350fbjoshua\nv`

![final](images/tiamat/final.png)

## 参考

[https://dttw.tech/posts/HJ9TU7J_O](https://dttw.tech/posts/HJ9TU7J_O)

[https://github.com/o-o-overflow/dc2021q-tiamat-public](https://github.com/o-o-overflow/dc2021q-tiamat-public)

[https://github.com/o-o-overflow/qemooo](https://github.com/o-o-overflow/qemooo)
