---
layout: post
category: write_up
---

[题目传送门](https://archive.ooo/c/tiamat/401/)

## TOC
- [The start](#the-start)

## 1 qemu-user 简介

简单介绍一点本题所涉及的 qemu 相关知识，需要声明的是这一节不是对 qemu 的源码分析，仅仅包含 qemu-user 执行过程的一个概括，省略了大量 qemu 的细节，甚至很多地方为了方便理解本题表述并不准确。

![qemu-user](https://github.com/RLee063/rlee063.github.io/blob/master/_images/tiamat/qemu-user.png?raw=true)

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

## 2. 题目初分析

题目总共给了七个文件，首先查看 Dockerfile ，除了把现有的文件复制过去之外还新增了几个文件：

- /flag：flag
- /lic：flag 的 md5
- /1.mz-f.mz：同样的内容 "STRANGE GAME\nTHE ONLY WINNING MOVE IS\nNOT TO PLAY.\n"

其他文件大致的意思就是执行 `/qemooo /liccheck.bin` ，于是理所应当将 liccheck.bin 丢进 IDA，但是出了一点问题。

![ida-xd](https://github.com/RLee063/rlee063.github.io/blob/master/_images/tiamat/ida-xd.png?raw=true)

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

## 3. 人类代码阅读计划

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

## 4. 程序逻辑分析

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

## 4. 找到 BUG(s)

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

![strange-leak](https://github.com/RLee063/rlee063.github.io/blob/master/_images/tiamat/strange-leak.png?raw=true)

### BUG2: syscall number misuse

芜湖，看起来我们已经摸到 flag 了！但是，等一下，为什么泄露了五个字节，fd 不是应该为 3 才对吗？再回头审计代码发现 'v' 操作里面读取 license 的时候，open 后没有 close，这确实会让 fd 加 1，但是只执行一次 ’v‘ 操作为什么 fd 会加 2？这里可以调试跟踪所有 open 和 close 系统调用的执行情况，最后会发现在 'n' 操作里，看似是 close 的操作其实根本没有执行 do_syscall，因为它传递了另一个架构的系统调用号！这里感受到了作者的恶意，在还原系统调用的时候真的很枯燥，看到 open、read 自然就觉得之后应该是 write。

> 事实上我在做题的时候没有发现这个漏洞，因为我还犯了另一个错误，我忘记在根目录创建 lic 文件，导致 'v' 操作的 open 不会成功，从而导致之后只能泄露出四个字节。
>

现在我们有两个可以让 fd 增加的函数，并且我们可以调用他们共计 0x20 次，加上 stdio 给我们贡献了 3 个文件描述符，足以让我们泄露所有的 license。是时候构建我们的第二个 payload： `"e"+"1"*32+"v"*7+"n"*0x16+"p"`

![leak-done](https://github.com/RLee063/rlee063.github.io/blob/master/_images/tiamat/leak-done.png?raw=true)

## 5. 还原 license

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

## 6. 错误的道路

似乎我们只需要先输入 `ex...xvnp` 就可以泄露 `License ^ Rand0 ^ Rand1` 的数值，然后输入 `np` 就可以泄露 `License ^ Rand0 ^ Rand1 ^ Rand2` 的数值，两个泄露的数值异或就可以得到 `Rand2` 的数值。 `Rand2` 是最新的随机数，校验函数将用它来异或 License 然后与我们的输入做比较，那我们使用 Rand2 来异或我们可能的 Licese，将其输入然后调用验证函数，如果是正确的 License 就可以通过校验输出 `flag` 了？

我激动地写完脚本，然后发现所有的 License 全部校验失败。在确定正确的 License 一定在之中后，我突然意识到，输入的时候要求所有字符都是在 `'0'-'f'`！怎么可能？这意味着输入一定是正确的 License，但是与输入比较的数据是与随机数异或之后的 License。难道说有办法让读入的 License 不被随机数异或？

## 7. 最后的 Flag

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

![final](https://github.com/RLee063/rlee063.github.io/blob/master/_images/tiamat/final.png?raw=true)

## 参考

[https://dttw.tech/posts/HJ9TU7J_O](https://dttw.tech/posts/HJ9TU7J_O)

[https://github.com/o-o-overflow/dc2021q-tiamat-public](https://github.com/o-o-overflow/dc2021q-tiamat-public)

[https://github.com/o-o-overflow/qemooo](https://github.com/o-o-overflow/qemooo)

## EXP:

```python
#!/bin/python3

from capstone import *
import ipdb

tmap_arch = [0x06, 0x07, 0x06, 0x07, 0x06, 0x07, 0x04, 0x02, 0x03, 0x00, 0x02, 0x01, 0x00, 0x03, 0x06, 0x02, 0x07, 0x05, 0x06, 0x04, 0x03, 0x01, 0x07, 0x02, 0x06, 0x00, 0x03, 0x01, 0x05, 0x02, 0x07, 0x00, 0x06, 0x01, 0x07, 0x03, 0x00, 0x06, 0x02, 0x04, 0x01, 0x03, 0x00, 0x05, 0x02, 0x07, 0x01, 0x00, 0x06, 0x03, 0x01, 0x07, 0x00, 0x04, 0x01, 0x00, 0x01, 0x06, 0x02, 0x03, 0x00, 0x02, 0x01, 0x05, 0x00, 0x01, 0x03, 0x02, 0x07, 0x03, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x03, 0x04, 0x02, 0x06, 0x03, 0x07, 0x05, 0x02, 0x04, 0x03, 0x06, 0x02, 0x05, 0x03, 0x02, 0x04, 0x01, 0x00, 0x01, 0x07, 0x03, 0x00, 0x02, 0x01, 0x05, 0x03, 0x00, 0x01, 0x00, 0x06, 0x04, 0x02, 0x03, 0x07, 0x06, 0x01, 0x02, 0x00, 0x03, 0x07, 0x02, 0x01, 0x00, 0x06, 0x03, 0x02, 0x03, 0x05, 0x02, 0x03, 0x01, 0x02, 0x07, 0x04, 0x03, 0x06, 0x07, 0x02, 0x06, 0x07, 0x03, 0x02, 0x06, 0x03, 0x02, 0x05, 0x00, 0x04, 0x01, 0x00, 0x01, 0x00, 0x01, 0x03, 0x00, 0x07, 0x02, 0x05, 0x03, 0x01, 0x06, 0x02, 0x03, 0x02, 0x07, 0x00, 0x01, 0x06, 0x07, 0x03, 0x02, 0x06, 0x07, 0x03, 0x00, 0x02, 0x06, 0x03, 0x07, 0x04, 0x01, 0x06, 0x00, 0x05, 0x01, 0x00, 0x01, 0x07, 0x06, 0x02, 0x03, 0x02, 0x03, 0x02, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x02, 0x03, 0x01, 0x07, 0x02, 0x00, 0x01, 0x03, 0x06, 0x02, 0x03, 0x02, 0x03, 0x00, 0x02, 0x01, 0x00, 0x01, 0x04, 0x03, 0x05, 0x04, 0x02, 0x05, 0x03, 0x02, 0x00, 0x07, 0x01, 0x00, 0x01, 0x00, 0x01, 0x03, 0x06, 0x02, 0x03, 0x04, 0x07, 0x06, 0x07, 0x02, 0x06, 0x07, 0x06, 0x07, 0x06, 0x03, 0x02, 0x03, 0x02, 0x03, 0x02, 0x03, 0x02, 0x03, 0x02, 0x03, 0x02, 0x07, 0x06, 0x03, 0x05, 0x04, 0x02, 0x03, 0x02, 0x03, 0x00, 0x02, 0x03, 0x02, 0x03, 0x02, 0x07, 0x06, 0x01, 0x00, 0x07, 0x06, 0x07, 0x06, 0x01, 0x07, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x03, 0x07, 0x02, 0x03, 0x05, 0x01, 0x04, 0x02, 0x05, 0x04, 0x05, 0x06, 0x03, 0x02, 0x03, 0x02, 0x07, 0x06, 0x07, 0x06, 0x00, 0x04, 0x07, 0x03, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x02, 0x07, 0x01, 0x05, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x03, 0x02, 0x03, 0x02, 0x03, 0x04, 0x02, 0x07, 0x01, 0x05, 0x03, 0x00, 0x02, 0x01, 0x03, 0x00, 0x01, 0x04, 0x02, 0x05, 0x04, 0x05, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x01, 0x03, 0x02, 0x00, 0x07, 0x06, 0x07, 0x03, 0x02, 0x04, 0x06, 0x05, 0x01, 0x00, 0x04, 0x03, 0x07, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01, 0x00, 0x01, 0x00, 0x01, 0x02, 0x07, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x03, 0x07, 0x02, 0x06, 0x07, 0x03, 0x06, 0x02, 0x03, 0x02, 0x07, 0x06, 0x03, 0x02, 0x07, 0x03, 0x02, 0x06, 0x03, 0x07, 0x06, 0x07, 0x06, 0x02, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x01, 0x07, 0x06, 0x02, 0x03, 0x02, 0x03, 0x02, 0x03, 0x07, 0x06, 0x00, 0x05, 0x02, 0x07, 0x06, 0x07, 0x03, 0x04, 0x02, 0x03, 0x02, 0x05, 0x04, 0x03, 0x06, 0x01, 0x05, 0x07, 0x00, 0x06, 0x04, 0x07, 0x02, 0x06, 0x05, 0x07, 0x01, 0x06, 0x00, 0x01, 0x04, 0x03, 0x05, 0x00, 0x02, 0x04, 0x07, 0x03, 0x05, 0x04, 0x02, 0x06, 0x03, 0x02, 0x05, 0x04, 0x07, 0x05, 0x01, 0x00, 0x06, 0x01, 0x00, 0x07, 0x03, 0x06, 0x02, 0x04, 0x01, 0x07, 0x03, 0x00, 0x02, 0x03, 0x02, 0x01, 0x06, 0x05, 0x03, 0x00, 0x04, 0x01, 0x02, 0x00, 0x07, 0x03, 0x02, 0x05, 0x03, 0x01, 0x00, 0x02, 0x04, 0x03, 0x06, 0x02, 0x03, 0x05, 0x07, 0x02, 0x04, 0x01, 0x00, 0x06, 0x01, 0x07, 0x00, 0x01, 0x00, 0x05, 0x06, 0x01, 0x07, 0x06, 0x07, 0x03, 0x04, 0x06, 0x00, 0x02, 0x05, 0x04, 0x05, 0x03, 0x02, 0x04, 0x01, 0x00, 0x05, 0x01, 0x03, 0x00, 0x04, 0x05, 0x02, 0x04, 0x01, 0x00, 0x01, 0x03, 0x00, 0x01, 0x00, 0x02, 0x05, 0x04, 0x01, 0x07, 0x05, 0x00, 0x06, 0x01, 0x04, 0x05, 0x03, 0x07, 0x00, 0x02, 0x04, 0x01, 0x00, 0x01, 0x05, 0x00, 0x03, 0x04, 0x05, 0x04, 0x05, 0x02, 0x03, 0x06, 0x07, 0x01, 0x04, 0x02, 0x06, 0x05, 0x04, 0x07, 0x06, 0x03, 0x07, 0x00, 0x05, 0x06, 0x07, 0x02, 0x04, 0x01, 0x03, 0x02, 0x05, 0x06, 0x04, 0x07, 0x03, 0x06, 0x02, 0x05, 0x03, 0x04, 0x05, 0x07, 0x00, 0x02, 0x06, 0x07, 0x01, 0x04, 0x00, 0x03, 0x01, 0x05, 0x04, 0x00, 0x02, 0x01, 0x00, 0x01, 0x06, 0x00, 0x07, 0x05, 0x03, 0x04, 0x05, 0x01, 0x06, 0x07, 0x00, 0x06, 0x04, 0x07, 0x01, 0x05, 0x00, 0x02, 0x03, 0x02, 0x04, 0x01, 0x06, 0x05, 0x04, 0x07, 0x05, 0x04, 0x05, 0x04, 0x06, 0x03, 0x05, 0x00, 0x04, 0x02, 0x03, 0x02, 0x07, 0x05, 0x01, 0x03, 0x06, 0x07, 0x00, 0x04, 0x02, 0x03, 0x02, 0x05, 0x03, 0x02, 0x06, 0x04, 0x03, 0x02, 0x07, 0x05, 0x06, 0x07, 0x06, 0x07, 0x01, 0x00, 0x06, 0x04, 0x07, 0x03, 0x06, 0x05, 0x07, 0x01, 0x04, 0x00, 0x06, 0x01, 0x02, 0x00, 0x03, 0x05, 0x04, 0x05, 0x07, 0x01, 0x06, 0x02, 0x03, 0x07, 0x02, 0x04, 0x03, 0x00, 0x01, 0x05, 0x02, 0x00, 0x06, 0x07, 0x06, 0x04, 0x05, 0x01, 0x07, 0x00, 0x06, 0x01, 0x00, 0x07, 0x03, 0x01, 0x04, 0x06, 0x02, 0x05, 0x07, 0x04, 0x05, 0x03, 0x02, 0x00, 0x03, 0x06, 0x01, 0x07, 0x06, 0x02, 0x07, 0x06, 0x07, 0x03, 0x00, 0x02, 0x03, 0x04, 0x05, 0x04, 0x02, 0x01, 0x06, 0x03, 0x05, 0x04, 0x02, 0x03, 0x00, 0x02, 0x07, 0x06, 0x07, 0x06, 0x01, 0x00, 0x03, 0x05, 0x04, 0x05, 0x07, 0x01, 0x00, 0x06, 0x02, 0x04, 0x07, 0x03, 0x02, 0x06, 0x05, 0x01, 0x03, 0x04, 0x07, 0x00, 0x06, 0x02, 0x05, 0x04, 0x03, 0x05, 0x07, 0x02, 0x03, 0x02, 0x03, 0x06, 0x07, 0x04, 0x01, 0x02, 0x06, 0x03, 0x02, 0x05, 0x04, 0x07, 0x00, 0x03, 0x02, 0x01, 0x03, 0x02, 0x00, 0x05, 0x03, 0x02, 0x04, 0x03, 0x05, 0x02, 0x06, 0x03, 0x07, 0x06, 0x07, 0x01, 0x04, 0x00, 0x02, 0x01, 0x00, 0x06, 0x05, 0x01, 0x07, 0x00, 0x06, 0x01, 0x04, 0x00, 0x05, 0x01, 0x03, 0x00, 0x04, 0x05, 0x04, 0x01, 0x00, 0x05, 0x04, 0x01, 0x07, 0x05, 0x04, 0x00, 0x02, 0x05, 0x06, 0x07, 0x03, 0x02, 0x06, 0x07, 0x06, 0x04, 0x05, 0x07, 0x03, 0x06, 0x02, 0x03, 0x04, 0x07, 0x02, 0x06, 0x01, 0x05, 0x03, 0x02, 0x07, 0x06, 0x04, 0x03, 0x05, 0x00, 0x04, 0x05, 0x04, 0x07, 0x02, 0x06, 0x05, 0x03, 0x01, 0x07, 0x04, 0x05, 0x02, 0x00, 0x06, 0x03, 0x04, 0x07, 0x05, 0x01, 0x06, 0x07, 0x04, 0x00, 0x06, 0x05, 0x01, 0x04, 0x02, 0x00, 0x01, 0x00, 0x05, 0x04, 0x01, 0x07, 0x03, 0x02, 0x00, 0x01, 0x06, 0x07, 0x03, 0x05, 0x04, 0x00, 0x02, 0x03, 0x05, 0x06, 0x01, 0x07, 0x02, 0x04, 0x00, 0x03, 0x06, 0x07, 0x06, 0x07, 0x01, 0x06, 0x00, 0x01, 0x07, 0x06, 0x07, 0x05, 0x02, 0x06, 0x00, 0x01, 0x07, 0x06, 0x07, 0x00, 0x03, 0x02, 0x06, 0x07, 0x01, 0x04, 0x03, 0x05, 0x02, 0x03]

def byteswap(i32: bytes):
    a, b, c, d = i32
    return bytes([d, c, b, a])

def replace(ins_str:str, replace_dir):
    for i in reversed(replace_dir):
        if i in ins_str:
            ins_str = ins_str.replace(i, replace_dir[i])
    return ins_str

def get_op_str(insn:CsInsn, replace_reg):
    IMM = lambda x: hex(x.value.imm)
    # REG = lambda x: mips_reg[replace_reg[insn.reg_name(x.value.reg)]]
    REG = lambda x: replace_reg[insn.reg_name(x.value.reg)]
    # MEM_B = lambda x: mips_reg[replace_reg[insn.reg_name(x.value.mem.base)]]
    MEM_B = lambda x: replace_reg[insn.reg_name(x.value.mem.base)]
    MEM_D = lambda x: hex(x.mem.disp)
    import capstone.mips as mips
    # import capstone.arm as arm
    # import capstone.sparc as sparc
    # import capstone.riscv as riscv
    op_str = []
    for i in insn.operands:
        if i.type == mips.MIPS_OP_REG:
            op_str.append(REG(i))
        elif i.type == mips.MIPS_OP_IMM:
            op_str.append(IMM(i))
        elif i.type == mips.MIPS_OP_MEM:
            op_str.append(MEM_B(i))
            op_str.append(MEM_D(i))
    return op_str

# des_addr = [66176, 65924, 65928, 66696, 67084, 66572, 67212, 67088, 66832, 67576, 67228, 66724, 66980, 66216, 66988, 66488, 66236, 66748, 66112, 67016, 67020, 66380, 66252, 67024, 67032, 66908, 66400, 66916, 67432, 66800, 66552]
des_addr = set()
des_addr = [66176, 65924, 67080, 66568, 65928, 67208, 67084, 66696, 66828, 67576, 67228, 66720, 66976, 66212, 66988, 66484, 66232, 66108, 66748, 67012, 66376, 67016, 66248, 67020, 67028, 66904, 66396, 66908, 66912, 67428, 66796, 66548, 67572, 66552]

def parse_insn(insn:CsInsn, replace_reg, arch, _arch=0):
    # IMM = lambda x: hex(x.value.imm)
    # REG = lambda x: replace_reg[insn.reg_name(x.value.reg)]
    # A2I = lambda x: int(x[2:], base=16)
    def JMPTO(offset, add=4):
        des = int(offset,base=16)+add+insn.address
        # des_addr.add(des)
        return "L"+hex(des)

    # JMPTO = lambda x: hex(int(x, base=16)+4+insn.address)
    # from capstone.mips import *
    # import capstone.mips as m
    ops = get_op_str(insn, replace_reg)
    if arch == A_SPARC:
        # ipdb.set_trace()
        if len(ops) > 0:
            ops.insert(0, ops.pop())
    # ops = insn.operands
    code = insn.mnemonic
    # mips & arm & riscv & sparc
    if insn.address in des_addr and 1:
        print("\nL%s:" % hex(insn.address))
        pass
    if code in ["add", "addi", "addiu"]:
        insn_str = ("%s = %s + %s;" % (ops[0],ops[1],ops[2]))
    elif code == "sub":
        insn_str = ("%s = %s - %s;" % (ops[0],ops[1],ops[2]))
    elif code in ["ori", "or"]:
        insn_str = ("%s = %s | %s;" % (ops[0], ops[1], ops[2]))
    elif code == "xor":
        insn_str = ("%s = %s ^ %s;" % (ops[0], ops[1], ops[2]))
    elif code == "sw":
        insn_str = ("MEM[%s + %s] = %s;" % (ops[1], ops[2], ops[0]))
    elif code == "lw":
        insn_str = ("%s = MEM[%s + %s];" % (ops[0], ops[1], ops[2]))
    elif code == "sb":
        insn_str = ("MEM[%s + %s] = (char)%s;" % (ops[1], ops[2], ops[0]))
    elif code == "lb":
        insn_str = ("%s = (char)MEM[%s + %s];" % (ops[0], ops[1], ops[2]))
    elif code in ["move", "mov", "mv"]:
        insn_str = ("%s = %s;" % (ops[0], ops[1]))
    elif code == "lui":
        insn_str = ("%s = %s0000;" % (ops[0], ops[1]))
    elif code == "sethi":
        insn_str = ("%s = STR;")
    elif code == "cmp":
        insn_str = ("flag = %s - %s;" % (ops[0],ops[1]))
    elif code == "addne":
        insn_str = ("if (flag) %s = %s - %s;" % (ops[0],ops[1],ops[2]))
    elif code == "ret":
        insn_str = ("return;")
    elif code in ["syscall", "svc", "ecall", "ta"]:
        if code == "syscall":
            insn_str = ("r2 = syscall(r2,r4,r5,r6,r7);")
        elif code == "svc":
            insn_str = ("r0 = svc(r7, r0,r1,r2,r3,r4,r5);")
        elif code == "ecall":
            insn_str = ("r10 = ecall(r17,r10,r11,r12,r13,r14,r15);")
        elif code == "ta":
            insn_str = ("eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);")
    elif code == "nop":
        insn_str = ("")
    elif code == "b":
        # des_addr.add(int(ops[0], base=16))
        insn_str = ("goto L%s;" % ops[0])
    elif code == "j":
        insn_str = ("goto %s;" % JMPTO(ops[0], -4))
    elif code == "jal":
        insn_str = ("%s();" % JMPTO(ops[0], 0))
    elif code == "blez":
        insn_str = ("if (%s <= 0) goto %s;" % (ops[0], JMPTO(ops[1], 0)))
    elif code == "beqz":
        insn_str = ("if (%s == 0) goto %s;" % (ops[0], JMPTO(ops[1], 0)))
    elif code == "bnez":
        insn_str = ("if (%s != 0) goto %s;" % (ops[0], JMPTO(ops[1], 0)))
    elif code == "bne":
        insn_str = ("if (%s != %s) goto %s;" % (ops[0], ops[1], JMPTO(ops[2], 0)))
    elif code == "bge":
        insn_str = ("if (%s >= %s) goto %s;" % (ops[0], ops[1], JMPTO(ops[2], 0)))
    elif code == "beq":
        insn_str = ("if (%s == %s) goto %s;" % (ops[0], ops[1], JMPTO(ops[2], 0)))
    else:
        raise Exception(insn.mnemonic)
    print("%s\t\t\t//%s\t%s" % (insn_str, hex(insn.address), arch_name[_arch]))
    # print(insn.mnemonic, insn.op_str)
    # print()

with open("./liccheck.bin.text", "rb") as f:
    code = f.read()

replace_table = [
        # {"g0":"r0","g1":"r2","g2":"r4","g3":"r6","g4":"r8","g5":"r10","g6":"r12","g7":"r14","o0":"eR0","o1":"eR2","o2":"eR4","o3":"eR6","o4":"eR8","o5":"eR10","o6":"eR12","o7":"eR14","l0":"eR16","l1":"eR18","l2":"eR20","l3":"eR22","l4":"eR24","l5":"eR26","l6":"eR28","l7":"eR30","i0":"eR32","i1":"eR34","i2":"eR36","i3":"eR38","i4":"eR40","i5":"eR42","i6":"eR44","i7":"eR46","fp":"eR44","icc":""},
        {"g0":"r0","g1":"r1","g2":"r2","g3":"r3","g4":"r4","g5":"r5","g6":"r6","g7":"r7","o0":"r8","o1":"r9","o2":"r10","o3":"r11","o4":"r12","o5":"r13","o6":"r14","o7":"r15","l0":"r16","l1":"r17","l2":"r18","l3":"r19","l4":"r20","l5":"r21","l6":"r22","l7":"r23","i0":"r24","i1":"r25","i2":"r26","i3":"r27","i4":"r28","i5":"r29","i6":"r30","i7":"r31","fp":"r30","icc":"r30"},
        {"zero":"r0","ra":"r1","sp":"r2","gp":"r3","tp":"r4","t0":"r5","t1":"r6","t2":"r7","s0":"r8","s1":"r9","a0":"r10","a1":"r11","a2":"r12","a3":"r13","a4":"r14","a5":"r15","a6":"r16","a7":"r17","s2":"r18","s3":"r19","s4":"r20","s5":"r21","s6":"r22","s7":"r23","s8":"r24","s9":"r25","s10":"r26","s11":"r27","t3":"r28","t4":"r29","t5":"r30","t6":"r31"},
        {"#":"","r0":"r0","r1":"r1","r2":"r2","r3":"r3","r4":"r4","r5":"r5","r6":"r6","r7":"r7","r8":"r8","sb":"r9","sl":"r10","fp":"r11","ip":"r12","sp":"r13","lr":"r14","pc":"r15"},
        {"$":"","zero":"r0","at":"r1","v0":"r2","v1":"r3","a0":"r4","a1":"r5","a2":"r6","a3":"r7","t0":"r8","t1":"r9","t2":"r10","t3":"r11","t4":"r12","t5":"r13","t6":"r14","t7":"r15","s0":"r16","s1":"r17","s2":"r18","s3":"r19","s4":"r20","s5":"r21","s6":"r22","s7":"r23","t8":"r24","t9":"r25","k0":"r26","k1":"r27","gp":"r28","sp":"r29","fp":"r30","ra":"r31"}]

mips_reg = {"@":"","r0":"zero","r1":"at","r2":"v0","r3":"v1","r4":"a0","r5":"a1","r6":"a2","r7":"a3","r8":"t0","r9":"t1","r10":"t2","r11":"t3","r12":"t4","r13":"t5","r14":"t6","r15":"t7","r16":"s0","r17":"s1","r18":"s2","r19":"s3","r20":"s4","r21":"s5","r22":"s6","r23":"s7","r24":"t8","r25":"t9","r26":"k0","r27":"k1","r28":"gp","r29":"sp","r30":"fp","r31":"ra"}

arch_name = [
        "[Sparc_LE]\t",
        "[Sparc_BE]\t",
        "[RISCV_LE]\t",
        "[RISCV_BE]\t",
        "[ARM_LE]\t",
        "[ARM_BE]\t",
        "[MIPS_LE]\t",
        "[MIPS_BE]\t",
        ]

A_SPARC = 0
A_RISCV = 1
A_ARM = 2
A_MIPS = 3

sparc_le = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN|CS_MODE_V9)
sparc_be = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN|CS_MODE_V9)
riscv_le = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
riscv_be = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
arm_le = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN|CS_MODE_ARM)
arm_be = Cs(CS_ARCH_ARM, CS_MODE_BIG_ENDIAN|CS_MODE_ARM)
mips_le = Cs(CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN|CS_MODE_MIPS32)
mips_be = Cs(CS_ARCH_MIPS, CS_MODE_BIG_ENDIAN|CS_MODE_MIPS32)

mds = [sparc_le, sparc_be, riscv_le, riscv_be, arm_le, arm_be, mips_le, mips_be]
ops = [set(),set(),set(),set()]
for md in mds:
    md.detail = True

print("int ecall(int,int,int,int,int,int,int);")
print("int ta(int,int,int,int,int,int,int);")
print("int svc(int,int,int,int,int,int,int);")
print("int syscall(int,int,int,int,int);")
print("int %s;" % ",".join(["r"+str(i) for i in range(32)]))
print("int %s;" % ",".join(["eR"+str(i) for i in range(64)]))
print("char MEM[0x1024];")
print("int main(){")
for addr in range(0, len(code), 4):
    if addr > 0x1080c-0x100d0:
        break
    arch = tmap_arch[addr >> 2]
    do_big_endian = arch & 1
    code_current = code[addr:addr+0x4]
    if arch == 3 or arch == 0:
        code_current = byteswap(code_current)
    try:
        i = next(mds[arch].disasm(code_current, addr+0x100D0))
        if 1:
            # ins_str = "%s\t%s\t#0x%x" % (i.mnemonic,\
                    # replace(i.op_str, replace_table[arch//2]), i.address)
            # ins_str = "0x%x:\t%s\t%s\t%s" % (i.address, arch_name[arch], i.mnemonic,\
                    # i.op_str)
            # ins_str = "0x%x:\t%s\t%s\t%s" % (i.address, arch_name[arch], i.mnemonic,\
            #        replace(i.op_str, replace_table[arch//2]))
            # print(ins_str)
            parse_insn(i, replace_table[arch//2], arch//2, arch)
            # print()
        # ops[arch//2].add(i.mnemonic)
    except StopIteration:
        print("0x%x:\t%s\t[FUXK]" % (addr+0x100D0, arch_name[arch]))
print("}")
# print(des_addr)
# for i in ops:
#     print(i)
```

```cpp
# define size_t unsigned long long 
size_t ecall(size_t,size_t,size_t,size_t,size_t,size_t,size_t);
size_t ta(size_t,size_t,size_t,size_t,size_t,size_t,size_t);
size_t svc(size_t,size_t,size_t,size_t,size_t,size_t,size_t);
size_t syscall(size_t,size_t,size_t,size_t,size_t);
size_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17,r18,r19,r20,r21,r22,r23,r24,r25,r26,r27,r28,sp,r30,r31;
size_t eR0,eR1,eR2,eR3,eR4,eR5,eR6,eR7,eR8,eR9,eR10,eR11,eR12,eR13,eR14,eR15,eR16,eR17,eR18,eR19,eR20,eR21,eR22,eR23,eR24,eR25,eR26,eR27,eR28,eR29,eR30,eR31,eR32,eR33,eR34,eR35,eR36,eR37,eR38,eR39,eR40,eR41,eR42,eR43,eR44,eR45,eR46,eR47,eR48,eR49,eR50,eR51,eR52,eR53,eR54,eR55,eR56,eR57,eR58,eR59,eR60,eR61,eR62,eR63;
char MEM[0x1024];
void print_sth(r10){
    //0x105cc
    r0 = r0;			//0x105d0
    eR0 = 0x1;			//0x105d4
    eR2 = r10;			//0x105d8
    r12 = r11 + r0;			//0x105dc
    eR4 = r12;			//0x105e0
    r2 = 0x4;			//0x105e4
    eR0 = write(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x105e8
    r10 = r0 + 0x1;			//0x105ec
    r11 = r27;			//0x105f0
    r12 = r0 + 0x1;			//0x105f4
    r17 = r0 + 0x40;			//0x105f8
    r10 = write(r17,r10,r11,r12,r13,r14,r15);			//0x105fc
    r10 = 0x0;			//0x10600
    return;			//0x10604
};

void L0x105a0(){
    r9 = r0 + 0x0;			//0x105a0
    if (r5 == 0) goto L0x105c4;			//0x105a4
L0x105ac:
    if (r9 >= r5) goto L0x105c4;			//0x105a8
    r10 = r4 + r9;			//0x105ac
    r8 = MEM[r10 + 0x0];			//0x105b0
    r8 = r8 ^ r15;			//0x105b4
    MEM[r10 + 0x0] = r8;			//0x105b8
    r9 = r9 + 0x4;			//0x105bc
    goto L0x105ac;			//0x105c0

L0x105c4:
    return;			//0x105c4
}

void get_random(){
    //0x10608
    //0x1060c
    r0 = r0;			//0x10610
    r14 = r0 + r1;			//0x10614
    r2 = eR28;			//0x10618
    if (r2 == 0) goto L0x10560;			//0x1061c
    eR28 = eR28 - 0x1;			//0x10620

    r20 = r0 + r1;			//0x10624
    r4 = 0x44;			//0x10628 //wrong
    r4 = r4 | 0x19e;			//0x1062c
    r0 = r4;			//0x10630
    r1 = r0;			//0x10634
    r7 = 0x5;			//0x10638
    r0 = open(r7, r0,r1,r2,r3,r4,r5);			//0x1063c
    // r0 = fd
    // open("/dev/random")

    r2 = r0;//real r0			//0x10640
    eR10 = r2;			//0x10644
    eR0 = r2;			//0x10648
    r2 = sp + 0x8;			//0x1064c
    eR2 = r2;			//0x10650
    r2 = 0x3;			//0x10654
    eR4 = 0x4;			//0x10658
    eR0 = read(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x1065c

    // read(fd, , 0x4)
    r15 = MEM[sp + 0x8];			//0x10660
    MEM[sp + 0x8] = r0;			//0x10664
    r4 = eR10;			//0x10668
    r2 = r0 + 0x6;			//0x1066c
    r2 = close(r2,r4,r5,r6,r7);			//0x10670

    r4 = MEM[sp + 0x4];			//0x10674
    r5 = (char)MEM[sp + 0xc];			//0x10678
    L0x105a0();			//0x1067c
    // pc = r14;			//0x10680
    return;
}

size_t main(){
    MEM[sp + 0x8] = r0;			//0x100d0
    MEM[sp + 0xc] = r0;			//0x100d4
    MEM[sp + 0x14] = r0;			//0x100d8
    MEM[sp + 0x18] = r0;			//0x100dc
    MEM[sp + 0x1c] = r0;			//0x100e0
    MEM[sp + 0x20] = r0;			//0x100e4

    r2 = MEM + 0x2f0;			//0x100e8
    r27 = r2 + 0x700;			//0x100ec
    r27 = r27 + 0x600;			//0x100f0
    eR46 = r2 + 0xd00;			//0x100f4

    r14 = r0;			//0x100f8
    eR30 = 0x8;			//0x100fc
    eR28 = 0x18;			//0x10100
    r10 = r0 + r0;			//0x10104
    r17 = r0 + 0xd6;			//0x10108
    r10 = brk(r17,r10,r11,r12,r13,r14,r15);			//0x1010c

    r30 = r10 + 0x0;			//0x10110
    r4 = r10;			//0x10114
    r6 = r0 + 0x3;			//0x10118
    r5 = 0x500;			//0x1011c
    r2 = r0 + 0x7d;			//0x10120
    r2 = r2 + 0xfa0;			//0x10124
    r2 = mprotect(r2,r4,r5,r6,r7);			//0x10128

    MEM[r30 + 0x0] = r0;			//0x1012c
    r6 = sp + 0x0;			//0x10130
    eR44 = r6;			//0x10134
    r2 = r30;			//0x10138
    eR42 = r2;			//0x1013c

    // Init some 0
    r2 = r2 + 0x4;			//0x10140
    MEM[sp + 0x0] = r2;			//0x10144
    MEM[r2 + 0x0] = r0;			//0x10148
    r2 = r2 + 0x20;			//0x1014c
    MEM[sp + 0x4] = r2;			//0x10150
    r2 = r2 + 0x100;			//0x10154
    MEM[sp + 0x1c] = r2;			//0x10158
    MEM[r2 + 0x0] = r0;			//0x1015c
    r2 = r2 + 0x200;			//0x10160
    MEM[sp + 0x20] = r2;			//0x10164

    get_random();			//0x10168
    r0 = 0x0;			//0x1016c
    r10 = 0xdb;			//0x10170
    r10 = r10 + r27;			//0x10174
    r4 = 0x80c;			//0x10178
    r11 = r11 + r4;			//0x1017c
    // print("Choose")
    print_sth(r10);			//0x10180  //welcome

round_0:
Round:
    MEM[sp + 0x8] = r0;			//0x10184

    r10 = 0x44;			//0x10188
    r10 = r10 | 0xe8;			//0x1018c
    r11 = r0 + 0x5;			//0x10190
    // print("READY")
    print_sth(r10);			//0x10194 //READY

    eR0 = 0x0;			//0x10198
    r2 = sp + 0x8;			//0x1019c
    eR2 = r2;			//0x101a0
    r2 = 0x3;			//0x101a4
    eR4 = 0x1;			//0x101a8
    // read(0, sp+0x8, 1) 
    eR0 = read(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x101ac

    r6 = eR0;			//0x101b0
    r5 = r0 + 0x67;			//0x101b4
    r4 = (char)MEM[sp + 0x8];			//0x101b8
    // 'g'
    if (r4 == r5) goto L0x10348;			//0x101bc

    eR0 = 0x1;			//0x101c0
    r2 = sp + 0x8;			//0x101c4
    eR2 = r2;			//0x101c8
    r2 = 0x4;			//0x101cc
    eR4 = 0x1;			//0x101d0
    // write(1, sp+0x8, 1)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x101d4

    // r6 = len(input1)
    // goto fail
    if (r6 == 0) goto fail_1;			//0x101d8
    r4 = (char)MEM[sp + 0x8];			//0x101dc
    r5 = r0 + 0x6a;			//0x101e0
    
    // 'j'
    if (r4 == r5) goto greedy;			//0x101e4

    eR0 = 0x1;			//0x101e8
    r2 = r27;			//0x101ec
    eR2 = r2;			//0x101f0
    eR4 = 0x1;			//0x101f4
    r2 = 0x4;			//0x101f8
    // write(1, "\n", 1)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x101fc 

    r2 = r0;			//0x10200
    r5 = 0x65;			//0x10204
    // 'e'
    if (r4 == r5) goto input_lic;			//0x10208
    r5 = r5 + 0x7;			//0x1020c
    // 'l'
    if (r4 == r5) goto L0x1035c;			//0x10210
    r5 = r5 + 0x2;			//0x10214
    r1 = pc - 0x9c;			//0x10218
    // 'n'
    if (r4 == r5) get_random();			//0x1021c
    r5 = r5 + 0x2;			//0x10220
    if (r4 == r5) goto print_input;			//0x10224
    r5 = r5 + 0x2;			//0x10228
    if (r4 == r5) goto round_0;			//0x1022c
    r5 = r5 + 0x4;			//0x10230
    if (r4 == r5) goto check;			//0x10234
    goto faile_2;			//0x10238

input_lic:
    r0 = 0x0;			//0x1023c
    r10 = 0x4e;			//0x10240
    r10 = eR46 + r10;			//0x10244
    r12 = 0x4f;			//0x10248
    r11 = r12 + r0;			//0x1024c
    // print("Enter the license key")
    print_sth(r10);			//0x10250

    eR0 = 0x0;			//0x10254
    r2 = MEM[sp + 0x0];			//0x10258
    eR2 = r2;			//0x1025c
    r2 = 0x3;			//0x10260
    r12 = r0 + 0x20;			//0x10264
    eR4 = r12;			//0x10268
    // read(0, [sp + 0], 0x20)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x1026c

    r6 = eR0;			//0x10270
    MEM[sp + 0xe] = (char)r6;			//0x10274
    r5 = 0x0;			//0x10278
    r3 = MEM[sp + 0x0];			//0x1027c

L0x10280: // check valid 0x29 < char < 0x67
    if (r5 >= r12) goto L0x102a4;			//0x10280
    r6 = r3 + r5;			//0x10284
    r7 = (char)MEM[r6 + 0x0];			//0x10288
    r2 = 0x29;			//0x1028c
    if (r2 >= r7) goto fail_1;			//0x10290
    r2 = 0x67;			//0x10294
    if (r7 >= r2) goto fail_1;			//0x10298
    r5 = r5 + 0x1;			//0x1029c
    goto L0x10280;			//0x102a0

L0x102a4:
    r10 = 0x9d;			//0x102a4
    r10 = eR46 + r10;			//0x102a8
    r11 = (char)MEM[sp + 0xe];			//0x102ac
    // print("*********")
    print_sth(r10);			//0x102b0
    goto Round;			//0x102b4

print_input:
    r10 = MEM[sp + 0x0];			//0x102b8
    r11 = r0 + 0x20;			//0x102bc
                                //real r0
    print_sth(r10);			//0x102c0  // Leak here! 
                            //But what kinds of data can u leak
    goto Round;			//0x102c4

greedy:
    r10 = r0;			//0x102c8
    r11 = sp + 0x14;			//0x102cc
    r17 = r0 + 0x3f;			//0x102d0
    r12 = 0x6;			//0x102d4
    // read(0, sp+0x14, 0x6)
    r10 = ecall(r17,r10,r11,r12,r13,r14,r15);			//0x102d8
    r6 = r10 + r0;			//0x102dc
    r5 = r0 + 0x6;			//0x102e0
    if (r6 != r5) goto fail_1;			//0x102e4

    r5 = 0x75680000;			//0x102e8
    // rt = (r5, 0x7568)
    r5 = r5 | 0x736f;			//0x102ec

    r6 = MEM[sp + 0x14];			//0x102f0
    if (r6 != r5) goto fail_1;			//0x102f4
    r5 = r0 + 0xa61;			//0x102f8
    r6 = MEM[sp + 0x18];			//0x102fc
    if (r6 != r5) goto fail_1;			//0x10300

    r6 = 0x1;			//0x10304
    eR0 = r6;			//0x10308
    r2 = 0x4;			//0x1030c
    r14 = eR44 + 0x14;			//0x10310
    //distroy
    eR2 = r14;			//0x10314
    eR4 = 0x6;			//0x10318
    // write(1, eR44+0x14, 6)
    // print("oshua\n")
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x1031c

    r10 = 0x30;			//0x10320
    r10 = r10 + r27;			//0x10324
    r2 = 0x1e;			//0x10328
    r11 = r0 + r2;			//0x1032c
    // print("GREETINGS PROFESSOR FALKEN.\n")
    print_sth(r10);			//0x10330

    r0 = r10;			//0x10334
    goto Round;			//0x10338

    eR0 = 0x1;			//0x1033c
    r5 = r5 | 0x736f;			//0x10340
    r6 = MEM[sp + 0x18];			//0x10344

L0x10348:
    r5 = r0;			//0x10348
    goto exit_2;			//0x1034c
    //0x10350
    //0x10354
    //0x10358

L0x1035c:
    // check if greedy
    r5 = 0x75680000;			//0x1035c
    r5 = r5 | 0x736f;			//0x10360
    r6 = MEM[sp + 0x14];			//0x10364
    if (r6 != r5) goto exit;			//0x10368
    r2 = MEM[sp + 0x1c];			//0x1036c
    r2 = MEM[r2 + 0x0];			//0x10370
    // r2 = [brk+0x124]
    if (r2 != 0) goto L0x103b4;			//0x10374

    r4 = 0xcb;			//0x10378
    r4 = r4 + r27;			//0x1037c
    r2 = r0 + 0xfa5;			//0x10380
    r5 = r0;			//0x10384
    // open("game")
    r2 = syscall(r2,r4,r5,r6,r7);			//0x10388
    r4 = r2;			//0x1038c
    eR0 = r4;			//0x10390
    r2 = MEM[sp + 0x1c];			//0x10394
    eR2 = r2;			//0x10398
    r2 = 0x3;			//0x1039c
    eR4 = 0x129;			//0x103a0
    // read(fd, [sp+0x1c], 0x129)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x103a4
    r2 = eR0;			//0x103a8
    r2 = r0 + 0xfa6;			//0x103ac
    // close(fd)
    r2 = syscall(r2,r4,r5,r6,r7);			//0x103b0

L0x103b4:
    r10 = r0 + 0x1;			//0x103b4
    r11 = MEM[sp + 0x1c];			//0x103b8
    r12 = r0 + 0x129;			//0x103bc
    r17 = r0 + 0x40;			//0x103c0
    // write(1, game_info, 0x129)
    r10 = ecall(r17,r10,r11,r12,r13,r14,r15);			//0x103c4
    eR0 = 0x1;			//0x103c8
    r10 = MEM[r27 + 0x0];			//0x103cc //What is this?
    eR2 = r10;			//0x103d0
    eR4 = 0x1;			//0x103d4
    r2 = 0x4;			//0x103d8
    // write(1, ???, 1) maybe \n? or something?
    // 写错了 ? write(1, 0x4854410A, 1)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x103dc
    game();			//0x103e0
    goto Round;			//0x103e4

    eR0 = 0x1;			//0x103e8
    r5 = r5 | 0x736f;			//0x103ec
    r6 = MEM[sp + 0x18];			//0x103f0
fail_1:
faile_2:
    eR0 = 0x1;			//0x103f4
    r10 = eR46 + r10;			//0x103f8
    goto L0x1055c;			//0x103fc
    //0x10400
    //0x10404

check:
    r2 = MEM[sp + 0x0];			//0x10408
    r2 = MEM[r2 + 0x0];			//0x1040c
    if (r2 == 0) goto fail_03;			//0x10410
    r2 = eR30;			//0x10414
    if (r2 == 0) goto fail_03;			//0x10418

    eR30 = eR30 - 0x1;			//0x1041c
    r4 = 0x44;			//0x10420
    r4 = r4 | 0xee;			//0x10424
    r0 = r4;			//0x10428
    r1 = r0;			//0x1042c
    r7 = 0x5;			//0x10430
    // open("lic")
    r0 = svc(r7, r0,r1,r2,r3,r4,r5);			//0x10434
    r2 = r0;			//0x10438
    r4 = r0; //real r0			//0x1043c          
    r2 = r4 + 0x30;			//0x10440
    MEM[sp + 0x10] = r2;			//0x10444
    eR0 = r4;			//0x10448
    r2 = MEM[sp + 0x4];			//0x1044c
    eR2 = r2;			//0x10450
    r2 = 0x3;			//0x10454
    eR4 = 0x20;			//0x10458
    // read(fd, [sp+0x4], 0x20)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x1045c
    r2 = eR0;			//0x10460
    r2 = r2;			//0x10464
    MEM[sp + 0xc] = (char)r2;			//0x10468
    r7 = r0;			//0x1046c
    r8 = r0 + 0x20;			//0x10470
    // r0 = 0
    r0 = r7;			//0x10474
    r3 = MEM[sp + 0x4];			//0x10478
    r4 = MEM[r3 + 0x0];			//0x1047c
    r5 = r0 + 0x0;			//0x10480

L0x10488:
    if (r5 >= r2) goto L0x104a0;			//0x10484
    r6 = r3 + r5;			//0x10488
    r4 = MEM[r6 + 0x0];			//0x1048c
    r4 = r4 ^ r15;			//0x10490
    MEM[r6 + 0x0] = r4;			//0x10494
    r5 = r5 + 0x4;			//0x10498
    goto L0x10488;			//0x1049c

L0x104a0:
    r19 = MEM[sp + 0x0];			//0x104a0
    r20 = MEM[sp + 0x4];			//0x104a4
    r21 = r0;			//0x104a8
    r22 = r0;			//0x104ac
    r23 = r0;			//0x104b0
    r24 = r0;			//0x104b4

L0x104bc:
    // 0x20
    if (r7 >= r8) goto L0x104ec;			//0x104b8
    r21 = r19 + r7;			//0x104bc
    r22 = r20 + r7;			//0x104c0
    r25 = MEM[r21 + 0x0];			//0x104c4
    r26 = MEM[r22 + 0x0];			//0x104c8
    r2 = r25 ^ r0;			//0x104cc
    r3 = r26;			//0x104d0
    r4 = r24;			//0x104d4
    int flag;
    flag = r2 - r3;			//0x104d8
    if (flag) r4 = r4 - 0x1;			//0x104dc
    r24 = r4;			//0x104e0
    r7 = r7 + 0x4;			//0x104e4
    goto L0x104bc;			//0x104e8

L0x104ec:
    if (r24 <= 0) goto L0x1050c;			//0x104ec
    r4 = 0x4;			//0x104f0
    r10 = r0 + 0x1;			//0x104f4
    r11 = r27 + 0x19;			//0x104f8
    r12 = r0 + 0x16;			//0x104fc
    r17 = r0 + 0x40;			//0x10500
    // write("Failed !!!!!")
    r10 = ecall(r17,r10,r11,r12,r13,r14,r15);			//0x10504
    goto round_0;			//0x10508

L0x1050c:
    r2 = r0 + 0xfa5;			//0x1050c
    r4 = 0x44;			//0x10510
    r4 = r4 | 0xf3;			//0x10514
    r5 = r0 + 0x0;			//0x10518
    r6 = r0 + 0x0;			//0x1051c
    // open("flag")
    r2 = syscall(r2,r4,r5,r6,r7);			//0x10520
    r4 = r2;			//0x10524
    eR0 = r4;			//0x10528
    r2 = MEM[sp + 0x4];			//0x1052c
    eR2 = r2;			//0x10530
    r2 = 0x3;			//0x10534
    eR4 = 0x24;			//0x10538
    // read("flag")
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x1053c
    r6 = eR0;			//0x10540
    MEM[sp + 0xc] = r6;			//0x10544
    r10 = MEM[sp + 0x4];			//0x10548
    r11 = MEM[sp + 0xc];			//0x1054c
    // print(flag)
    print_sth(r10);			//0x10550
    //0x10554

fail_03:
L0x1055c:
    r0 = r0;			//0x10558

    //0x1055c

L0x10560:
    r0 = 0x1;			//0x10560
    r1 = r27;			//0x10564
    r2 = 0x1;			//0x10568
    r7 = 0x4;			//0x1056c
    // write("\n")
    r0 = svc(r7, r0,r1,r2,r3,r4,r5);			//0x10570
    r11 = r27 + 0x0;			//0x10574
    r10 = r0 + 0x1;			//0x10578
    r12 = r0 + 0x7;			//0x1057c
    r17 = r0 + 0x40;			//0x10580
    // write("\nATH 0\n")
    r10 = ecall(r17,r10,r11,r12,r13,r14,r15);			//0x10584
    r4 = r0 + 0x16;			//0x10588
    r2 = r0 + 0xfa1;			//0x1058c
    // exit()
    r2 = syscall(r2,r4,r5,r6,r7);			//0x10590
    //0x10594
    //0x10598
    r0 = r0;			//0x1059c

    r5 = r0 + 0x31;			//0x10684

game:
    r5 = 0x31;			//0x10688
    r2 = r2 + 0x11;			//0x1068c
    eR0 = 0x1a6;			//0x10690
    r0 = r0;			//0x10694
    //0x10698

L0x1069c:
    MEM[sp + 0x8] = r0;			//0x1069c
    r2 = 0x4;			//0x106a0
    eR0 = 0x1;			//0x106a4
    eR2 = 0x44;			//0x106a8
    eR2 = eR2 | 0x1b2;			//0x106ac
    r4 = eR2;			//0x106b0
    eR4 = 0x8;			//0x106b4
    // write(1, "CHOOSE>")
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x106b8
    eR0 = 0x0;			//0x106bc
    r2 = sp + 0x8;			//0x106c0
    eR2 = r2;			//0x106c4
    r2 = 0x3;			//0x106c8
    eR4 = 0x1;			//0x106cc
    // read(0, sp+0x8, 1)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x106d0
    r6 = eR0;			//0x106d4
    r10 = sp + 0x8;			//0x106d8
    r4 = MEM[sp + 0x8];			//0x106dc
    r11 = r0 + 0x1;			//0x106e0
    // print(input_char)
    print_sth(r10);			//0x106e4
    r5 = r0 + 0x31;			//0x106e8
    if (r4 == r5) goto L0x10764;			//0x106ec
    r5 = r0 + 0x32;			//0x106f0
    if (r4 == r5) goto L0x10764;			//0x106f4
    r5 = r0 + 0x33;			//0x106f8
    if (r4 == r5) goto L0x10764;			//0x106fc
    r5 = r0 + 0x34;			//0x10700
    if (r4 == r5) goto L0x10764;			//0x10704
    r5 = r0 + 0x35;			//0x10708
    if (r4 == r5) goto L0x10764;			//0x1070c
    r5 = r0 + 0x36;			//0x10710
    if (r4 == r5) goto L0x10764;			//0x10714
    r5 = r0 + 0x37;			//0x10718
    if (r4 == r5) goto L0x10764;			//0x1071c
    r5 = r0 + 0x38;			//0x10720
    if (r4 == r5) goto L0x10764;			//0x10724
    r5 = r0 + 0x39;			//0x10728
    if (r4 == r5) goto L0x10764;			//0x1072c
    r5 = r0 + 0x61;			//0x10730
    if (r4 == r5) goto L0x10764;			//0x10734
    r5 = r0 + 0x62;			//0x10738
    if (r4 == r5) goto L0x10764;			//0x1073c
    r5 = r0 + 0x63;			//0x10740
    if (r4 == r5) goto L0x10764;			//0x10744
    r5 = r0 + 0x64;			//0x10748
    if (r4 == r5) goto L0x10764;			//0x1074c
    r5 = r0 + 0x65;			//0x10750
    if (r4 == r5) goto L0x10764;			//0x10754
    r5 = r0 + 0x66;			//0x10758
    if (r4 == r5) goto L0x10764;			//0x1075c
    goto round_0;			//0x10760

L0x10764:
    //
    r4 = 0x7a6d0000;			//0x10764
    r4 = r5 + r4;			//0x10768
    r4 = r4 | 0x2e00;			//0x1076c
    r3 = MEM[sp + 0x20];			//0x10770
    MEM[r3 + 0x4] = r4;			//0x10774
    MEM[r3 + 0x8] = r0;			//0x10778
    r4 = 0x2f2f0000;			//0x1077c
    r4 = r4 | 0x2f2f;			//0x10780
    MEM[r3 + 0x0] = r4;			//0x10784

    r10 = r3;			//0x10788
    r11 = r0 + 0x8;			//0x1078c
    // puts(filename)
    print_sth(r10);			//0x10790

    r3 = MEM[sp + 0x20];			//0x10794
    r2 = r0 + 0xfa5;			//0x10798
    r4 = r3;			//0x1079c
    r5 = r0 + 0x0;			//0x107a0
    r6 = r0 + 0x0;			//0x107a4
    // open("1.mz~f.mz")
    r2 = syscall(r2,r4,r5,r6,r7);			//0x107a8
    r4 = r2;			//0x107ac
    r3 = MEM[sp + 0x20];			//0x107b0
    eR0 = r4;			//0x107b4
    r2 = r3 + 0xc;			//0x107b8
    eR2 = r2;			//0x107bc
    eR4 = 0x33;			//0x107c0
    r2 = 0x3;			//0x107c4
    // read(fd, MEM[sp+0x20]+0xc, 0x33)
    eR0 = ta(r2, eR0, eR2, eR4, eR6, eR8, eR10);			//0x107c8
    r2 = eR0;			//0x107cc
    r2 = r0 + 0xfa6;			//0x107d0
    // close
    r2 = syscall(r2,r4,r5,r6,r7);			//0x107d4
    r3 = MEM[sp + 0x20];			//0x107d8
    r10 = r0 + 0x1;			//0x107dc
    r11 = r3 + 0xc;			//0x107e0
    r12 = r0 + 0x33;			//0x107e4
    r17 = r0 + 0x40;			//0x107e8
    // write(1, read_before, 0x33)
    r10 = ecall(r17,r10,r11,r12,r13,r14,r15);			//0x107ec
    goto L0x1069c;			//0x107f0

exit:
exit_2:
    //0x107f4

    //0x107f8
    r0 = r0;			//0x107fc
    //0x10800
    r4 = r0 + 0x2a;			//0x10804
    r2 = r0 + 0xfa1;			//0x10808
    r2 = syscall(r2,r4,r5,r6,r7);			//0x1080c
}

    //0x105c8
```

```python
#!/bin/python2
from LibcSearcher import LibcSearcher
from mypwn import *
from binascii import *

setting = {
    "aslr": False,
    "log": True,
    "elf": True,
    "libc": False,
    "libc_image": False,
    "debug": False,
    "gdb_script": "",
    "remote": False,
    # "ip": "tiamat.challenges.ooo",
    "ip": "127.0.0.1",
    "port": "5000"
}

#b* 0x555555554000
gdb_script = """
"""

setting["gdb_script"] = gdb_script
from mypwn import *

all_possi = ["04e7a3cb66233a6c0f4d513421d4a74e"]

def do_xor(b1, b2):
    b1 = [ord(i) for i in b1]
    for i in range(len(b1)):
        b1[i] ^= ord(b2[i])
    return "".join([chr(i) for i in b1])

for p in all_possi:
    try:
        if 0:
            start_program(setting)
            senda("READY", "e"+"1"*32+"vnp")
            recvu("1"*32)
            s1 = recvn(4)
            print(hexlify(s1))
            interactive()
        if 0:
            start_program(setting)
            senda("READY", "e"+"1"*32+"vnp")
            recvu("1"*32)
            s1 = recvn(4)
            print(hexlify(s1))
            senda("READ", "np")
            recvu("1"*32)
            s2 = recvn(4)
            print(hexlify(s2))
            rand = do_xor(s1, s2)
            print(hexlify(rand))
            payload = ""
            for i in range(8):
                payload += do_xor(rand, p[i*4:i*4+4])
            senda("READ", "e"+payload+"joshua\nv")
            interactive()

        if 1:
            start_program(setting)
            senda("READY", "e"+"1"*32+"v"*7+"n"*0x16+"p")
            recvu("1"*32)
            senda("READY", "joshua\nvnp")
            recvu("1"*32)
            print(hexlify(recvn((0x20))))
            interactive()
            continue
    except Exception as e:
        continue
        print("[-] Error:", e)
        raw_input()
```