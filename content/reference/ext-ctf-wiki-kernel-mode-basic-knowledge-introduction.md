---
title: "Introduction - 基础知识 (CTF Wiki)"
category: "pwn"
subcategory: "basic-knowledge"
type: "reference"
tags: ["ctf-wiki", "pwn", "heap", "canary", "introduction", "basic-knowledge", "knowledge", "chinese", "zh"]
summary: "Windows 操作系统全称为新技术视窗（Windows New Technology，简称 Windows NT），其 曾经 声称采用的是微内核架构（micro kernel），即大部分系统组件都以用户态形式存在，仅有部分必要组件以内核态形式存在，但实际上现在 Windows 往内核态塞了不少东西，所以现在的 NT kernel 更偏向于 混合内核 （hybrid kernel）。"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/windows/kernel-mode/basic-knowledge/introduction.md"
license: "CC BY-NC-SA 4.0"
---

# 基础知识

> 如果你对操作系统基本理论并不熟悉，那笔者其实更推荐 [从 Linux kernel 这一个开源宏内核进行入门](https://arttnba3.cn/2021/02/21/OS-0X00-LINUX-KERNEL-PART-I/)，本文基本不会涉及操作系统基础概念。

Windows 操作系统全称为**新技术视窗**（Windows New Technology，简称 **Windows NT**），其 _曾经_ 声称采用的是**微内核架构**（micro kernel），即**大部分系统组件都以用户态形式存在，仅有部分必要组件以内核态形式存在**，但实际上现在 Windows 往内核态塞了不少东西，所以现在的 NT kernel 更偏向于 _混合内核_ （hybrid kernel）。

![Windows 内核架构总览](https://s2.loli.net/2025/02/01/o9DzrNqSvLxIfdR.png)

本篇博客我们主要介绍 **64 位** Windows NT kernel 的基本运行原理以及一些基本组件，主要以 Windows 10 作为案例进行讲解， _不会涉及与 32 位相关的内容_ 。

> 关于 Windows 内核一些结构体的定义可以参见 [这个网站](https://www.vergiliusproject.com/kernels)

## 一、用户态部分

Windows NT 操作系统在用户态主要分为四个部分：

- 系统进程（System Processes）
- 服务（Services）
- 应用（Applications）
- 环境子系统（Environment Subsystem）

Windows 下所有用户态程序对系统资源的获取最终都要通过 `ntdll.dll` 提供的系统调用接口完成。

## 二、内核态部分

 NT kernel 并不存在硬件意义上的分层（都跑在 ring0），但在设计上存在分层依赖的概念，可以分为如图所示的三层：

![Windows 系统架构层次](https://s2.loli.net/2025/02/01/ZwtEYSgi8UPr7Wx.png)

### 上层：执行体 （Executive）

**执行体**（Executive）是 NT kernel 的核心部分， **本质上就是传统的操作系统内核本体**，比较核心的一些子系统如下：

- **对象管理器**（Object Manager）：对象管理器是 **执行体的底层部分** ，在内核中 **所有的资源都是一个对象** （object），对象管理器便负责管理所有的内核对象。
- 输入输出管理器（I/O Manager）：负责接收用户态程序的 I/O 请求（如访问磁盘），将其转换为对相关设备的调用。
- 安全引用监视器（Security Reference Monitor）：Windows 使用**访问控制列表**（Access Control List）来确定对象的安全性，该子系统便负责实行安全规则。
- 进程间通信管理器（IPC Manager）：负责处理不同进程间的通信请求。
- 虚拟内存管理器（Virtual Memory Manager）：负责从内核层面进行整个操作系统的内存管理。
- 进程管理器（Process Manager）：负责进程与线程的创建与销毁， _不负责直接调度_。
- 即插即用管理器（Plug and Play Manager）：负责处理设备动态载入与卸载时进行检测及提供相应服务，大部分实际上在用户态的 `Plug and Play` 中实现。
- 电源管理器（Power Manager）：负责处理电源相关事件（关机、睡眠等），并通知相关联的驱动程序。
- 图形设备接口（Graphic Device Interface）：负责所有基本的绘图功能，自 NT 4.0 起移入内核态中运行（此前在用户态）。

执行体相关的代码位于 `ntoskrnl.exe` 中，其向用户态导出的接口位于 `ntdll.dll` 中。

### 中层：（微）内核（Kernel）

**内核**（Kernel）在 NT kernel 中**仅**负责多处理器间同步、线程直接调度、中断/异常分发等最基本的 _硬件侧职能_ ，符合“微内核”架构的基本思想。

内核相关代码位于 `ntoskrnl.exe` 中。

### 中层：内核模式驱动（Kernel Mode Driver）

Windows 下的驱动有两种：用户模式驱动和内核模式驱动，后者负责向前者提供对应的接口，并将数据传递给更为底层的驱动程序。

内核模式驱动可以分为如图所示的三层，越贴近底层越靠近详细具体的硬件结构：

![](https://s2.loli.net/2025/02/01/KeypmW8xGPViXQH.png)

内核模式驱动被实现为离散的模块化组件，而非位于某个特定的 PE 文件中（有点像 LKM？）。

### 下层：硬件抽象层（Hardware Abstract Layer）

**硬件抽象层**（Hardware Abstract Layer）负责隐藏与屏蔽底层不同硬件的各种细节，从而向上层内核提供**统一的抽象硬件接口**，例如 IO 接口、中断控制器等硬件行为的统一抽象。

HAL 的目的主要是消除硬件架构间的差异，从而方便操作系统与驱动开发者为不同硬件平台编写与具体硬件架构无强相关的代码以跨平台运行，从而无需为每个硬件平台都单独编写一套针对性代码。

需要注意的是 HAL 主要负责 IO 等通用资源的抽象，部分驱动的部分操作仍然是绕开 HAL 直接与硬件进行通信的。

HAL 相关代码位于 `hal.dll` 中。

## “一切皆对象”

类似于 *NIX 系统中一切皆文件的哲学，在 Windows NT kernel 当中同样有**一切都是一个对象**（object）的说法，文件、设备、同步机制、注册表项等**在内核中都表示为对象**，每个对象有一个 `header` 存储对象基本信息（如名字、类型、位置），以及一个 `body` 存储数据。

NT kernel 中的对象可以分为两类：

- 执行体对象（Executive Objects）：执行体对外暴露的资源对象（如进程、线程、文件等），对用户态可见。
- 内核对象（Kernel Objects）：最基本的资源对象（如物理设备等），对用户态不可见。

### 一、\_OBJECT\_HEADER：对象基本信息

在 NT kernel 中 `_OBJECT_HEADER` 结构体用来存储对象的基本信息，定义如下：```powershell
kd> dt nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int8B
   +0x008 HandleCount      : Int8B
   +0x008 NextToFree       : Ptr64 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : UChar
   +0x019 TraceFlags       : UChar
   +0x019 DbgRefTrace      : Pos 0, 1 Bit
   +0x019 DbgTracePermanent : Pos 1, 1 Bit
   +0x01a InfoMask         : UChar
   +0x01b Flags            : UChar
   +0x01b NewObject        : Pos 0, 1 Bit
   +0x01b KernelObject     : Pos 1, 1 Bit
   +0x01b KernelOnlyAccess : Pos 2, 1 Bit
   +0x01b ExclusiveObject  : Pos 3, 1 Bit
   +0x01b PermanentObject  : Pos 4, 1 Bit
   +0x01b DefaultSecurityQuota : Pos 5, 1 Bit
   +0x01b SingleHandleEntry : Pos 6, 1 Bit
   +0x01b DeletedInline    : Pos 7, 1 Bit
   +0x01c Reserved         : Uint4B
   +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : Ptr64 Void
   +0x028 SecurityDescriptor : Ptr64 Void
   +0x030 Body             : _QUAD
```

一个对象除了固定的 `_OBJECT_HEADER` 以外**还可以有额外的 optional header 来存储额外的信息**，对应的 optional header 是否存在由 `_OBJECT_HEADER->InfoMask` 掩码决定：

![](https://s2.loli.net/2025/02/01/S8hIzlRWCFGjTed.png)

当 `_OBJECT_HEADER->InfoMask` 掩码中存在对应位时则表示 _对应的 optional header 存在_ ，由于 optional header 的存储顺序固定，NT kernel 可以很容易计算出不同 header 对应的偏移，掩码与 header type & size 对应关系如下：

| Bit  |              Type              | Size (on X86) |
| :--: | :----------------------------: | :-----------: |
| 0x01 | nt!_OBJECT_HEADER_CREATOR_INFO |     0x10      |
| 0x02 |  nt!_OBJECT_HEADER_NAME_INFO   |     0x10      |
| 0x04 | nt!_OBJECT_HEADER_HANDLE_INFO  |     0x08      |
| 0x08 |  nt!_OBJECT_HEADER_QUOTA_INFO  |     0x10      |
| 0x10 | nt!_OBJECT_HEADER_PROCESS_INFO |     0x08      |

在**NT kernel 19H1 版本以前**，Windows 内核**仅**使用 `Pool Allocator` ，此时对于每个分配的内核池对象都有一个 `_POOL_HEADER` 结构体存储相应的信息：
```powershell
kd> dt nt!_POOL_HEADER
   +0x000 PreviousSize     : Pos 0, 8 Bits
   +0x000 PoolIndex        : Pos 8, 8 Bits
   +0x002 BlockSize        : Pos 0, 8 Bits
   +0x002 PoolType         : Pos 8, 8 Bits
   +0x000 Ulong1           : Uint4B
   +0x004 PoolTag          : Uint4B
   +0x008 ProcessBilled    : Ptr64 _EPROCESS
   +0x008 AllocatorBackTraceIndex : Uint2B
   +0x00a PoolTagHash      : Uint2B
```

由此我们可以得到一个内核对象的基本结构如下图所示：

![](https://s2.loli.net/2025/02/01/rzoqgZXxNSmsa52.png)

### 二、对象管理器与命名空间

NT kernel 中所有的对象通过**对象管理器**（Object Manager）进行管理，用户态对任何对象的访问都需要通过对象管理子系统，对象管理器主要负责如下任务：

- 管理对象的创建与销毁
- 维护对象命名空间数据库
- 追踪分配给进程的资源
- 追踪特定对象的访问权限
- 管理对象的生命周期

对象归属于不同的[命名空间](https://learn.microsoft.com/zh-cn/windows/win32/termserv/kernel-object-namespaces)（Namespace），不同的用户会话（user session）便为不同的命名空间，对象创建时默认归属于当前会话的命名空间，此外还有一个全局共享的**全局命名空间**，从而使得对象可以在不同会话间进行共享。

> 创建对象时可以通过 `"Global\"` 前缀来将该对象创建于全局命名空间中，例如通过如下代码可以创建一个属于全局命名空间的事件对象：
>
> ```cpp
> CreateEvent( NULL, FALSE, FALSE, "Global\\ARTTNBA3" );
> ```
>
> 也可以通过 `“Local\”` 前缀显式说明对象创建在会话命名空间中。

### 三、句柄（handler）

> 有点类似于 Linux 下文件描述符的概念，但是扩展到了大部分内核对象。
>
> > 非常不知所谓的翻译，笔者个人感觉翻译成 _引用符_ 可能会更好一些。

**句柄**（handler）是 Windows 下用户态程序用来管理对应内核对象的一个对象描述符，表示形式为一个整数值（32/64 位系统中为 32/64 位整数），用户程序通过其拥有的句柄可以访问内核中相对应的内核对象。

在 Windows 中一共有以下几种存储对象信息的句柄表：

- Windows NT kernel 中所有对象的句柄都存放在一个全局的句柄表当中
- 每个进程有其独立的一个句柄表（其地址存放在进程控制块的 `_EPROCESS->_HANDLER_TABLE->TableCode` 中），**进程所获取到的对象句柄值实际上是【该表对应项的下标索引值x4】**（64 位系统，每个条目 16 字节）

进程句柄表结构如下图所示，其中第 0 项为保留项，句柄表项为 `_HANDLE_TABLE_ENTRY` 结构，其低 44 位值左移 4 位加上 `0xffff000000000000` 便是对象头地址：

> 在 Windows 7 当中进程句柄表实际上仅简单存放对象的地址，但是到了高版本内核一切都开始变得复杂了起来。

![32 位 NT kernel 中句柄表的结构，64 位下的原理基本一致](https://s2.loli.net/2025/02/01/yZk1NKeIqBcriVS.png)

同时 `TableCode` 使用低 4 位**标识句柄表的结构层次**——即**进程句柄表实际上可以有多层结构**，类似于页表，**仅有最后一层存放对象地址，其他层都用于存放表地址**，每张表的大小为 4096 字节（一张内存页大小）：

![](https://s2.loli.net/2025/02/01/nU3FkTsiGpPMw8Q.png)

## 内存管理

内存管理是操作系统最核心的一部份之一，不可不品尝。

### 一、物理内存管理

#### 内核地址空间布局

首先来一张 64 位 NT kernel 内存布局总览：

> 32 位就暂时不考虑研究了，毕竟从 Win11 开始就已经都是纯 64 位了。

| **Start**               | **End**                   | **Size**  | **Description**          | Usage                                                  |
| ----------------------- | ------------------------- | --------- | ------------------------ | ------------------------------------------------------ |
| FFFF080000000000       | FFFFF67FFFFFFFFF         | 238TB     | Unused System Space      | 不会被用到的空间                                       |
| FFFFF68000000000       | FFFFF6FFFFFFFFFF         | 512GB     | PTE Space                | 页表所在区域                                           |
| FFFFF70000000000       | FFFFF77FFFFFFFFF         | 512GB     | HyperSpace               | 用来做临时中转映射                                     |
| FFFFF78000000000       | FFFFF78000000FFF         | 4K        | Shared System Page       | 共享内存空间，（作为内核入口点？）在每个进程中都有映射 |
| FFFFF78000001000       | FFFFF7FFFFFFFFFF         | 512GB-4K  | System Cache Working Set | 系统缓存的工作集 |
| FFFFF80000000000       | FFFFF87FFFFFFFFF         | 512GB     | Initial Loader Mappings  | 最初的内核加载器所用区域                               |
| FFFFF88000000000       | FFFFF89FFFFFFFFF         | 128GB     | Sys PTEs                 | 系统页表项区域，MDL 映射的虚拟内存和驱动映像都在此处   |
| FFFFF8a000000000       | FFFFF8bFFFFFFFFF         | 128GB     | Paged Pool Area          | 分页内存区域                                           |
| FFFFF90000000000       | FFFFF97FFFFFFFFF         | 512GB     | Session Space            |                                                        |
| FFFFF98000000000       | FFFFFa70FFFFFFFF         | 1TB       | Dynamic Kernel VA Space  | 动态内存区域                                           |
| FFFFFa8000000000       | *nt!MmNonPagedPoolStart-1 | 6TB Max   | PFN Database             | 存储 PFN 相关信息                                      |
| *nt!MmNonPagedPoolStart | *nt!MmNonPagedPoolEnd     | 512GB Max | Non-Paged Pool           | 非分页内存区域（不会被换到硬盘上）                     |
| FFFFFFFFFFc00000       | FFFFFFFFFFFFFFFF         | 4MB       | HAL and Loader Mappings  | 硬件抽象层与加载器所用区域                             |

#### _MMPFN：物理页框

类似于 Linux kernel 中使用 `page` 结构体数组表示物理内存的方式，在 NT kernel 中使用 `_MMPFN` 结构体来表示**一张物理页**，并通过一个**结构体数组**来管理**所有的物理内存页**，数组下标即为物理页的**页帧号**（Page Frame Number，PFN），该数组即为 `PFN Database` 区域，在全局指针变量 `_MMPFN* MmPfnDatabase`  中存放着该数组的地址：

![](https://s2.loli.net/2025/02/01/DjXOsiKcuGe3F62.png)

根据 Page 的不同用途，非 active 页面对应的`_MMPFN` 会被放入不同的链表当中，链表头为 `_MMPFNLIST` 结构体：

- `MmZeroedPageListHead` ：清零了的空闲页面链表
- `MmFreePageListHead`：常规空闲页面链表，系统空闲时会从中取出页面进行清零后放到 `MmZeroedPageListHead`  上
- `MmStandbyPageListHead`：进程从其工作集（working set，即**进程的虚拟地址空间中驻留在物理内存中的一组页面**）中丢弃页面时，若页未被修改则放入该链表，在 free 链表和 zeroed 链表都为空时会从上分配页面
- `MmModifiedPageListHead`：进程从其工作集中丢弃页面时，若页被修改且需要写回磁盘则放入该链表，在 modified page writer 完成操作之后会将页面放至 standby 链表
- `MmModifiedNoWritePageListHead`：进程从其工作集中丢弃页面时，若页被修改且**不**需要写回磁盘则放入该链表，modified page writer 完成操作之后会将页面放至 standby 链表
- `MmBadPageListHead`：这些页面可能存在一些故障

> 进程从其工作集中丢弃页面有两种原因，一是原有工作集已满且要引入新页面，二是内存管理器修剪了其工作集（例如内存不够用了）。
>
> 在进程退出时，所有的页面都会进入 freepagelist 链表中。

![](https://s2.loli.net/2025/02/01/F31JSlV7XCruWyT.png)

页面在不同链表间循环的总览图如下：

![](https://s2.loli.net/2025/02/01/p2amPDjBd34IZYk.png)

在 `_MMPFN` 结构体当中同样用了大量的 union，当页面在不同链表间循环时， `_MMPFN` 不同偏移的字段有着不同含义：

![image.png](https://s2.loli.net/2023/12/29/JqmC3DZRiVpMPbB.png)

#### 页位图

> 待施工。

### 二、Pool Memory（before 19H1）

Windows NT kernel 将页面按照不同的用途分为不同的“**池**”（Pool）来管理，并将这些页面划分为更细粒度的小对象供内核组件使用，池的总类一共有三种：

- 非换页池（Non Paged Pool）：该池中的页面常驻物理内存中，不会被换出到磁盘
- 换页池（Paged Pool）：该池中的页面在内存紧张时可能被换出到磁盘
- 会话换页池（Session Paged Pool）：该池中的页面在内存紧张时可能被换出到磁盘，不同会话间存在隔离

#### 基本单位：池块（Pool Block）

池内存中每次内存分配的对象称为一个池块（Pool Block），类似于 ptmalloc2 中的 chunk，每个池块的数据前部有一个 header 存储如下数据：

- Previous Size：相邻低地址池块的大小**右移 4 位的结果**
- Pool Index：池块归属的池描述符组的索引，多个池描述符组成一个池描述符数组
- Block Size：池块大小**右移 4 位的结果**
- Pool Type：池块所属池的类型
- Pool Tag：调试时用于进行识别的字符
- （一个Union）：
    - Process Billed：指向分配了这个池块的进程描述符 `_EPROCESS` 的指针
    - （一个结构体）
        - Allocator Back Trace Index：
        - Pool Tag Hash：

此外，自 Windows Server 2003 版本起，在 Pool Chunk 尾部引入了 Canary 字段，用于预防潜在的 chunk overflow，这个值会在 （ _暂时没查到更多信息，推测是池块分配与释放时_ ） 时被检查。

![](https://s2.loli.net/2025/02/01/abBQ3WwxVCvdPj8.png)

> 需要注意的是，Pool Chunk 仅用于请求内存大小不大于 4080 字节的情况（加上 16 字节的 header 刚好一张内存页大小）。

Pool Chunk 的管理与 ptmalloc2 chunk 非常相似，在 NT kernel 中会复用 Freed Chunk 的 Data 字段来组织 Free Chunk 为单向或双向链表：

![](https://s2.loli.net/2025/02/03/MoOTksItJ6Wvdmr.png)

#### 池描述符：内核共享内存池

> 这个结构在 Windows 10 数个版本当中也经历了一定的大大小小的变化， 但比较关键的变化是从 1809 版本到 1903 （19H1）版本，自 1903 版本 NT kernel 引入了 Segment Heap 机制作为内核的动态内存分配器，因此这一小节我们主要讲 1809 及以前的仍使用池内存分配器的 64 位版本。

类似于 Linux kernel 中的 `kmem_cache` ，Windows kernel 中单个内存池使用 `_POOL_DESCRIPTOR` 结构进行表示，其结构如下图所示：

![](https://s2.loli.net/2025/02/05/lcemqOtFIfyMCVa.png)

池描述符所对应的内存池在整个内核间共享，比较核心的有两个链表：

- ListHeads 链表数组：存放常规的释放后的池块，使用双向链表进行连接，根据池块大小的不同放入不同的子链表中
- PendingFrees 链表：当内存池设置了 `DELAY_FREE` 标志位时，池块释放后会先链入该单向链表（大小不限），当链表深度超过指定值时再统一回收

所有初始的内存池描述符都放在 `nt!PoolVector` 数组当中。

#### 核心独占内存池：Lookaside Lists

池描述符对应的内存池在所有核心间共享，核心一多效率就灾难了，因此每个核心实际上还有一个独有的内存池，存放在内核态 GS 寄存器指向的 `处理器控制区`（Process Control Region，为 `_KPCR` 结构体，类似于 Linux 下的 `.percpu` 段）当中—— Lookaside Lists 用于优先处理当前核心的池内存请求，只有当其不足以满足需求时才会向共享内存池请求内存。

LookasideList 的结构如下图所示，根据大小归属数组上不同的链表，每个链表又分为二个子链：一个单向链表（默认，长度有上限，LIFO）与一个双向链表（前者满时放到这），LookasideList 的数组成员数量较少因此仅用于较小的内存分配。

![](https://s2.loli.net/2025/02/05/VBuc9hZysC2fbr4.png)

LookasideList 一共有四类（`PP == Per Processsor`）：

- PPLookasideList：用于频繁分配与释放的对象的 LookasideList
- PPNxPagedLookasideList：非换页池的 non-eXecuted 页面的 LookasideList
- PPNPagedLookasideList：非换页池的 LookasideList
- PPPagedLookasideList：换页池的 LookasideList

> PPLookasideList 和其他 LookasideList 有什么不同？笔者也不知道 ~~，静待 Windows 开源的那一天~~ ......

#### 内存分配基本算法

##### 1. 内存请求顺序

池内存的分配核心函数是 `ExAllocatePoolWithTag(POOL_TYPE PoolType,SIZE_T NumberOfBytes,ULONG Tag)` ，用户需要手动指定分配的池类型、需要的内存大小等信息，内核组件与驱动通常通过该 API 或是更上层的 Wrapper 完成内核中的内存分配请求

- 通用的池内存分配仅适用于小于 4080 字节的内存请求，对于大于这个大小的内存请求则内部会通过 `nt!ExpAllocateBigPool()` 完成
- 首先会尝试根据请求的池类型从 `_KPCR` 的 LookasideList 区域的不同链表进行内存分配，如果可以满足则直接返回
- 若 LookasideList 无法满足，锁上对应的池，并尝试从 ListHeads 链表进行分配，若分配的池块大小大于所需则会将其分割为两块，一块返回给用户一块挂回 ListHeads 链表
- 若无可用池块，则会调用 `nt!MiAllocatePoolPages` 分配内存页，并将其分割为两块，一块返回给用户一块挂回 ListHeads 链表


##### 2. 池块分割方法：非页对齐的块从尾部分割

在分割池块时，内核首先会检查池块的地址，若与内存页大小对齐（0x1000）则从头部分割出用户所需的池块，否则从尾部分割下用户所需的池块。

![](https://s2.loli.net/2025/02/05/tNK6CdgSholBeq4.png)

#### 内存释放基本算法

池内存的释放核心函数是 `ExFreePoolWithTag( PVOID Entry, ULONG Tag)` ，内核组件与驱动通常通过该 API 或是更上层的 Wrapper 完成内核中的内存释放请求。

在 Chunk header 当中存放着该 Chunk 所属的 Pool Type & Index，因此释放时可以直接判断归属的 Pool 与对应的 List，具体释放流程如下：

- 首先检查该 Chunk 是否为页的第一个 Chunk （页对齐），若是则尝试调用 `nt!MiFreePoolPages()` 进行回收，成功则直接返回
- 接下来检查物理相邻高地址 Chunk 的 PrevSize 是否与该 Chunk header 记录的 Size 相等，若否会报错
- 如果 Size 小于某个特定值，尝试放回相应的 Lookaside List 中
- 如果对应的 Pool 设置了 `DELAY_FREE` 标志位，放回 PendingFrees List（如果PendingFreeDepth 大于某个特定值，会先调用 `nt!ExDeferredFreePool` 函数清空 PendingFrees List）
- 检查相邻低地址、高地址 Chunk 状态，合并空闲块，需要注意这里 _不会与下一张内存页的头部 Chunk 合并_ 
- 最后检查该 Chunk 所在 Page 是否为空闲页，若是则调用 `nt!MiFreePoolPages()` 进行回收，否则放回对应的 ListHeads 链表

### 三、Segment Heap in Kernel（from 19H1）

**自 NT kernel 19H1 版本起，用户态 Segment Heap 的分配逻辑被引入内核。**

> 待施工。

## 系统调用

### 一、系统调用路径

类似于 Linux 下的系统调用，Windows 下由内核向用户态进程提供的服务称为**系统服务**（system service），所有对系统服务的调用都通过 `ntdll.dll` 来完成进入内核的过程：

![以 Notepad 创建文件为示例的 Windows 系统调用路径](https://s2.loli.net/2025/02/01/cbfeQk6OagNXMZP.png)

> 在 `ntdll.dll` 中以 `Nt` 开头的以及以 `Zw` 开头的函数皆为系统调用，本质上没有差别。

以 `NtDeleteFile` 这一系统服务为例，若支持 syscall 指令则通过 `syscall` 指令进入内核，否则通过 `int 0x2E` 软中断走中断门进入内核：

![](https://s2.loli.net/2025/02/01/byVx3MwQfCKJavL.png)

> `0x7FFE0000` 这块区域为一块**内核与用户进程共享的内存**（只有内核有写权限），为一个 `KUSER_SHARED_DATA` 结构体，由内核向用户态提供一些信息。
>
> 在偏移 `0x308` 处存放的便是一个布尔值，用来标识该架构是否支持 `syscall` 指令。

Windows 系统调用内核层的入口被设置为 `KiSystemCall64()` 函数，当进行 `syscall` 指令/ `0x2E` 软中断时，CPU 会切换到 ring0 并执行该函数作为统一的系统调用入口点，该函数定义于 `ntoskrnl.exe` 中，根据 `rax` 寄存器指定的系统调用号来调用 SSDT 中对应的内核函数。

![](https://s2.loli.net/2025/02/01/VLWQjOwufy8UnT4.png)

> 注：有的时候系统调用入口为 `kiSystemCall64Shadow()` 函数，不过这个函数最终会跳转到 `kiSystemCall64()` 中的 `KiSystemServiceUser` 标签。

### 二、系统服务描述符表

#### SSDT 基本结构

逆向分析 `ntoskrnl.exe` 中的  `KiSystemCall64()` 函数，注意到其会引用到 `KeServiceDescriptorTable` 和 `KeServiceDescriptorTable` 这两个变量，这便是**系统服务描述符表**（System Service Descriptor Table，简称 `SSDT` ），用来存储**不同的系统调用号对应的系统调用函数**：

![](https://s2.loli.net/2025/02/01/AycmGR8wENvHjeg.png)

其本质上是一个 `tag_SERVICE_DESCRIPTOR_TABLE` 结构体，为由四张子表组成的 `SYSTEM_SERVICE_TABLE` **结构体数组**：
```c
typedef struct tag_SERVICE_DESCRIPTOR_TABLE {
    SYSTEM_SERVICE_TABLE nt;		// KeServiceDescriptorTable 只有这张表
    SYSTEM_SERVICE_TABLE win32k;	// KeServiceDescriptorTableShadow 额外多用一个这张表
    SYSTEM_SERVICE_TABLE sst3;
    SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE;
```

 `SYSTEM_SERVICE_TABLE` 结构体定义如下，其中的 `ServiceTable` 成员为实质上的系统调用表：
```c
typedef struct tag_SYSTEM_SERVICE_TABLE {
    PULONG      ServiceTable;	// 实际的系统调用表
    PULONG      CounterTable;	// 
    ULONG       ServiceLimit;	// 系统调用的数量
    PCHAR       ArgumentTable;	// 参数数量表
} SYSTEM_SERVICE_TABLE;
```

![](https://s2.loli.net/2025/02/01/vNFWB1j9YVIZEdH.png)

`ServiceTable` 成员 **实际上为一个指向【目标函数到系统调用表偏移】的数组的指针，每一项为 4 字节**，但是实际上计算时会 _将该值先右移四位_ 后再与 _系统调用表起始地址_ 相加获取系统调用实际的地址，即：
$$
Addr_{syscall} = Addr_{ServiceTable} + (ServiceTable[syscall\_nr] >> 4)
$$

由此我们得到 SSDT 的基本结构如下图所示（以 `NtOpenFile()` 系统调用为例）：

![](https://s2.loli.net/2025/02/01/J4bHB6uQV1nOFMA.png)

在 Windbg 中验证：

![](https://s2.loli.net/2025/02/01/IgC4Fm9ZYnhp7WQ.png)

这里为什么要进行左右移 4 位的神秘操作有以下原因：

- **出于安全性考虑**，这样使得通过 SSDT 调用到的系统调用范围被限制在 SSDT 附近 4G 偏移处，驱动地址空间之间间隔至少 4GB，而 SSDT 地址又是写死在代码里的，这样可以很好地防止对 SSDT 的劫持，加大攻击难度。
- **存储栈上参数数量**，NT kernel 很多系统调用参数都远大于 6 个，因此需要使用栈进行传参，此时这 4 bit 便用于记录不同系统调用**使用栈进行传递的参数数量**。

#### _Shadow SSDT：GUI程序的 SSDT_ 

**影子系统服务描述符表**（Shadow System Service Descriptor Table，简称 `Shadow SSDT` ）是**GUI 程序所专用的一张 SSDT**，相比起 SSDT 而言其额外多了一张负责图形相关系统调用的子表 `W32pServiceTable` ，位于 `win32k.sys` 即 **图形子系统** 中：

> SSDT 和 Shadow SSDT 第一张子表都是 `KiServiceTable` ，对应 NT kernel 的常规系统调用。

![注意这里指向 SystemServiceTable 不是指针而是展开](https://s2.loli.net/2025/02/01/vBinIhjLrtHElw2.png)

当应用程式在 Windows 下进行系统调用时，线程控制块（`KTHREAD` ）中对应的标志位决定了调用哪一张大表，`eax` 寄存器的 13 ~ 12 位被用来指定调用哪一张子表，低 12 位则被用来指定表中具体的系统调用：

![](https://s2.loli.net/2025/02/01/7EsiL5ednOkg1Y8.png)

> #### _扩展阅读：KeServiceDescriptorTableFilter_
>
> 自 Windows 10 开始引入了这张表，当 KTHREAD 中设置了 `RestrictedGuiThread` 标志位时会用该表替代 Shadow SSDT，不过目前该表相关的资料暂时比较少（🕊）

## 进程管理

### 一、NT kernel 中的进程与线程

在 Windows NT kernel 当中使用 `_EPROCESS` 结构体来表示一个进程，类似于 Linux 下的 `task_struct`，该结构体当中存储了 Windows 进程的所有信息，所有进程的 `_EPROCESS` 之间构成一个双向链表。

内核态 GS 寄存器指向 `处理器控制区`（Process Control Region），类似于 Linux 下的 `.percpu` 段，其中存放着指向当前线程控制块的指针，在这其中便又存放着指向当前进程控制块的指针。

![](https://s2.loli.net/2025/02/01/a5lbF1fgDAUErcz.png)

### 二、Token：进程权限凭证

正如 Linux 在 `task_struct` 当中使用 `cred` 结构体标识进程的权限，NT kernel 中使用 `_Token` 结构体标识进程的权限。

> 待施工。

## Reference

https://arttnba3.cn/

[Microsoft Learn. Spark possibility. ](https://learn.microsoft.com/en-us/)

《windows内核原理与实现》——潘爱民 著

[CodeMachine - Windows Object Headers](https://codemachine.com/articles/object_headers.html)

[BlackHat USA 2021  - Windows Heap‐Backed Pool](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Windows-Heap-Backed-Pool-The-Good-The-Bad-And-The-Encoded.pdf)

[CodeMachine - Kernel Virtual Address Layout](https://codemachine.com/articles/x64_kernel_virtual_address_space_layout.html)

[[原创]Windows内存篇Ⅱ x64内核内存布局的迁移演变 ](https://bbs.kanxue.com/thread-262931-1.htm)

[Page Frame Number Database](https://flylib.com/books/en/4.491.1.69/1/)

[Windows 系统调用分析与免杀实现](https://myzxcg.com/2022/01/Windows-%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8%E5%88%86%E6%9E%90%E4%B8%8E%E5%85%8D%E6%9D%80%E5%AE%9E%E7%8E%B0/)

[A Syscall Journey in the Windows Kernel](https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/)

[Windows Internals](https://github.com/Faran-17/Windows-Internals)

[探索Windows内核系列——句柄，利用句柄进行进程保护](https://tttang.com/archive/1682/)

[AngelBoy——Windows Kernel Heap: Segment heap in windows kernel Part 1](https://speakerdeck.com/scwuaptx/windows-kernel-heap-segment-heap-in-windows-kernel-part-1)

[Inside Windows Page Frame Number (PFN) - Part 1](https://rayanfam.com/topics/inside-windows-page-frame-number-part1/)

[OSR - Windows Pool Manager](https://www.osr.com/nt-insider/2014-issue1/windows-pool-manager/)

[Exploit Development: Swimming In The (Kernel) Pool - Leveraging Pool Vulnerabilities From Low-Integrity Exploits, Part 1](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/)

[Kernel Pool Exploitation on Windows 7 - Tarjei Mandt](https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf)

[BlackHat USA 2012 - Windows 8 Heap Internals](https://media.blackhat.com/bh-us-12/Briefings/Valasek/BH_US_12_Valasek_Windows_8_Heap_Internals_Slides.pdf)

[Vergilius Project | Kernels](https://www.vergiliusproject.com/kernels)

---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/windows/kernel-mode/basic-knowledge/introduction.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
