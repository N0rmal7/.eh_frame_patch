# eh_frame_patch

**IDA Pro 9.0 插件 —— 让 `.eh_frame` 也能像代码段一样被汇编编辑。**

Keypatch 只允许汇编到 IDA 认为是"代码"的区域。`.eh_frame` 是只读数据段，
所以 Keypatch 直接拒绝编辑。而 AWDP-pwn 里最实用的热修复手法恰好需要它：

```
漏洞处（只剩几个字节）        :  jmp <stub>
.eh_frame（空间充足）         :  mov qword ptr [<指针槽位>], 0
                                 jmp <原流程>
```

本插件把这件事做成 GUI 工具，并负责检查、写入、导出与执行权限。

---

## 为什么需要它

AWDP 防守时经常遇到 UAF：`free(ptr)` 之后没有清零，导致指针悬空。
修复只要一句 `*(槽位) = NULL`，但**漏洞点附近往往放不下**：

| 约束 | 现实 |
|---|---|
| `free` 之后到函数结尾 | 常常只有 5-12 字节，放不下算地址 + 清零 |
| 想跳到 `.eh_frame` 里写 | Keypatch 不让编辑数据段 |
| 手写 hex 补丁 | 相对跳转、RIP 相对寻址极易算错 |
| 忘了加 `PF_X` | 补丁写对了也跑不起来，直接 SIGSEGV |

---

## 功能

| 菜单项 | 快捷键 | 作用 |
|---|---|---|
| **Patch...** | `Ctrl+Alt+J` | 在任意已映射地址汇编并写入（含 `.eh_frame`） |
| **Goto safe area** | `Ctrl+Alt+K` | 跳到可写地址头，自动判断该用多大空间 |
| **Preview** | — | 查看补丁预览（不写入） |
| **Permissions...** | — | 段权限 + 是否依赖栈展开 |
| **Export...** | `Ctrl+Alt+Shift+J` | 导出包含补丁的新 ELF |
| **Add exec bit** | `Ctrl+Alt+Shift+X` | 把整个 `.eh_frame` 段改为可执行 |
| **Undo** | — | 撤销本次会话上一次写入 |

### 关键特性

- **任意地址汇编** —— 数据段、`.eh_frame`、未定义字节都不再受限
- **块内标签** —— `start:` / `jmp start`，`;` `#` `//` 注释
- **IDA 符号解析** —— `jmp 0x1100`、`lea rdx, [0x4060]` 自动处理
- **预算 / 跨段校验** —— 超长拒绝，跨段需显式放行
- **原始字节预览** —— 写入前看到会被覆盖的内容
- **NOP 填充** —— 可选，补齐到预算
- **受控写入** —— 走 IDA 补丁接口，回读校验，只重新识别补丁区间
- **智能可写区** —— 区分「免费」「代价低」「代价高」三档
- **栈展开探测** —— 自动判断覆盖 `.eh_frame` 是否影响运行

---

## 安装

需要 **IDA Pro 9.0**（x86 / x86-64）和 **Keystone 引擎**。

```powershell
$dst = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
Copy-Item .\plugins\eh_frame_patch.py "$dst\" -Force
Copy-Item .\plugins\ehp "$dst\ehp" -Recurse -Force
```

重启 IDA，Output 窗口应出现：

```
eh_frame_patch 1.0.0 loaded (keystone=True, capstone=False)
```

`keystone=True` 是必须的。若为 False，把 `keystone-engine` 装进 **IDA 自带的 Python**：

```powershell
& '<IDA>\python311\python.exe' -m pip install keystone-engine
```

详细安装与排错见 [docs/INSTALL.md](docs/INSTALL.md)。

---

## 快速开始

按 **`Ctrl+Alt+K`** 找地址 → 写跳板 → **`Ctrl+Alt+J`** 写 `jmp`
→ **`Ctrl+Alt+Shift+X`** 加执行权限 → **`Ctrl+Alt+Shift+J`** 导出

完整操作手册（含常见坑和错误对照表）见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

---

## 工作示例

针对一个真实的 AWDP 题目（`samples/main`，UAF：`free(addrList[idx])` 后未清零）：

**洞区 `0x2110`（516 字节可用）**

```asm
mov eax, dword ptr [rbp-4]       ; idx 的来源，按实际反汇编确认
cdqe
lea rdx, [0x4060]                ; &addrList（绝对地址，Keystone 编成 RIP 相对）
mov qword ptr [rdx + rax*8], 0   ; addrList[idx] = NULL   ← 修复本体
jmp 0x16CC                       ; 跳回原函数的 leave; ret
```

**入口 `0x16C0`（12 字节）**

```asm
jmp 0x2110
```

结果：

```
原始程序：double free or corruption (top)   rc=134
修复程序：第二次 delete 返回 Invalid Index   rc=0
```

可运行的脚本示例见 [examples/awdp_main_fix.py](examples/awdp_main_fix.py)。

---

## 写汇编的三个硬规则

```asm
; 1. 内存操作必须带位宽
mov qword ptr [rdx + rax*8], 0    ; OK
mov [rdx + rax*8], 0              ; 报错 Invalid operand

; 2. 数组寻址先取基址（PIE 安全）
lea rdx, [0x4060]                 ; OK  Keystone 编成 RIP 相对
lea rdx, [0x4060 + rax*8]         ; 错  编成绝对地址，PIE 下必错

; 3. free 之后只能信 callee-saved 寄存器
lea rbx, [rbx + rax*8]            ; rbx 跨 call 有效
mov qword ptr [rbx], 0            ; OK
; rdi / rax / rcx / rdx 都会被 free 破坏
```

---

## 关于 `.eh_frame` 的安全性

覆盖 `.eh_frame` 是否影响运行，**取决于程序是否使用栈展开**：

| 程序类型 | 覆盖后果 |
|---|---|
| 纯 C，仅链接 libc | 运行期不解析，通常无影响 |
| C++ / `-fexceptions` / `backtrace` | 首次抛异常即 SIGSEGV |

插件的 **Goto safe area** 会自动检测（查 `__cxa_throw` / `libstdc++` / `.gcc_except_table`），
并据此决定给"最大空间"还是"只给尾部填充"。

---

## 目录结构

```
plugins/
  eh_frame_patch.py    IDA 侧：动作、Qt 编辑器、写入、导出
  ehp/                 不依赖 IDA 的核心库（可脱离 IDA 单测）
    asm_engine.py      Keystone 封装、标签、注释、符号解析
    plan.py            预算 / 跨段 / 权限校验、NOP 填充
    elf_image.py       ELF32/64 读写、PF_X 修改
    unwind_cave.py     .eh_frame 可覆盖区分析
    aligned_heads.py   16 字节对齐可写头枚举
    unwind_probe.py    栈展开依赖探测
    disasm_preview.py  可选 Capstone 反汇编预览
docs/                  安装 / 操作 / 兼容性笔记 / 验证报告
examples/              UAF 修复示例
samples/               测试用 ELF32 / ELF64
tests/                 单元测试 + IDA 内自检脚本
```

核心库 `ehp/` **不 import 任何 IDA 模块**，可直接用 CPython 跑测试。

---

## 测试

```bash
cd tests
python -m unittest discover -s . -p "test_*.py"
```

覆盖：汇编引擎、补丁规划、ELF 读写、`.eh_frame` 可覆盖区、栈展开探测。

IDA 内自检（需真实 IDA）：

```powershell
ida.exe -A -S"tests\ida_selftest.py" samples\uaf_demo64
```

详见 [docs/VERIFY.md](docs/VERIFY.md)。

---

## 已知限制

- 仅支持 **x86 / x86-64**，Intel 语法
- **不自动搬迁**被覆盖的指令，跳板需自己写全
- **不自动修正** RIP 相对寻址（写绝对地址，让 Keystone 重新编码）
- `Add exec bit` 影响整个 PT_LOAD，不只 `.eh_frame`
- 覆盖 CIE/FDE 会影响栈展开（插件会提示，但不阻止）

---

## 与 Keypatch 共存

本插件不 import、不修改 `keypatch.py`。动作名前缀 `eh_frame_patch:`，
与 Keypatch 的 `Kp_MC_*` 无冲突，可同时启用。

---

## 许可

MIT
