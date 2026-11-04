# eh_frame_patch 操作手册

**适用**：IDA Pro 9.0 · x86 / x86-64 · AWDP-pwn 热修复
**目标**：把修复代码写进 `.eh_frame`，在漏洞处只留一条 `jmp`

---

## 0. 先理解三件事

| 操作 | 实际效果 |
|---|---|
| **Patch** | 只改 IDA 数据库里的字节，**磁盘文件没变** |
| **Export** | 把补丁写进**新的** ELF 文件，原文件不动 |
| **Add exec bit** | 把**整个 `.eh_frame` 段**改为可执行：IDA 段权限 + 文件 `PF_X`（自动备份） |

三者互相独立。要跑起来必须：`Patch` → `Export`（或 `Add exec bit`）。

---

## 1. 菜单与快捷键

```
Edit → eh_frame_patch
├── Patch...              Ctrl+Alt+J        在光标处汇编并写入
├── Goto safe area        Ctrl+Alt+K        ★跳到可写地址头
├── Preview                              查看补丁预览（不写）
├── Permissions...                       段权限 + 是否依赖栈展开
├── Export...             Ctrl+Alt+Shift+J 导出补丁副本
├── Add exec bit          Ctrl+Alt+Shift+X ★给 .eh_frame 加 PF_X
└── Undo                                 撤销本次会话上一次写入
```

反汇编窗口 / Hex 窗口右键也有同一组菜单。

> `Ctrl+Alt+E` 被 QQ 等软件占用，所以本插件不用它。

---

## 2. 最常用流程（UAF 修复）

### 第 1 步：找到可写地址

按 **`Ctrl+Alt+K`**。

插件会自动判断这个程序**是否依赖栈展开**：

**情况 A：纯 C 程序（只链接 libc）**

```
跳到 0x2110，预算 516
```

覆盖 CIE/FDE 对运行没有影响，直接用最大空间。

**情况 B：C++ 程序（有 libstdc++ / __cxa_throw）**

```
警告：该程序运行时会栈展开
使用 0x2175（尾部填充，11 字节）
```

因为覆盖整条 CIE 会在第一次抛异常时崩。

### 第 2 步：写跳板

编辑器里填：

| 字段 | 值 |
|---|---|
| **Target VA (hex)** | 自动填好（如 `0x2110`） |
| **Overwrite budget** | 自动填好（如 `516`） |
| **Declared return VA** | 留空 |
| **NOP-pad** | **不勾**（手动补 NOP 更可控） |

**Assembly**（按你的程序改地址）：

```asm
mov eax, dword ptr [rbp-4]       ; idx 的来源，看反汇编确认
cdqe
lea rdx, [0x4060]                ; &数组（写绝对地址）
mov qword ptr [rdx + rax*8], 0   ; 数组[idx] = 0   ← 修复本体
jmp 0x16CC                       ; 跳回原流程
```

点 **Patch**。

### 第 3 步：在漏洞处写 jmp

光标移到 `call free` 之后的第一条指令（如 `0x16C0`），按 **`Ctrl+Alt+J`**：

| 字段 | 值 |
|---|---|
| **Target VA** | `0x16C0` |
| **Overwrite budget** | `12`（到 `leave` 之前的长度） |
| **NOP-pad** | **勾选** |

```asm
jmp 0x2110
```

点 **Patch**。预期 `E9 xx xx xx xx` + 7 个 `90`。

### 第 4 步：让整个 `.eh_frame` 可执行

按 **`Ctrl+Alt+Shift+X`**（Add exec bit）。

它会**同时**改两处，缺一不可：

| 层次 | 改什么 | 作用 |
|---|---|---|
| **IDA 段权限** | `R--` → `R-X` | 反汇编器把该段当代码，段窗口显示 `R-X` |
| **ELF `p_flags`** | 加 `PF_X` | 内核真正允许执行，**运行时必须这一项** |

实测结果：

```
IDA perm before : R-- (4)
IDA perm after  : R-X (5)
ELF PT_LOAD     : R--  ->  R-X
whole_segment   : True（段首和段尾都可执行）
```

首次运行自动写 `xxx.bak`。重复运行是幂等的，不会重复修改。

> `PF_X` 覆盖整个 PT_LOAD（如 `0x2000-0x2318`），不只 `.eh_frame`。

### 第 5 步：导出副本

按 **`Ctrl+Alt+Shift+J`**（Export），存成新文件（如 `main_fixed`）。

弹窗会列出所有被写入的区间，核对是否包含**两处**（跳板 + 入口 jmp）。

---

## 3. 编辑器字段说明

| 字段 | 说明 |
|---|---|
| **Target VA (hex)** | IDA 里的虚拟地址，不是文件偏移。写 `0x2110` 或 `2110` 都行 |
| **Overwrite budget (decimal)** | 允许覆盖的字节数，**十进制**。填 `516`，不要填 `0x204` |
| **Declared return VA** | 可选，仅用于展示和映射检查。**不会**自动生成 `jmp` |
| **IDA segment** | 只读，显示段名/范围/权限 |
| **Assembly** | Intel 语法，一行一条。`;` `#` `//` 之后是注释 |
| **Convert patched range to code** | 默认开。只把补丁区间转指令，**不碰整段** |
| **NOP-pad to the full budget** | 默认关。勾选后用 `90` 填满预算 |
| **Allow segment crossing** | 默认关。只放行段边界，不放行未映射地址 |

底部状态栏：`N code bytes + M NOP bytes; X errors, Y warnings`。
**有 error 时 Patch 按钮变灰**，看右侧 `checks:` 找原因。

---

## 4. 写汇编的常见坑

### 4.1 位宽必须写明

```asm
mov [rdx + rax*8], 0          ; ❌ Invalid operand（不知道写多宽）
mov qword ptr [rdx + rax*8], 0 ; ✅ 64 位指针
mov dword ptr [rdx + rax*8], 0 ; ✅ 32 位 int
```

位宽错了会只清一半（64 位指针只清低 32 位 → 漏洞还在）。

### 4.2 IDA 的名字不是汇编符号

| 写这个 | 报错 | 改成 |
|---|---|---|
| `call free` | 找不到符号 | `call 0x1100`（`free@plt` 的地址） |
| `[rbp+var_14]` | 找不到符号 | `[rbp-0x14]` |
| `lea rdx, addrList` | 可能找不到 | `lea rdx, [0x4060]` |

### 4.3 数组寻址：先取基址

```asm
lea rdx, [0x4060]                ; ✅ 取 &数组，Keystone 编成 RIP 相对
mov qword ptr [rdx + rax*8], 0

lea rdx, [0x4060 + rax*8]        ; ❌ 编成绝对地址，PIE 下必错
```

### 4.4 清零的是槽位，不是寄存器

```asm
xor eax, eax                     ; ❌ 只清寄存器，内存里的悬空指针还在
mov qword ptr [rdx + rax*8], 0   ; ✅ 清数组槽位
```

### 4.5 `free` 之后不能信 `rdi` / `rax` / `rcx` / `rdx`

实测 `free` 返回后：`rax → 0`、`rdi → 0x7`。要跨 `call` 保存值，只能用
**`rbx` / `rbp` / `r12-r15`**（callee-saved）。

```asm
lea rbx, [0x4060]                ; rbx 存槽位地址
lea rbx, [rbx + rax*8]
mov rdi, qword ptr [rbx]
call 0x1100                      ; free
mov qword ptr [rbx], 0           ; ✅ rbx 还活着
```

### 4.6 不要覆盖 `leave; ret`

`leave` 负责 `mov rsp,rbp; pop rbp`。覆盖它，`ret` 会弹错返回地址。
而且错误分支（如 `Invalid Index`）经常也 `jmp` 到 `leave`。

---

## 5. 常见错误信息

| 信息 | 处理 |
|---|---|
| `only N byte(s) fit` | 超预算。缩短代码，或换更大的地址 |
| `code crosses the end of .eh_frame` | 跨段。挪地址，或勾 Allow crossing |
| `branch target 0x.... is not mapped` | `jmp` 目标写错 |
| `unresolved symbol(s): var_14` | IDA 伪名，改用 `[rbp-0x14]` |
| `Invalid operand` | 缺位宽，补 `qword ptr` |
| `nothing to assemble yet` | 编辑器空着，正常提示（不是错误） |
| `no execute permission in IDA` | 只是提醒。真正能否执行看 PF_X |
| `unwind data` 警告 | 提醒覆盖的可能是有效展开信息 |
| `No usable overwrite area` | `.eh_frame` 没有可写区，手动选地址 |

---

## 6. 验证修复是否成功

```bash
# 1. 确认 PF_X 生效（应该是 R E，不是 R  ）
readelf -lW ./main_fixed | grep -A1 'LOAD.*0x002000'

# 2. 确认两处补丁都在
objdump -d -M intel ./main_fixed --start-address=0x16C0 --stop-address=0x16CC
objdump -d -M intel ./main_fixed --start-address=0x2110 --stop-address=0x2130

# 3. 跑功能测试
./main_fixed
```

**必须验证三条路径**：正常操作、漏洞路径（重复释放）、错误路径（非法索引）。

> 输入格式注意：`readNum` 每次固定读 4 字节，所以每个字段占 4 字节。
> 用 `printf '%-4s' 1` 这种写法生成输入。

---

## 7. 交付前检查清单

- [ ] 清零的是**实际保存悬空指针的槽位**，位宽正确
- [ ] 入口覆盖的是**完整指令**，没切到别的指令中间
- [ ] 洞区预算核对过，被覆盖的原行为已重现
- [ ] **没有**覆盖 `leave` / `ret`
- [ ] 返回地址正确
- [ ] 原始文件已备份（`Add exec bit` 会自动生成 `.bak`）
- [ ] 导出副本**包含两处**补丁
- [ ] `.eh_frame` 的 PT_LOAD 有 `E` 标志
- [ ] 三条路径（正常 / 漏洞 / 错误）都实际跑过

---

## 8. 已知限制

| 项 | 说明 |
|---|---|
| 只支持 x86 / x86-64 | Intel 语法 |
| 不自动搬迁被覆盖的指令 | 跳板要自己写全 |
| 不自动修正 RIP 相对寻址 | 写绝对地址，让 Keystone 重新编码 |
| `Add exec bit` 影响整个 PT_LOAD | 不只你的 stub |
| 覆盖 CIE/FDE 影响栈展开 | 纯 C 程序无感，C++ 抛异常会崩 |

---

## 9. 一句话速查

```
Ctrl+Alt+K  找地址   →   写跳板   →   Ctrl+Alt+J 写 jmp
             →   Ctrl+Alt+Shift+X 加执行权限   →   Ctrl+Alt+Shift+J 导出
```
