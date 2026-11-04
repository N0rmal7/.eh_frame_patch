# 打包说明

## 产物

运行 `python packaging/build_release.py`，在 `dist/` 下生成两个压缩包：

| 文件 | 用途 | 内容 |
|---|---|---|
| `eh_frame_patch-1.0.1.zip` | **完整包**（源码/文档/测试/样本） | 全部 29 个文件，顶层目录 `eh_frame_patch-1.0.1/` |
| `eh_frame_patch-1.0.1-ida-only.zip` | **直接安装包** | 仅 6 个必需文件，**可直接解压进 IDA 插件目录** |

两个包都是确定性构建：文件顺序排序、时间戳固定为 `2024-01-01 00:00:00`，
相同源码重复打包得到字节一致的归档。

---

## 安装（用 ida-only 包）

`ida-only` 包内**没有** `plugins/` 这一层，因此解压目标就是 IDA 的插件目录：

```powershell
$dst = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
Expand-Archive -Path eh_frame_patch-1.0.1-ida-only.zip -DestinationPath $dst -Force
```

结果：

```
%APPDATA%\Hex-Rays\IDA Pro\plugins\eh_frame_patch.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ehp\__init__.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ehp\asm_engine.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ehp\disasm_preview.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ehp\elf_image.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ehp\plan.py
```

重启 IDA 后，Output 窗口应显示
`eh_frame_patch 1.0.1 loaded (keystone=True, capstone=False)`。

> 不要用 Git Bash / WSL 的 `unzip` 写到该目录：权限受限会失败，请用 PowerShell。

---

## 完整包里各目录的作用

```
eh_frame_patch-1.0.1/
├── README.md              总览、功能表、验证状态
├── VERSION                版本号
├── plugins/               ← 需要安装的部分
│   ├── eh_frame_patch.py  插件主体
│   └── ehp/               不依赖 IDA 的核心库
├── docs/
│   ├── INSTALL.md         安装与排查
│   ├── USAGE.md           用法与 UAF 修复流程
│   ├── IDA_NOTES.md       IDA 9.0 表单/补丁 API 兼容性笔记
│   └── VERIFY.md          验证报告（自动化 vs 实际 IDA）
├── examples/              UAF 修复示例（教学样本 + 真实 AWDP 题目）
├── samples/               测试用 ELF32/ELF64
└── tests/                 单测、真机执行、IDA 内自检
```

---

## 验证完整包

```bash
# 解压后可直接跑，不需要 IDA
cd eh_frame_patch-1.0.1
python -m unittest discover -s tests -p "test_*.py"
# 期望：Ran 30 tests ... OK (skipped=1)
```

WSL 下还能跑真实执行验证与 AWDP 复现：

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/runtime_check.sh      # 期望最后一行 RUNTIME-OK
bash tests/verify_awdp_main.sh   # 期望 orig=134 fixed=0
```

IDA 内自检（需要完整包里的 `tests/ida_selftest.py`）：

```powershell
Start-Process 'D:\...\ida.exe' -ArgumentList '-A',
    '-S"<pkg>\tests\ida_selftest.py"', '"<pkg>\samples\uaf_demo64"'
# 期望 SUMMARY pass=39 fail=0
```

---

## 打包脚本要点

- `EXCLUDE_DIRS`：`__pycache__`、`dist`、`.git`、`out`
- `EXCLUDE_EXT`：`.pyc`、`.pyo`、`.log`、`.i64`、`.id0/.id1/.id2`、`.nam`、`.til`
  ——避免把 IDA 数据库与运行日志打进包里。
- `IDA_ONLY` 列表显式声明 ida-only 包的 6 个文件；`strip_prefix="plugins/"`
  去掉层级，保证可直接解压进插件目录。
