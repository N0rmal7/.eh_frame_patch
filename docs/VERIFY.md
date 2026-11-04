# 1.0.1 复现与验证范围

本文件记录本次重新执行的验证，不继承 1.0.0 的通过声明。

## 自动测试

在项目目录执行：

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

Windows CPython 3.12：47 项，43 通过，4 项平台条件跳过。
WSL Ubuntu 22.04 / Python 3.10 / Keystone 0.9.2：47 项全部通过。

跳过项包括 Linux ELF 执行、AWDP 行为回归、POSIX 模式位、无权限创建符号链接。
WSL 验证实际执行 ELF32、ELF64，验证原始 UAF 与修复后拒绝写入；AWDP main 验证 exit/add/delete 正常路径和 double-delete 被拒绝，并核验输入文件哈希未变。

## 真实 IDA 9.0

- `tests/ida_review.py`：实际补丁 API、预览过期拒绝、无效计划拒绝、撤销冲突、部分写入恢复、显式外部补丁收集、非零重定位后导出、PF_X、与 Keypatch 共存。
- `tests/ida_form_review.py`：真实 Qt 渲染，修改汇编/预算/NOP 选项，点击实际 Patch 按钮并检查最终计划，保存截图。警告确认在测试中自动应答；没有手工确认风险对话框。
- `tests/ida_export_e2e.py`：插件 apply_patch → 插件 export_executable_copy → ELF 副本。断言洞区、入口跳转、GOT 和 leave/ret 字节，再通过 WSL 运行导出文件验证 double-delete。

运行方式：以 IDA 可执行文件启动隔离的数据库，用 `-S"脚本绝对路径"` 指定测试脚本。API 测试可加 `-A`；表单渲染测试不要加 `-A`。不要关闭其他 IDA 进程，不要使用生产数据库运行测试。

本次 JSON、日志和截图保留在交付工作目录的 `evidence/` 中；数据库和生成的 ELF 不进入安装包。`docs/REVIEW.md` 给出评测与限制。

未覆盖：所有恶意 ELF 变体、完整栈展开兼容、其他 IDA 版本、真实比赛 checker、自动指令搬迁。数据库导出不等于比赛验收通过。
