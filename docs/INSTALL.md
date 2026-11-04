# 安装 / 更新 1.0.1

IDA Pro 9.0，x86/x86-64；IDA 使用的 Python 中需要 Keystone，界面使用 IDA 自带 PyQt5。Capstone 可选。

在 IDA Python 控制台检查依赖：

```python
import keystone
from PyQt5 import QtWidgets
print(keystone.__version__)
```

1. 退出需要更新的 IDA 实例。
2. 解压 ida-only 包，将 eh_frame_patch.py 和完整 ehp/ 目录放入同一个 IDA 插件目录。
3. 更新时一起替换两部分，并确保其他插件目录没有旧版本重复副本。
4. 重启 IDA，确认输出窗口显示 eh_frame_patch 1.0.1 loaded。
5. Edit → eh_frame_patch 或 Ctrl+Alt+J 打开编辑器。

定位用户插件目录：

```python
import os, ida_diskio
print(os.path.join(ida_diskio.get_user_idadir(), "plugins"))
```

安装 Keystone 时选用 IDA 实际加载的 Python 环境。Keypatch 能正常汇编时通常不需重复安装。
本评测没有替换现有安装，请先在样本数据库副本上试用。
卸载时退出 IDA，移除入口及 ehp/；卸载不会恢复已修改的 IDB 或 ELF 字节。
