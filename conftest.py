"""空文件，作用只有一个：让 pytest 把仓库根目录放进 sys.path。

项目采用根目录平铺模块（parser.py / analyzer.py / reporter.py / config.py），
测试里写的是 `from parser import parse_pcap`。有本文件时，直接运行 `pytest`
与 `python -m pytest` 都能导入成功。
"""
