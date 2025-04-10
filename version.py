#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
版本信息模块
"""

# 版本信息
VERSION = "1.2.0"
PROGRAM_NAME = "SafeLine AutoBlocker"
AUTHOR = "Clion Nieh"
DATE = "2025.4.6"
LICENSE = "MIT"

# 获取完整版本字符串
def get_version_string():
    """返回格式化的版本信息字符串"""
    return f"{PROGRAM_NAME} v{VERSION}\n作者: {AUTHOR}\n日期: {DATE}\n许可证: {LICENSE}"