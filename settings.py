#!/usr/bin/python
# -*- coding: utf-8 -*-

# define patterns for badfunctions, securefunctions
#
patterns = [
    ["echo", ["htmlentities", "htmlspecialchars"], "Cross-Site Scripting"],
    ["print", ["htmlentities", "htmlspecialchars"], "Cross-Site Scripting"],
    ["print_r", ["htmlentities", "htmlspecialchars"], "Cross-Site Scripting"]
]