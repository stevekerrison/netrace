#!/usr/bin/env python

"""
setup.py file for netrace
"""

from distutils.core import setup, Extension


netrace_module = Extension('_netrace',
                           sources=['netrace_wrap.c', 'netrace.c'],
                           )

setup (name = 'netrace',
       version = '1.0',
       author      = "University of Texas at Austin",
       description = """Dependency-Tracking Trace-Based Network-on-Chip Simulation""",
       ext_modules = [netrace_module],
       py_modules = ["netrace"],
       )

