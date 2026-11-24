#!/usr/bin/env python3
"""Run from repository root via asciinema; commands and output are real."""
import subprocess
import sys
import time

def command(text):
    sys.stdout.write('\033[1;32m$ \033[0m')
    sys.stdout.flush()
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(.018)
    print(flush=True)
    result = subprocess.run(text, shell=True)
    print('\033[2mexit=%d\033[0m' % result.returncode, flush=True)
    time.sleep(1.5)

print('\033[2J\033[Hssh-keyaudit-lite  |  one file, Python stdlib, no pip install\n', flush=True)
time.sleep(.5)
command('python3 ssh_keyaudit_lite.py --demo')
time.sleep(1.5)
