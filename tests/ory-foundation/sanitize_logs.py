"""Emit diagnostic logs without credential-bearing lines or fixture identifiers."""
import re
import sys

for line in sys.stdin:
    if re.search(r'password|secret|dsn|session.token|authorization|cookie|credentials|hashed_password|postgres://', line, re.I):
        print('[credential-bearing diagnostic line omitted]')
        continue
    line = re.sub(r'[\w.+-]+@[\w.-]+', '[email]', line)
    line = re.sub(r'eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}', '[token]', line)
    print(line, end='')
