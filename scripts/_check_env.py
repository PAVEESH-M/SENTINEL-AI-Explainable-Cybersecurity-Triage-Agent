from pathlib import Path
lines = Path('.env').read_text().splitlines()
for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    if '=' in line:
        k, v = line.split('=', 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        print(f'{k}: {"SET" if v and not v.startswith("#") else "empty"}')
