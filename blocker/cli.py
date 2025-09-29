# blocker/cli.py
import json
from pathlib import Path
import argparse


BASE = Path(__file__).parent
STATE_FILE = BASE / 'blocklist.json'


def load():
if STATE_FILE.exists():
return json.loads(STATE_FILE.read_text())
return []


def save(data):
STATE_FILE.write_text(json.dumps(data, indent=2))


parser = argparse.ArgumentParser(description='Manage blocklist')
parser.add_argument('action', choices=['list','add','remove','clear'])
parser.add_argument('token', nargs='?')
args = parser.parse_args()


data = load()
if args.action == 'list':
for t in data:
print(t)
elif args.action == 'add':
if not args.token:
print('Specify token to add')
else:
data.append(args.token)
save(data)
print('Added')
elif args.action == 'remove':
if not args.token:
print('Specify token to remove')
else:
data = [x for x in data if x != args.token]
save(data)
print('Removed')
elif args.action == 'clear':
save([])
print('Cleared')