import sys
import os

n = int(sys.argv[1])
tests = ['basic-example', 'array_O0', 'fail', 'fail2', 'fail3', 'fail4', 'fail5', 'bomb', 'merge']

print()
print(("Running tests using memory n=" + str(n)))
print()

for t in tests:
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	print(("% TEST: " + t))
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	os.system('time -p python -u run.py ' + str(n) + ' tests/' + t)
	print()
	print()

