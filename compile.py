import os

iDebug = input('Debug mode? Y/N: ')

cmd = "pyinstaller client.py --onefile --clean"
if iDebug == 'Y':
    debug = True
elif iDebug == 'N':
    debug = False
else:
    print('Input must be Y/N')
    exit

if not debug:
    cmd += " --noconsole"

os.system(cmd)
