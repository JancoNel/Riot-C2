import os
w = os

file_exists = True
try:
    w.remove('poes.jouma')
except:
    file_exists = False

if file_exists:
    w.system('pip install -r requirements.txt')
    w.remove('requirements.txt')
    file_exists = False
else:
    pass

Ding_lering = w.system('python server.py')