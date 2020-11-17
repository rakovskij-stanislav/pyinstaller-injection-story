import base64
a = open("injector.py", "rb").read()
b = "import base64;exec(base64.b64decode('"+base64.b64encode(a).decode()+"'))"
open("injector.py.repl.txt", "w").write(b)