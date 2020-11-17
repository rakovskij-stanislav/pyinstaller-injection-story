import zlib
import base64
import marshal
import os

target = "injector.py"

inp = open(target, "rb").read()

fish = "import base64\nexec(base64.b64decode(\""+base64.b64encode(inp)+"\"))"
open(target+".fish.py", "w").write(fish)
import py_compile
to_compress = open(py_compile.compile(target+".fish.py") or target+".fish.pyc", "rb").read()[8:]


os.remove(target+".fish.pyc")
os.remove(target+".fish.py")
    
    
#print(to_compress)
open(target+".zlib", "wb").write(zlib.compress(
    to_compress
))
with open(target+".malen", "w") as malen:
    malen.write(str(len(to_compress)))

print "Preparations done!"
