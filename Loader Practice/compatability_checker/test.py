import os
import sys
import shutil
import pefile
import subprocess
import win32com.shell.shell as shell

temp_dir = "temp"
source_dir = "test-binaries"


def delete_temp():
    shutil.rmtree(temp_dir)

def create_temp():
    if os.path.exists(temp_dir):
        delete_temp()
    os.mkdir(temp_dir)

def main():
    print("> Preparing...")
    targets = [target for target in os.listdir(source_dir) if target.endswith(".exe")]
    print(targets)
    for target in targets:
        target_full_path = os.path.join(source_dir, target)
        mem = open(target_full_path, "rb").read()
        ov_offset = pefile.PE(target_full_path).get_overlay_data_start_offset()
        open(os.path.join(temp_dir, target + ".executable"), "wb").write(mem[:ov_offset])
        while ov_offset < len(mem) and mem[ov_offset] == b"\x00":
            ov_offset += 1
        open(os.path.join(temp_dir, target+".pkg"), "wb").write(mem[ov_offset:])
    print("> Done. Count:", len(targets))
    f = open("report.txt", "w")
    for executable in targets:
        executable_path = os.path.join(temp_dir, executable+".executable")
        result = []
        print("Check", executable)
        for package in targets:
            #if executable == package:
            #    continue
            package_path = os.path.join(temp_dir, package + ".pkg")

            new_executable_path = package_path[:-4]+".exe"
            shutil.move(executable_path, new_executable_path)
            executable_path = new_executable_path
            print(">", executable_path)

            out = subprocess.Popen([executable_path], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)

            t = out.communicate()[0], out.returncode
            print(">", t)
            if t[-1] in [0, 1]: # errorcode, 0 - ok, 1 - error (volatility with no params returns 1)
                result.append("+")
            else:
                result.append("-")
        os.remove(executable_path)

        f.write(executable + "   " + " ".join(result)+"\n")
    f.close()




if __name__ == '__main__':
    create_temp()
    main()
    #delete_temp()