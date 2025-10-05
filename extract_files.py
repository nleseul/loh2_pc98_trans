import configparser
import fnmatch
import os
import subprocess

from compression_util import decompress_bzh

if __name__ == '__main__':
    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")
    config = configfile["Common"]
    source_disks = configfile["SourceDisks"]

    ndc_path = config["NdcPath"]

    source_output_path_base = "local/source_files"
    decompressed_output_path_base = "local/decompressed"

    patterns = [
        "ENDING.BZH",
        "OPENING.BZH",
        "PROG.BZH",
        "UTY.BZH",
        "MON/M_*.BZH",
        "SCENA/*.BZH"
    ]

    for disk_path in source_disks.values():
        print(disk_path)

        folder_list = [""]
        while len(folder_list) > 0:
            folder_name = folder_list.pop(0)

            output_path = os.path.join(source_output_path_base, folder_name)

            list_result = subprocess.run([ndc_path, disk_path, "0", folder_name], capture_output=True, text=True)
            if list_result.returncode != 0:
                print(f"Failed to process folder {folder_name} on source disk {disk_path}: {list_result.stdout}")
            else:
                for line in list_result.stdout.splitlines():
                    table_entries = line.split("\t")
                    if len(table_entries) <= 1:
                        break
                    elif table_entries[0] in [".", ".."]:
                        continue
                    else:
                        entry_name = (folder_name + "/" if len(folder_name) > 0 else "") + table_entries[0]
                        if table_entries[2] == "<DIR>":
                            folder_list.append(entry_name)
                        else:
                            for pattern in patterns:
                                if fnmatch.fnmatch(entry_name, pattern):
                                    print(f"Copying {entry_name}...")

                                    os.makedirs(output_path, exist_ok=True)

                                    get_result = subprocess.run([ndc_path, "G", disk_path, "0", entry_name, output_path], capture_output=True, text=True)
                                    if get_result.returncode != 0:
                                        print("Failed.", get_result.stdout)

                                    break

        print()

    for path, dirs, files in os.walk(source_output_path_base):
        for filename in files:
            file_path = os.path.join(path, filename)
            output_path = os.path.join(decompressed_output_path_base, file_path[len(source_output_path_base)+1:]) + ".bin"
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            print(f"Decompressing {file_path}...")

            with open(file_path, 'rb') as in_file:
                uncompressed_data = decompress_bzh(in_file)
                with open(output_path, 'w+b') as out_file:
                    out_file.write(uncompressed_data)
