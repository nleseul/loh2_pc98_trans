import configparser
import fnmatch
import os
import subprocess

if __name__ == '__main__':
    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")
    config = configfile["Common"]
    source_disks = configfile["SourceDisks"]

    ndc_path = config["NdcPath"]

    output_path_base = "local/source_files"

    patterns = [
        "PROG.BZH",
        "MON/M_*.BZH",
        "SCENA/*.BZH"
    ]

    for disk_path in source_disks.values():
        print(disk_path)

        folder_list = [""]
        while len(folder_list) > 0:
            folder_name = folder_list.pop(0)

            output_path = os.path.join(output_path_base, folder_name)

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
                            #print(f"{folder_name} {table_entries[0]} (Directory)")
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
