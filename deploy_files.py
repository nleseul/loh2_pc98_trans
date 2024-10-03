import configparser
import os
import subprocess


def main() -> None:
    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")
    config = configfile["Common"]
    deploy_disks = configfile["DeployDisks"]
    base_path = deploy_disks["BasePath"]

    ndc_path = config["NdcPath"]

    for key, disk_path in deploy_disks.items():
        if key == "BasePath".lower():
            continue

        print(disk_path)

        folder_list = [base_path]
        files_to_check:list[tuple[str, int]] = []

        for folder_name in folder_list:

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
                            entry_size = int(table_entries[2].replace(',', ''))
                            files_to_check.append((entry_name, entry_size))

        for file_path, file_size in files_to_check:
            local_path = os.path.join("local/recompressed/", file_path[len(base_path) + 1:])
            if os.path.exists(local_path):
                local_size = os.path.getsize(local_path)
                folder_name = os.path.dirname(file_path)
                print(f"Replacing {file_path} ({file_size} bytes) with {local_path} ({local_size} bytes)...")

                delete_result = subprocess.run([ndc_path, "D", disk_path, "0", file_path], capture_output=True, text=True)
                if delete_result.returncode != 0:
                    print("Delete failed.", delete_result.stdout)

                put_result = subprocess.run([ndc_path, "P", disk_path, "0", local_path, folder_name], capture_output=True, text=True)
                if put_result.returncode != 0:
                    print("Put failed.", put_result.stdout)


if __name__ == '__main__':
    main()