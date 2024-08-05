import ips_util
import os

from compression_util import compress_bzh


def make_program_data_patch(file_data):
    patch = ips_util.Patch()

    patch.add_record(0x7c80, b"   Prologue - Peaceful Days   ")

    patch.add_record(0x7f30, b"At?las\x06")
    patch.add_record(0x7f70, b"Landor\x06")
    patch.add_record(0x7fb0, b"Flora\x06")
    patch.add_record(0x7ff0, b"Cindy\x06")

    return patch


if __name__ == "__main__":
    decompressed_output_path_base = "local/decompressed"
    modified_output_path_base = "local/modified"
    recompressed_output_path_base = "local/recompressed"

    for path, dirs, files in os.walk(decompressed_output_path_base):
        for filename in files:
            file_path = os.path.join(path, filename)
            modified_path = os.path.join(modified_output_path_base, file_path[len(decompressed_output_path_base)+1:])

            print(modified_path)

            with open(file_path, 'rb') as in_file:
                file_data = in_file.read()
            patch = None

            if modified_path.endswith("PROG.BZH.bin"):
                patch = make_program_data_patch(file_data)

            if patch is not None:
                patched_data = patch.apply(file_data)

                os.makedirs(os.path.dirname(modified_path), exist_ok=True)
                with open(modified_path, 'w+b') as out_file:
                    out_file.write(patched_data)
    print()

    for path, dirs, files in os.walk(modified_output_path_base):
        for filename in files:
            file_path = os.path.join(path, filename)
            recompressed_path = os.path.join(recompressed_output_path_base, file_path[len(modified_output_path_base)+1:-4])

            print(recompressed_path)

            with open(file_path, 'rb') as in_file:
                file_data = in_file.read()

            compressed_data = compress_bzh(file_data)

            os.makedirs(os.path.dirname(recompressed_path), exist_ok=True)
            with open(recompressed_path, 'w+b') as out_file:
                out_file.write(compressed_data)
    print()

