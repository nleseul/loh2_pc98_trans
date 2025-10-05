import time
import typing

from compression_util import *


def decompress(filename:str) -> None:
    with open(filename, 'rb') as in_file:
        decompress_bzh(in_file)


def compress(filename:str) -> None:
    with open(filename, 'rb') as in_file:
        file_data = in_file.read()
    compress_bzh(file_data)


def do_timing(desc:str, func:typing.Callable) -> None:
    start = time.perf_counter()

    func()

    end = time.perf_counter()

    print(f"{desc} - {end - start:.2f}s")


def main() -> None:

    do_timing("Decompress small file", lambda: decompress("local/source_files/SCENA/T_000.BZH"))
    do_timing("Decompress large file", lambda: decompress("local/source_files/OPENING.BZH"))

    do_timing("Compress small file", lambda: compress("local/decompressed/SCENA/T_000.BZH.bin"))
    do_timing("Compress large file", lambda: compress("local/decompressed/OPENING.BZH.bin"))


if __name__ == '__main__':
    main()