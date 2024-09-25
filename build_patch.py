from dataclasses import dataclass
import ips_util
import os

from compression_util import compress_bzh
from trans_util import TranslationCollection


class SpacePool:
    @dataclass
    class Span:
        start:int
        end:int

    def __init__(self):
        self._available_spans:list[SpacePool.Span] = []

    @property
    def total_available_space(self) -> int:
        return sum([s.end - s.start + 1 for s in self._available_spans])

    @property
    def largest_available_space(self) -> int:
        return max([s.end - s.start + 1 for s in self._available_spans])

    def add_space(self, start:int, end:int) -> None:
        if end < start:
            raise Exception("Start must come before end!")

        should_append = True
        for span_index, span in enumerate(self._available_spans):
            if end < span.start:
                self._available_spans.insert(span_index, SpacePool.Span(start, end))
                should_append = False
                break
            elif start >= span.start and start <= span.end:
                print(f"    Space from {start:04x} to {end:04x} overlaps with existing space from {span.start:04x} to {span.end:04x}")
                span.end = max(span.end, end)
                should_append = False
                break
            elif start == span.end + 1:
                span.end = end
                should_append = False
                break

        if should_append:
            self._available_spans.append(SpacePool.Span(start, end))

    def take_space(self, length:int, strategy:str='first') -> int:
        addr = None

        best_index = None
        best_rating = None

        for span_index, span in enumerate(self._available_spans):
            if span.end - span.start + 1 >= length:
                if strategy == 'smallest':
                    span_rating = -(span.end - span.start + 1 - length)
                elif strategy == 'largest':
                    span_rating = span.end - span.start + 1 - length
                else:
                    span_rating = -span_index # First

                if best_rating is None or span_rating > best_rating:
                    best_rating = span_rating
                    best_index = span_index

        if best_index is not None:
            span = self._available_spans[best_index]
            addr = span.start
            span.start += length
            if span.start > span.end:
                del self._available_spans[best_index]
        else:
            raise Exception(f"Unable to find {length} bytes of space! Total available: {self.total_available_space} bytes; largest available: {self.largest_available_space} bytes")

        return addr

    def dump(self):
        print("Available space:")
        for span in self._available_spans:
            print(f"  {span.start:04x}~{span.end:04x} ({span.end - span.start + 1} bytes)")
        print()

    def patch_leftover_space(self, patch:ips_util.Patch) -> None:
        for span in self._available_spans:
            patch.add_rle_record(span.start, b'\x00', span.end - span.start + 1)


def add_table_to_patch(patch:ips_util.Patch, trans:TranslationCollection, pad_length:int|None = None) -> None:
    for key in trans.keys:
        entry = trans[key]
        encoded = entry.text.encode('cp932')

        if pad_length is not None:
            if len(encoded) > pad_length:
                raise Exception(f"String {entry.text} cannot be encoded in {pad_length} bytes")
            encoded = encoded.rjust(pad_length, b' ')

        patch.add_record(key, encoded)


def patch_locations(patch:ips_util.Patch, location_trans:TranslationCollection) -> None:
    location_trans = TranslationCollection.load("yaml/Locations.yaml")
    pool = SpacePool()

    for key in location_trans.keys:
        entry = location_trans[key]
        pool.add_space(key, key+entry.original_byte_length-1)

    for key in location_trans.keys:
        entry = location_trans[key]
        encoded = entry.text.encode('cp932')
        if len(encoded) > 12:
            raise Exception(f"Location string {entry.text} cannot be encoded in 12 bytes")
        else:
            if len(encoded) % 2 == 1:
                encoded += b' '

            if len(encoded) < 12:
                encoded = ((12 - len(encoded)) // 2).to_bytes(1, byteorder='little') + encoded

        new_addr = pool.take_space(len(encoded))
        patch.add_record(new_addr, encoded)

        for ref_addr in entry.reference_addrs:
            patch.add_record(ref_addr, (new_addr - 0x7c00).to_bytes(2, byteorder='little'))

    pool.patch_leftover_space(patch)


def make_program_data_patch(file_data):
    patch = ips_util.Patch()

    patch.add_record(0x7c80, b"   Prologue - Peaceful Days   ")

    patch.add_record(0x7f30, b"At?las\x06")
    patch.add_record(0x7f70, b"Landor\x06")
    patch.add_record(0x7fb0, b"Flora\x06")
    patch.add_record(0x7ff0, b"Cindy\x06")

    add_table_to_patch(patch, TranslationCollection.load("yaml/Spells.yaml"), 8)
    add_table_to_patch(patch, TranslationCollection.load("yaml/Items.yaml"), 14)

    patch_locations(patch, TranslationCollection.load("yaml/Locations.yaml"))

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

