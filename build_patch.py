from dataclasses import dataclass
import ips_util
import os

from compression_util import compress_bzh
from ds6_event_util import *
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


def make_program_data_patch() -> ips_util.Patch:
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


def make_data_file_patch(yaml_path:str, code_base_addr:int, data_base_addr:int) -> ips_util.Patch:
    #base_name = os.path.splitext(os.path.basename(file_path))[0]
    #output_path = os.path.join("yaml/Combats", f"{base_name}.yaml")

    trans = TranslationCollection.load(yaml_path)
    if trans.empty:
        return None

    patch = ips_util.Patch()

    space_pool = SpacePool()

    # Maps old address to new address
    relocations:dict[int, int] = {}

    # Maps new address of reference to old address of target
    references_to_relocate:dict[int, int] = {}


    for key in trans.keys:
        entry = trans[key]

        if entry.is_relocatable:
            space_pool.add_space(key, key + entry.original_byte_length - 1)
            #print(f"Adding {entry.original_byte_length} bytes at {key:04x}")

    #space_pool.dump()

    for key in trans.keys:
        entry = trans[key]
        encoded, references, locators = encode_event_string(entry.text)

        if entry.is_relocatable:
            new_addr = space_pool.take_space(len(encoded))
            #print(f"Relocating {key:04x} to {new_addr:04x}")
        else:
            #print(f"Non-relocatable event {key:04x}")
            if entry.max_byte_length is None:
                raise Exception(f"Non-relocatable event at {key:04x} should have a defined max_byte_length!")
            encoded = encoded.ljust(entry.max_byte_length, b'\x00')

            new_addr = key

        patch.add_record(new_addr - data_base_addr, encoded)

        relocations[key] = new_addr
        for locator in locators:
            relocations[locator.addr] = new_addr + locator.offset
            #print(f"Locator at {locator.addr:04x} moved to {new_addr + locator.offset:04x}")

        for code_reference_addr in entry.reference_addrs:
            #print(f"Code reference to {key:04x} at {code_reference_addr:04x} will need updated")
            references_to_relocate[code_reference_addr - code_base_addr + data_base_addr] = key

        for reference in references:
            #print(f"Reference to {reference.addr:04x} at {new_addr + reference.offset:04x} (formerly {key + reference.offset:04x}) will need updated")
            references_to_relocate[new_addr + reference.offset] = reference.addr

    for reference_addr, reference_target_addr in references_to_relocate.items():
        if reference_target_addr not in relocations:
            raise Exception(f"Trying to update reference to {reference_target_addr:04x}, which is not in the relocation table")
        new_target_addr = relocations[reference_target_addr]

        #print(f"Updating reference to {reference_target_addr:04x} at {reference_addr:04x} to {new_target_addr:04x}")

        patch.add_record(reference_addr - data_base_addr, int.to_bytes(new_target_addr, length=2, byteorder='little'))

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
                patch = make_program_data_patch()
            elif modified_path.startswith("local/modified/MON/"):
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                yaml_path = os.path.join("yaml/Combats", f"{base_name}.yaml")
                patch = make_data_file_patch(yaml_path, 0xed40, 0x7140)
            elif modified_path.startswith("local/modified/SCENA/"):
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                yaml_path = os.path.join("yaml/Scenarios", f"{base_name}.yaml")
                patch = make_data_file_patch(yaml_path, 0xd53e, 0x593e)

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

