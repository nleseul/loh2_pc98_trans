from dataclasses import dataclass
import fnmatch
import os
import typing

from code_analysis_util import BlockPool, EmptyHook, Link, X86CodeBlock
from trans_util import *
from ds6_event_util import *


@dataclass
class EntryPointInfo:
    domain:str
    target_addr:int
    source_addr:int|None = None


def explore(block_pool:BlockPool, entry_points:typing.List[EntryPointInfo]) -> None:
    for entry_point in entry_points:
        block = block_pool.get_block(entry_point.domain, entry_point.target_addr)
        Link(entry_point.source_addr, entry_point.target_addr).connect_blocks(None, block)

    while True:
        should_continue = False

        unlinked_blocks = list(block_pool.get_unlinked_blocks())
        for block in unlinked_blocks:
            block.link(block_pool)
            should_continue = True

        if not should_continue:
            break


def extract_scenario_events(scenario_data:typing.ByteString, custom_hooks:list[X86CodeHook]) -> TranslationCollection:
    code_entry_points = [ EntryPointInfo("code", int.from_bytes(scenario_data[0:2], byteorder='little')) ]

    addr_offset = 2
    while addr_offset + 0xd53e < code_entry_points[0].target_addr:
        addr = int.from_bytes(scenario_data[addr_offset:addr_offset+2], byteorder='little')
        if addr < 0xd53e:
            break
        else:
            code_entry_points.append(EntryPointInfo("code", addr) )
        addr_offset += 2

    code_hooks = [
        DS62_StandardEventCodeHook(),
        DS62_NpcTable1370CodeHook(),
        DS62_NpcTable13e7CodeHook(),
        DS62_BuyFromShopCodeHook(),
        DS62_SellToShopCodeHook()
    ]

    if custom_hooks is not None:
        code_hooks += custom_hooks

    block_pool = BlockPool()
    block_pool.register_domain("code", scenario_data, 0xd53e, X86CodeBlock, {'hooks': code_hooks})
    block_pool.register_domain("event", scenario_data, 0x593e, DS6EventBlock)

    explore(block_pool, code_entry_points)

    trans = TranslationCollection()
    for block in block_pool.get_blocks("event"):
        entry = trans[block.start_addr]
        entry.original = block.format_string()
        entry.original_byte_length = block.length

        references = set()
        for link in block.get_incoming_links():
            if link.source_addr is None:
                entry.is_relocatable = False
            elif link.source_block is not None and isinstance(link.source_block, X86CodeBlock):
                references.add(link.source_addr)
        entry.reference_addrs = list(references)

    return trans


def extract_combat_events(combat_data:typing.ByteString, monster_count:int = 4) -> TranslationCollection:
    entry_points = []
    for name_index in range(monster_count):
        entry_points.append(EntryPointInfo("event", 0x7140 + name_index * 0x40 + 0x30))

    intro_text_addr = int.from_bytes(combat_data[0x108:0x10a], byteorder='little')
    if intro_text_addr >= 0x7140:
        entry_points.append(EntryPointInfo("event", intro_text_addr, 0xed40 + 0x108))

    for entry_addr_offset in range(0x10a, 0x118, 2):
        entry_addr = int.from_bytes(combat_data[entry_addr_offset:entry_addr_offset+2], byteorder='little')
        if entry_addr >= 0xed40:
            entry_points.append(EntryPointInfo("code", entry_addr, 0xed40 + entry_addr_offset))

    global_code_hooks = [
        DS62_StandardEventCodeHook()
    ]

    block_pool = BlockPool()
    block_pool.register_domain("code", combat_data, 0xed40, X86CodeBlock, {'hooks': global_code_hooks})
    block_pool.register_domain("event", combat_data, 0x7140, DS6EventBlock)

    explore(block_pool, entry_points)

    trans = TranslationCollection()
    for block in block_pool.get_blocks("event"):
        entry = trans[block.start_addr]
        entry.original = block.format_string()
        entry.original_byte_length = block.length

        references = set()
        for link in block.get_incoming_links():
            if link.source_addr is None:
                entry.is_relocatable = False
            else:
                references.add(link.source_addr)
        entry.reference_addrs = list(references)

        if block.start_addr < 0x7140 + 0x40*monster_count:
            entry.max_byte_length = 0x10

    return trans


def extract_opening_text(opening_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()

    addr = 0x3dc2

    for text_index in range(5):
        text = ""
        while True:
            if opening_data[addr] == 0xff:
                text += "<PAGE>\n"
                addr += 1
                break
            elif opening_data[addr] == 0:
                text += "\n"
                addr += 1
            else:
                ch, addr = read_sjis_char(opening_data, addr)
                text += ch


        trans[text_index].original = text

    return trans


def extract_ending_text(ending_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()

    addresses = [
        0x226c,
        0x22c1,
        0x23c1, # Special background scrolling code; may be different
        0x24d3,
        0x2611,
        0x2722,
        0x2792,
        0x2825,
        0x2b76  # Staff roll; probably different codes
    ]

    for start_addr in addresses:
        addr = start_addr
        text = ""

        while True:
            if ending_data[addr] == 0x9:
                addr += 1
                break
            elif ending_data[addr] == 0x0:
                text += "\n"
                addr += 1
            elif ending_data[addr] == 0x1:
                text += "\n" if text[-1] == "\n" else "<PAGE>\n"
                addr += 1
            elif ending_data[addr] == 0x2:
                text += "<PAGE_FULL>\n"
                addr += 1
            elif ending_data[addr] == 0x3:
                text += "<NAME>"
                text += ending_data[addr+1:addr+9].decode('cp932')
                text += "</NAME>\n"
                addr += 9
            elif ending_data[addr] == 0x4:
                text += "<PAGE_PAUSE>\n"
                addr += 1
            elif ending_data[addr] == 0x5:
                text += "<PAUSE>"
                addr += 1
            elif ending_data[addr] == 0x6:  # Changes graphic during the Freya animation
                text += "<CHANGE_FREYA_GRAPHIC>"
                addr+= 1
            elif ending_data[addr] == 0x8:  # Something specific to the staff roll
                text += "<STAFF_ROLL_MARKER>"
                addr+= 1
            else:
                ch, addr = read_sjis_char(ending_data, addr)
                text += ch

        entry = trans[start_addr]
        entry.original = text
        entry.original_byte_length = addr - start_addr
        # TODO: Copy reference addresses from source

    # Line lengths are hardcoded at 0x1003 and 0x1019
    final_text_addr = 0x28d3
    line_lengths = [0xd, 0xb]
    second_line_start = final_text_addr + line_lengths[0]*2
    trans[final_text_addr].original = ending_data[final_text_addr:final_text_addr+line_lengths[0]*2].decode('cp932') +\
          "\n" +\
          ending_data[second_line_start:second_line_start+line_lengths[1]*2].decode('cp932')

    return trans


def extract_spells(prog_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()
    base_addr = 0x1ebc + 0x7c00

    for spell_index in range(32):
        addr = base_addr + spell_index*12
        spell_name = prog_data[addr:addr+8].decode('cp932')
        trans[addr].original = spell_name.strip()

    return trans


def extract_items(prog_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()
    addr = 0xf3b + 0x7c00

    while prog_data[addr] != 0:
        item_name = prog_data[addr:addr+14].decode('cp932')
        trans[addr].original = item_name.strip()

        addr += 14 if addr >= 0x152b + 0x7c00 else 20

    return trans


def extract_locations(prog_data:typing.ByteString) -> list[str]:
    trans = TranslationCollection()
    table_addr = 0xc60 + 0x7c00

    for location_index in range(64):
        table_entry_addr = table_addr + location_index*2
        addr = int.from_bytes(prog_data[table_entry_addr:table_entry_addr+2], byteorder='little') + 0x7c00
        entry = trans[addr]

        first_byte = prog_data[addr]

        length = 12
        if first_byte < 0x20:
            length -= first_byte * 2
            addr += 1

        location_name = prog_data[addr:addr+length].decode('cp932')

        entry.original = location_name
        entry.original_byte_length = 12 if first_byte >= 0x20 else 12 - first_byte*2 + 1
        entry.reference_addrs.append(table_entry_addr)

    return trans


def update_translations(trans:TranslationCollection, save_path:str) -> None:
    if not trans.empty:
        trans.import_translations(TranslationCollection.load(save_path))
        trans.save(save_path)


def main() -> None:
    scenario_list = []
    combat_list = []
    for path, dirs, files in os.walk("local/decompressed"):
        if path.endswith("/SCENA"):
            for filename in files:
                scenario_list.append(os.path.join(path, filename))
        elif path.endswith("/MON"):
            for filename in fnmatch.filter(files, "M_*.BZH.bin"):
                combat_list.append(os.path.join(path, filename))
    scenario_list = sorted(scenario_list)
    combat_list = sorted(combat_list)

    for file_path in scenario_list:
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = os.path.join("yaml/Scenarios", f"{base_name}.yaml")
        print(output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(file_path, 'rb') as in_file:
            scenario_data = in_file.read()

        scenario_hooks = None
        if base_name == "C_203.BZH":
            scenario_hooks = [EmptyHook(0xd5cb, False, 0xd5d6)] # Skip some subroutine calls that would stomp si

        try:
            update_translations(extract_scenario_events(scenario_data, scenario_hooks), output_path)
        except Exception as e:
            print(f" FAILED - {e}")

    for file_path in combat_list:
        output_path = os.path.join("yaml/Combats", os.path.splitext(os.path.basename(file_path))[0] + ".yaml")
        print(output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(file_path, 'rb') as in_file:
            combat_data = in_file.read()

        try:
            update_translations(extract_combat_events(combat_data, 1 if "M_501" in file_path else 4), output_path)
        except Exception as e:
            print(f" FAILED - {e}")

    with open("local/decompressed/OPENING.BZH.bin", 'rb') as in_file:
        opening_data = in_file.read()
    update_translations(extract_opening_text(opening_data), "yaml/Opening.yaml")

    with open("local/decompressed/ENDING.BZH.bin", 'rb') as in_file:
        ending_data = in_file.read()
    update_translations(extract_ending_text(ending_data), "yaml/Ending.yaml")

    with open("local/decompressed/PROG.BZH.bin", 'rb') as in_file:
        prog_data = in_file.read()

    update_translations(extract_spells(prog_data), "yaml/Spells.yaml")
    update_translations(extract_items(prog_data), "yaml/Items.yaml")
    update_translations(extract_locations(prog_data), "yaml/Locations.yaml")

if __name__ == '__main__':
    main()