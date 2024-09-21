from dataclasses import dataclass
import fnmatch
import os
import typing

from code_analysis_util import BlockPool, EmptyHook, Link, X86CodeBlock
from csv_util import *
from ds6_event_util import *


@dataclass
class EntryPointInfo:
    domain:str
    target_addr:int


def explore(block_pool:BlockPool, entry_points:typing.List[EntryPointInfo]) -> None:
    for entry_point in entry_points:
        block = block_pool.get_block(entry_point.domain, entry_point.target_addr)
        Link(None, entry_point.target_addr).connect_blocks(None, block)

    while True:
        should_continue = False

        unlinked_blocks = list(block_pool.get_unlinked_blocks())
        for block in unlinked_blocks:
            block.link(block_pool)
            should_continue = True

        if not should_continue:
            break


def extract_scenario_events(scenario_data:typing.ByteString, custom_hooks:list[X86CodeHook]) -> typing.List[DS6EventBlock]:
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

    return sorted(list(block_pool.get_blocks("event")), key=lambda e: e.start_addr)


def extract_combat_events(combat_data:typing.ByteString) -> typing.List[DS6EventBlock]:
    entry_points = []
    for name_index in range(1 if "M_501" in file_path else 4):
        entry_points.append(EntryPointInfo("event", 0x7140 + name_index * 0x40 + 0x30))

    intro_text_addr = int.from_bytes(combat_data[0x108:0x10a], byteorder='little')
    if intro_text_addr >= 0x7140:
        entry_points.append(EntryPointInfo("event", intro_text_addr))

    for entry_addr_offset in range(0x10a, 0x118, 2):
        entry_addr = int.from_bytes(combat_data[entry_addr_offset:entry_addr_offset+2], byteorder='little')
        if entry_addr >= 0xed40:
            entry_points.append(EntryPointInfo("code", entry_addr))

    global_code_hooks = [
        DS62_StandardEventCodeHook()
    ]

    block_pool = BlockPool()
    block_pool.register_domain("code", combat_data, 0xed40, X86CodeBlock, {'hooks': global_code_hooks})
    block_pool.register_domain("event", combat_data, 0x7140, DS6EventBlock)

    explore(block_pool, entry_points)

    return sorted(list(block_pool.get_blocks("event")), key=lambda e: e.start_addr)


def extract_opening_text(opening_data:typing.ByteString, start_addr:int) -> typing.Tuple[int, str]:
    text = ""
    addr = start_addr

    while True:
        if opening_data[addr] == 0xff:
            addr += 1
            break
        elif opening_data[addr] == 0:
            text += "\n"
            addr += 1
        elif opening_data[addr] >= 0xe0: # Kanji block above 0xe0 is two bytes each.
            text += opening_data[addr:addr+2].decode('cp932')
            addr += 2
        elif opening_data[addr] >= 0xa0: # Half-width katakana are between 0xa0 and 0xdf. One byte each.
            text += opening_data[addr:addr+1].decode('cp932')
            addr += 1
        elif opening_data[addr] >= 0x80:
            text += opening_data[addr:addr+2].decode('cp932')
            addr += 2
        elif opening_data[addr] >= 0x20:
            text += opening_data[addr:addr+1].decode('cp932')
            addr += 1
        else:
            raise Exception(f"Unknown byte {opening_data[addr]:02x} at location {addr:04x} in opening.")

    return addr, text


if __name__ == '__main__':
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
        output_path = os.path.join("csv/Scenarios", f"{base_name}.csv")
        print(output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(file_path, 'rb') as in_file:
            scenario_data = in_file.read()

        scenario_hooks = None
        if base_name == "C_203.BZH":
            scenario_hooks = [EmptyHook(0xd5cb, False, 0xd5d6)] # Skip some subroutine calls that would stomp si

        try:
            events = extract_scenario_events(scenario_data, scenario_hooks)

            if len(events) > 0:
                csv_data = load_csv(output_path)

                for event in events:
                    add_csv_original(csv_data, event.start_addr, event.format_string())

                save_csv(output_path, csv_data)
        except Exception as e:
            print(f" FAILED - {e}")

    for file_path in combat_list:
        output_path = os.path.join("csv/Combats", os.path.splitext(os.path.basename(file_path))[0] + ".csv")
        print(output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(file_path, 'rb') as in_file:
            combat_data = in_file.read()

        try:
            events = extract_combat_events(combat_data)

            if len(events) > 0:
                csv_data = load_csv(output_path)

                for event in events:
                    add_csv_original(csv_data, event.start_addr, event.format_string())

                save_csv(output_path, csv_data)
        except Exception as e:
            print(f" FAILED - {e}")

    with open("local/decompressed/OPENING.BZH.bin", 'rb') as in_file:
        opening_data = in_file.read()
    opening_csv_data = load_csv("csv/Opening.csv")

    opening_addr = 0x3dc2
    for opening_page_index in range(5):
        opening_addr, text = extract_opening_text(opening_data, opening_addr)
        add_csv_original(opening_csv_data, opening_page_index, text)

    save_csv("csv/Opening.csv", opening_csv_data)


