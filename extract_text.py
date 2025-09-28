from dataclasses import dataclass
import fnmatch
import os
import typing

from code_analysis_util import BlockPool, DataBlock, EmptyHook, Link, X86CodeBlock
from trans_util import *
from ds6_event_util import *


class TrackAccessesInRangeHook(X86CodeHook):
    def __init__(self, start_addr, end_addr):
        self._start_addr = start_addr
        self._end_addr = end_addr

        self._accesses = set()
        self._min_access = None
        self._max_access = None

    def should_handle(self, instruction) -> bool:
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM:
                addr = operand.mem.disp
                if addr >= self._start_addr and addr <= self._end_addr:
                    for offset in range(operand.size):
                        self._accesses.add(addr+offset)
                        self._min_access = addr if self._min_access is None else min(addr, self._min_access)
                        self._max_access = addr if self._max_access is None else max(addr, self._max_access)
        return False

    @property
    def accesses(self) -> typing.Iterable[int]:
        yield from sorted(list(self._accesses))

    @property
    def min_access(self) -> int | None:
        return self._min_access

    @property
    def max_access(self) -> int | None:
        return self._max_access


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


def make_entry_from_block(block:DS6EventBlock) -> TranslatableEntry:
    is_relocatable = True
    code_references = {}
    data_references = {}
    for link in block.get_incoming_links():
        if link.source_addr is None:
            is_relocatable = False
        elif isinstance(link.source_block, DS6EventBlock):
            # Ignore references from events for now, since those are already embedded
            # in the event's string representation.
            pass
        elif isinstance(link.source_block, DataBlock):
            data_references[link.source_addr] = link.target_addr
        else:
            #assert(isinstance(link.source_block, X86CodeBlock))
            code_references[link.source_addr] = link.target_addr

    if is_relocatable:
        entry = RelocatableTranslatableEntry(original_byte_length=block.length)
        for source_addr, target_addr in code_references.items():
            entry.references.append(CodeReference(source_addr, target_addr))
        for source_addr, target_addr in data_references.items():
            entry.references.append(DataReference(source_addr, target_addr))
    else:
        entry = FixedTranslatableEntry(max_byte_length=block.length)

    entry.original = block.format_string()

    return entry


def extract_menu(trans:TranslationCollection, data:typing.ByteString, start_addr:int, force_item_count:int|None = None) -> None:

    item_count = data[start_addr+3] if force_item_count is None else force_item_count
    addr = start_addr + 0x4

    menu_text = ""

    for _ in range(item_count):
        if len(menu_text) > 0:
            menu_text += "\n"
        item_bytes = b''
        while data[addr] != 0:
            item_bytes += data[addr:addr+1]
            addr += 1
        menu_text += item_bytes.decode('cp932')
        addr += 1

    entry = FixedTranslatableWindowEntry(original=menu_text,
                                         max_byte_length=addr - (start_addr + 0x4),
                                         window_position=int.from_bytes(data[start_addr:start_addr+1], byteorder='little'),
                                         window_width=data[start_addr+2],
                                         line_count=data[start_addr+3])
    if force_item_count is not None:
        entry.forced_line_count = force_item_count

    trans.add_entry(start_addr, entry)



def extract_program_events(program_data:typing.ByteString):
    code_hooks = [
        EmptyHook(0x1592, False, stop=True), # Calls into scenario entry points
        EmptyHook(0x21b7, False, stop=True), # Calls into combat entry points
        EmptyHook(0x4c53, False, stop=True), # Calls into scenario entry points
        DS62_PointerTableCodeHook(0x1596, 0x159b, 5, table_domain="code"),
        DS62_PointerTableCodeHook(0x2e89, 0x0f24, 5),
        DS62_PointerTableCodeHook(0x5268, 0x1a32, 8),
        DS62_PointerTableCodeHook(0x5bb4, 0x2326, 7),
        DS62_PointerTableCodeHook(0x5de3, 0x1b20, 6),
        DS62_PrefixedEvent1d74CodeHook(),

        DS62_StandardEventCodeHook(),
    ]

    code_entry_points = [ EntryPointInfo("code", 0) ]

    block_pool = BlockPool()
    block_pool.register_domain("code", program_data[:0x7c00], 0, X86CodeBlock, {'hooks': code_hooks})
    block_pool.register_domain("event", program_data[0x7c00:], 0, DS6EventBlock)

    explore(block_pool, code_entry_points)

    trans = TranslationCollection()
    trans.end_of_file_addr = len(program_data)
    for block in block_pool.get_blocks("event"):
        entry = make_entry_from_block(block)
        trans.add_entry(block.start_addr, entry)

    return trans


def extract_scenario_events(scenario_data:typing.ByteString, custom_hooks:list[X86CodeHook]) -> TranslationCollection:
    code_entry_points = [ EntryPointInfo("code", int.from_bytes(scenario_data[0:2], byteorder='little')) ]

    addr_offset = 2
    while addr_offset + DS62_SCENARIO_CODE_START < code_entry_points[0].target_addr:
        addr = int.from_bytes(scenario_data[addr_offset:addr_offset+2], byteorder='little')
        if addr < DS62_SCENARIO_CODE_START:
            break
        else:
            code_entry_points.append(EntryPointInfo("code", addr) )
        addr_offset += 2

    outOfRangeAccessTracker = TrackAccessesInRangeHook(DS62_SCENARIO_DATA_START + len(scenario_data), DS62_SCENARIO_DATA_MAX)

    code_hooks = [
        DS62_StandardEventCodeHook(),
        DS62_GiveMoneyCodeHook(),
        DS62_NpcTable1370CodeHook(),
        DS62_NpcTable13e7CodeHook(),
        DS62_BuyFromShopCodeHook(),
        DS62_SellToShopCodeHook(),
        outOfRangeAccessTracker
    ]

    if custom_hooks is not None:
        code_hooks += custom_hooks

    block_pool = BlockPool()
    block_pool.register_domain("code", scenario_data, DS62_SCENARIO_CODE_START, X86CodeBlock, {'hooks': code_hooks})
    block_pool.register_domain("data", scenario_data, DS62_SCENARIO_DATA_START, DataBlock)
    block_pool.register_domain("event", scenario_data, DS62_SCENARIO_DATA_START, DS6EventBlock)

    explore(block_pool, code_entry_points)

    end_addr = DS62_SCENARIO_DATA_START + len(scenario_data) - 1
    max_addr = end_addr if outOfRangeAccessTracker.max_access is None else outOfRangeAccessTracker.max_access

    trans = TranslationCollection()
    trans.end_of_file_addr = max_addr - DS62_SCENARIO_DATA_START + 1
    for block in block_pool.get_blocks("event"):
        entry = make_entry_from_block(block)
        trans.add_entry(block.start_addr, entry)

    for block in block_pool.get_blocks("data"):

        if any(True for _ in block.get_outgoing_links()):
            # If there are any outgoing links in the block, don't track it. Not really
            # set up to update references inside a relocated data block yet.
            continue

        references = {}
        for link in block.get_incoming_links():
            if link.source_addr is None:
                raise Exception(f"Data block at {block.start_addr:04x} is non-relocatable, which is not supported/useful.")
            elif isinstance(link.source_block, DS6EventBlock):
                pass
            else:
                references[link.source_addr] = link.target_addr

        entry = RelocatableRawDataEntry(data=block.data,
                                        references=[CodeReference(source_addr, target_addr) for source_addr, target_addr in references.items()])

        trans.add_entry(block.start_addr, entry)

    return trans


def extract_combat_events(combat_data:typing.ByteString, monster_count:int = 4) -> TranslationCollection:
    entry_points = []
    for name_index in range(monster_count):
        entry_points.append(EntryPointInfo("event", DS62_COMBAT_DATA_START + name_index * 0x40 + 0x30))

    intro_text_addr = int.from_bytes(combat_data[0x108:0x10a], byteorder='little')
    if intro_text_addr >= DS62_COMBAT_DATA_START:
        entry_points.append(EntryPointInfo("event", intro_text_addr, DS62_COMBAT_CODE_START + 0x108))

    for entry_addr_offset in range(0x10a, 0x118, 2):
        entry_addr = int.from_bytes(combat_data[entry_addr_offset:entry_addr_offset+2], byteorder='little')
        if entry_addr >= DS62_COMBAT_CODE_START:
            entry_points.append(EntryPointInfo("code", entry_addr, DS62_COMBAT_CODE_START + entry_addr_offset))

    for entry_addr_offset in range(0x120, 0x140, 2):
        entry_addr = int.from_bytes(combat_data[entry_addr_offset:entry_addr_offset+2], byteorder='little')
        if entry_addr >= DS62_COMBAT_CODE_START:
            entry_points.append(EntryPointInfo("code", entry_addr, DS62_COMBAT_CODE_START + entry_addr_offset))

    outOfRangeAccessTracker = TrackAccessesInRangeHook(DS62_COMBAT_DATA_START + len(combat_data), DS62_COMBAT_DATA_MAX)

    global_code_hooks = [
        DS62_StandardEventCodeHook(),
        outOfRangeAccessTracker
    ]

    block_pool = BlockPool()
    block_pool.register_domain("code", combat_data, DS62_COMBAT_CODE_START, X86CodeBlock, {'hooks': global_code_hooks})
    block_pool.register_domain("data", combat_data, DS62_COMBAT_DATA_START, DataBlock)
    block_pool.register_domain("event", combat_data, DS62_COMBAT_DATA_START, DS6EventBlock)

    explore(block_pool, entry_points)

    end_addr = DS62_COMBAT_DATA_START + len(combat_data) - 1
    max_addr = end_addr if outOfRangeAccessTracker.max_access is None else outOfRangeAccessTracker.max_access

    trans = TranslationCollection()
    trans.end_of_file_addr = max_addr - DS62_COMBAT_DATA_START + 1
    for block in block_pool.get_blocks("event"):
        entry = make_entry_from_block(block)
        if block.start_addr < DS62_COMBAT_DATA_START + 0x40*monster_count:
            entry.max_byte_length = 0x10
        trans.add_entry(block.start_addr, entry)



    return trans


def extract_opening_text(opening_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()

    start_addr = 0x3dc2
    addr = start_addr
    page_count = 5

    text = ""
    while True:
        if opening_data[addr] == 0xff:
            text += "<PAGE>\n"
            addr += 1
            page_count -= 1
            if page_count == 0:
                break
        elif opening_data[addr] == 0:
            text += "\n"
            addr += 1
        else:
            ch, addr = read_sjis_char(opening_data, addr)
            text += ch

    entry = FixedTranslatableEntry(original=text, max_byte_length=addr-start_addr)
    trans.add_entry(0x3dc2, entry)

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

        entry = RelocatableTranslatableEntry(original=text, original_byte_length=addr-start_addr)
        trans.add_entry(start_addr, entry)
        # TODO: Copy reference addresses from source

    # Line lengths are hardcoded at 0x1003 and 0x1019
    final_text_addr = 0x28d3
    line_lengths = [0xd, 0xb]
    second_line_start = final_text_addr + line_lengths[0]*2
    final_entry = FixedTranslatableEntry(original=ending_data[final_text_addr:final_text_addr+line_lengths[0]*2].decode('cp932') +\
          "\n" +\
          ending_data[second_line_start:second_line_start+line_lengths[1]*2].decode('cp932'))

    return trans


def extract_spells(prog_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()
    base_addr = 0x1ebc + 0x7c00

    for spell_index in range(32):
        addr = base_addr + spell_index*12
        spell_name = prog_data[addr:addr+8].decode('cp932')
        entry = FixedTranslatableEntry(original=spell_name.strip(), max_byte_length=8)
        trans.add_entry(addr, entry)

    return trans


def extract_items(prog_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()
    addr = 0xf3b + 0x7c00

    while prog_data[addr] != 0:
        item_name = prog_data[addr:addr+14].decode('cp932')
        entry = FixedTranslatableEntry(original=item_name.strip(), max_byte_length=14)
        trans.add_entry(addr, entry)

        addr += 14 if addr >= 0x152b + 0x7c00 else 20

    return trans


def extract_locations(prog_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()
    table_addr = 0xc60 + 0x7c00

    for location_index in range(64):
        table_entry_addr = table_addr + location_index*2
        addr = int.from_bytes(prog_data[table_entry_addr:table_entry_addr+2], byteorder='little') + 0x7c00

        current_addr = addr

        first_byte = prog_data[current_addr]

        length = 12
        if first_byte < 0x20:
            length -= first_byte * 2
            current_addr += 1

        location_name = prog_data[current_addr:current_addr+length].decode('cp932')

        entry = RelocatableTranslatableEntry(original=location_name,
                                             original_byte_length=12 if first_byte >= 0x20 else 12 - first_byte*2 + 1)
        entry.references.append(CodeReference(table_entry_addr, addr))
        trans.add_entry(addr, entry)

    return trans


def extract_program_menus(prog_data_code:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()

    prog_data_data = prog_data_code[0x7c00:]

    menu_addr_list = [ 0x88c, 0xc1e, 0x1b2c, 0x1be1, 0x1c90, 0x1d5d, 0x2334 ]

    toggle_list = [
        (0x1c34, 2),
        (0x1c42, 2),
        (0x1c50, 4),
        (0x1c6c, 2),
        (0x1c7a, 2),
        (0x1cdc, 2),
        (0x1cea, 2),
        (0x1cfa, 2)
    ]

    for menu_addr in menu_addr_list:
        extract_menu(trans, prog_data_data, menu_addr, 7 if menu_addr == 0x2334 else None)

    for toggle_addr, toggle_count in toggle_list:
        toggle_text = ""
        addr = toggle_addr

        for _ in range(toggle_count):
            if len(toggle_text) > 0:
                toggle_text += "\n"
            item_bytes = b''
            while prog_data_data[addr] != 0:
                item_bytes += prog_data_data[addr:addr+1]
                addr += 1
            toggle_text += item_bytes.decode('cp932')
            addr += 1

        entry = FixedTranslatableEntry(original=toggle_text,
                                       max_byte_length=addr-toggle_addr)
        trans.add_entry(toggle_addr, entry)

    # Combat menu is just three lines with no header.
    combat_menu_addr = 0x19f4
    combat_menu_text = ""
    for _ in range(3):
        if len(combat_menu_text) > 0:
            combat_menu_text += "\n"
        item_bytes = b''
        while prog_data_data[combat_menu_addr] != 0:
            item_bytes += prog_data_data[combat_menu_addr:combat_menu_addr+1]
            combat_menu_addr += 1
        combat_menu_text += item_bytes.decode('cp932')
        combat_menu_addr += 1
    combat_menu_entry = FixedTranslatableEntry(original=combat_menu_text,
                                               max_byte_length=combat_menu_addr - 0x19f4)
    trans.add_entry(0x19f4, combat_menu_entry)

    return trans


def extract_utility_text(utility_data:typing.ByteString) -> TranslationCollection:
    trans = TranslationCollection()

    menu_addr_list = [ 0x271a, 0x2760, 0x2797, 0x27d8, 0x2a58, 0x2b52, 0x2c0d, 0x2c38,
                       0x2d70, 0x2de4, 0x2e3a, 0x2e84, 0x2ee3, 0x2f42, 0x2f5f, 0x2fc3,
                       0x2fea, 0x3028, 0x3072, 0x30d0, 0x3112, 0x316e, 0x31af ]

    for menu_addr in menu_addr_list:
        extract_menu(trans, utility_data, menu_addr)

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
        elif base_name == "F_000.BZH":
            scenario_hooks = [DS62_OverworldDestinationTableCodeHook(0xd800)]
        elif base_name == "F_200.BZH":
            scenario_hooks = [DS62_OverworldDestinationTableCodeHook(0xd7b9)]
        elif base_name == "F_400.BZH" or base_name == "F_500.BZH":
            scenario_hooks = [DS62_OverworldDestinationTableCodeHook(0xd570)]

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

    with open("local/decompressed/UTY.BZH.bin", 'rb') as in_file:
        utility_data = in_file.read()

    update_translations(extract_spells(prog_data), "yaml/Spells.yaml")
    update_translations(extract_items(prog_data), "yaml/Items.yaml")
    update_translations(extract_locations(prog_data), "yaml/Locations.yaml")
    update_translations(extract_program_menus(prog_data), "yaml/Menus.yaml")

    update_translations(extract_program_events(prog_data), "yaml/ProgramText.yaml")

    update_translations(extract_utility_text(utility_data), "yaml/Utility.yaml")


if __name__ == '__main__':
    main()