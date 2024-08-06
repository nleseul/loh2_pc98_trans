import csv
import fnmatch
import os
import typing

from code_analysis_util import BlockPool, Link, X86CodeBlock
from ds6_event_util import DS6EventBlock, DS62_StandardEventCodeHook

def extract_scenario_events(scenario_data:typing.ByteString) -> typing.List[DS6EventBlock]:
    code_entry_points = [ {'target_addr': int.from_bytes(scenario_data[0:2], byteorder='little') } ]

    addr_offset = 2
    while addr_offset + 0xd53e < code_entry_points[0]['target_addr']:
        addr = int.from_bytes(scenario_data[addr_offset:addr_offset+2], byteorder='little')
        if addr < 0xd53e:
            break
        else:
            code_entry_points.append( { 'target_addr': addr } )
        addr_offset += 2

    global_code_hooks = [
        DS62_StandardEventCodeHook()
    ]

    block_pool = BlockPool()
    block_pool.register_domain("code", scenario_data, 0xd53e, X86CodeBlock, {'hooks': global_code_hooks})
    block_pool.register_domain("event", scenario_data, 0x593e, DS6EventBlock)

    for entry_point in code_entry_points:
        block = block_pool.get_block("code", entry_point['target_addr'])
        Link(None, entry_point['target_addr']).connect_blocks(None, block)

    while True:
        should_continue = False

        unlinked_blocks = list(block_pool.get_unlinked_blocks())
        for block in unlinked_blocks:
            block.link(block_pool)
            should_continue = True

        if not should_continue:
            break

    return sorted(list(block_pool.get_blocks("event")), key=lambda e: e.start_addr)


if __name__ == '__main__':
    scenario_list = []
    combat_list = []
    for path, dirs, files in os.walk("local/decompressed"):
        if path.endswith("/SCENA"):
            for filename in files:
                scenario_list.append(os.path.join(path, filename))
        elif path.endswith("/MON"):
            for filename in fnmatch.filter(files, "M_*.BZH.dat"):
                combat_list.append(os.path.join(path, filename))
    scenario_list = sorted(scenario_list)
    combat_list = sorted(combat_list)

    for file_path in scenario_list:
        output_path = os.path.join("csv/SCENA", os.path.splitext(os.path.basename(file_path))[0] + ".csv")
        print(output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(file_path, 'rb') as in_file:
            scenario_data = in_file.read()

        try:
            events = extract_scenario_events(scenario_data)

            if len(events) > 0:
                with open(output_path, 'w+', encoding='utf8', newline='') as csv_out:
                    csv_writer = csv.writer(csv_out, quoting=csv.QUOTE_ALL, lineterminator=os.linesep)
                    for event in events:
                        csv_writer.writerow([f"{event.start_addr:04x}", event.format_string()])
        except Exception as e:
            print(f" FAILED - {e}")


