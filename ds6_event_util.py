from capstone.x86 import *
import typing

from code_analysis_util import Block, Link, X86CodeHook


def disassemble_event(scenario_data, base_addr, start_addr, continuation_extent_end_addr=None):

    EVENT_CODE_INFO = {
        0x00: { 'length': 1, 'terminator': True }, # Terminator
        0x01: { 'length': 1 }, # Newline
        0x02: { 'length': 1 },
        0x03: { 'length': 1 }, # Wait for keypress
        0x04: { 'length': 1 },
        0x05: { 'length': 1 }, # Page break
        0x06: { 'length': 1, 'terminator': True }, # Unknown terminator
        0x07: { 'length': 1, 'terminator': True }, # Return
        0x08: { 'length': 1 },
        0x09: { 'length': 2 }, # Party member's name
        0x0a: { 'length': 1, 'terminator': True }, # Not sure on this... seems weird
        0x0b: { 'length': 1 },
        0x0c: { 'length': 3 },
        0x0d: { 'length': 1, 'terminator': True },
        0x0e: { 'length': 1 },
        0x0f: { 'length': 3 }, # Jump
        0x10: { 'length': 3 }, # Subroutine call
        0x11: { 'length': 3 }, # Something about conditions...
        0x12: { 'length': 3 }, # ...
        0x13: { 'length': 3 }, # ...
        0x14: { 'length': 3 }, # ...
        0x15: { 'length': 3 }, # Assembly call
        0x16: { 'length': 11 }, # Multiple calls? Based on leader?

        0x1a: { 'length': 1 },
        0x1c: { 'length': 1 },
        0x1e: { 'length': 1 },
        0x1f: { 'length': 1 },

        # New codes for DS6-2
        0xf0: { 'length': 2 },
        0xf1: { 'length': 2 },
        0xf2: { 'length': 3 },
        0xf3: { 'length': 3 },
        0xf4: { 'length': 4 },
        0xf5: { 'length': 4 },
        0xf6: { 'length': 3 },
        0xf7: { 'length': 1 },
        0xf8: { 'length': 4 },
        0xf9: { 'length': 4 },
        0xfb: { 'length': 5 },

    }

    addr = start_addr - base_addr
    instructions = []

    jumps = set()

    while True:
        if addr+base_addr in jumps:
            jumps.remove(addr+base_addr)

            # Split up text if a jump lands in the middle of a block of text.
            if len(instructions) > 0 and 'text' in instructions[-1]:
                instructions.append( { 'addr': addr+base_addr, 'text': "" } )

        if scenario_data[addr] < 0x20 or scenario_data[addr] >= 0xf0:
            code = scenario_data[addr]

            if code not in EVENT_CODE_INFO:
                raise Exception(f"Unknown code {scenario_data[addr]:02x} at {addr+base_addr:03x}!")

            code_info = EVENT_CODE_INFO[code]

            instructions.append( { 'addr': addr+base_addr, 'code': code, 'data': scenario_data[addr+1:addr+1+code_info['length'] - 1], 'length': code_info['length'] } )

            addr += code_info['length']

            if code == 0x0f:
                jumps.add(int.from_bytes(instructions[-1]['data'], byteorder='little'))
            elif code == 0x15: # ASM call
                if int.from_bytes(instructions[-1]['data'], byteorder='little') == 0xe887:
                    break
            elif 'terminator' in code_info:
                if addr+base_addr in jumps and continuation_extent_end_addr is not None and addr+base_addr <= continuation_extent_end_addr:
                    raise Exception(f"Event at {start_addr:04x} has both a jump to the end and a continuation. So confusing...")
                elif addr+base_addr in jumps:
                    jumps.remove(addr+base_addr)
                elif continuation_extent_end_addr is not None and addr+base_addr <= continuation_extent_end_addr:
                    instructions[-1]['continue'] = True
                else:
                    break
        else:
            if len(instructions) == 0 or 'text' not in instructions[-1]:
                instructions.append( { 'addr': addr+base_addr, 'text': "" } )

            try:
                if scenario_data[addr] >= 0xe0: # Kanji block above 0xe0 is two bytes each.
                    instructions[-1]['text'] += scenario_data[addr:addr+2].decode('cp932')
                    addr += 2
                elif scenario_data[addr] >= 0xa0: # Half-width katakana are between 0xa0 and 0xdf. One byte each.
                    instructions[-1]['text'] += scenario_data[addr:addr+1].decode('cp932')
                    addr += 1
                elif scenario_data[addr] >= 0x80:
                    instructions[-1]['text'] += scenario_data[addr:addr+2].decode('cp932')
                    addr += 2
                elif scenario_data[addr] >= 0x20:
                    instructions[-1]['text'] += scenario_data[addr:addr+1].decode('cp932')
                    addr += 1
            except UnicodeDecodeError as e:
                print(f"Unable to interpret SJIS sequence {scenario_data[addr:addr+2].hex()} at {addr+base_addr:04x} while disassembling event at {start_addr:04x}")
                raise e

    return instructions


class DS6EventBlock(Block):
    def __init__(self, data:typing.ByteString, base_addr:int, start_addr:int, params:dict|None = None):
        self._continuation_extent_end_addr = None

        super().__init__(data, base_addr, start_addr)

    def dump(self):
        for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, self._continuation_extent_end_addr):
            if True in [not isinstance(in_link, Link) and instruction['addr'] == in_link['dest_addr'] for in_link in self._incoming_links]:
                print("--> ", end='')
            else:
                print("    ", end='')

            print(f"{instruction['addr']:04x}  ", end='')

            if 'text' in instruction:
                print(instruction['text'], end='')
            else:
                print(f"{instruction['code']:02x} {instruction['data'].hex()} ", end='')

            if True in [not isinstance(out_link, Link) and 'source_addr' in out_link and instruction['addr'] == out_link['source_addr'] for out_link in self._outgoing_links]:
                print("--> ", end='')
            else:
                print("    ", end='')

            print()
        print()


    def _explore(self):
        for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, self._continuation_extent_end_addr):
            pass

        self._length = instruction['addr'] + instruction['length'] - self._start_addr

    def link(self, block_pool):
        for link, link_path in zip(self._incoming_links, self._incoming_link_path_index):
            link_path_info = self._link_paths[link_path]
            if 'is_linked' in link_path_info:
                continue

            link_target_addr = link.target_addr
            execution_context = link.execution_context

            jump_map = {}

            for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, 0):
                if instruction['addr'] in jump_map:
                    self.add_internal_reference(jump_map[instruction['addr']] + 1, instruction['addr'], source_instruction_addr=jump_map[instruction['addr']])
                    del jump_map[instruction['addr']]

                if 'code' in instruction:
                    code = instruction['code']
                    if code == 0x0f: # Jump
                        arg = int.from_bytes(instruction['data'], byteorder='little')
                        jump_map[arg] = instruction['addr']
                    elif code == 0x10: # Subroutine
                        arg = int.from_bytes(instruction['data'], byteorder='little')
                        link = Link(instruction['addr'] + 1, arg, source_instruction_addr=instruction['addr'])
                        if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                            link.connect_blocks(self, None)
                            self.add_global_reference(instruction['addr'] + 1, arg)
                        else:
                            link.connect_blocks(self, block_pool.get_block("event", arg))

                    elif code == 0x15: # ASM call
                        arg = int.from_bytes(instruction['data'], byteorder='little')
                        link = Link(instruction['addr'] + 1, arg, source_instruction_addr=instruction['addr'])
                        if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                            link.connect_blocks(self, None)
                            self.add_global_reference(instruction['addr'] + 1, arg)
                        else:
                            link.connect_blocks(self, block_pool.get_block("code", arg))

                    elif code == 0x16: # Subroutine call based on leader
                        for ref_index in range(5):
                            arg = int.from_bytes(instruction['data'][ref_index*2:ref_index*2+2], 'little')
                            link = Link(instruction['addr'] + ref_index*2 + 1, arg, source_instruction_addr=instruction['addr'])
                            if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                                link.connect_blocks(self, None)
                                self.add_global_reference(instruction['addr'] + ref_index*2 + 1, arg)
                            else:
                                link.connect_blocks(self, block_pool.get_block("event", arg))

            for jump_target, jump_source in jump_map.items():
                link = Link(jump_source + 1, jump_target, source_instruction_addr=jump_source)
                if (jump_target < self._base_addr or arg >= self._base_addr + len(self._data)):
                    link.connect_blocks(self, None)
                    self.add_global_reference(jump_source + 1, jump_target)
                else:
                    link.connect_blocks(self, block_pool.get_block("event", jump_target))


            link_path_info['is_linked'] = True

    def format_string(self):
        out = ""

        jumps = set()

        external_locators = set()
        for link in self._incoming_links:
            external_locators.add(link.target_addr)


        for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, self._continuation_extent_end_addr):
            if instruction['addr'] in jumps:
                jumps.remove(instruction['addr'])
                if len(out) > 0:
                    out += f"<LOC{instruction['addr']:04x}>"
            elif instruction['addr'] in external_locators:
                if len(out) > 0:
                    out += f"<LOC{instruction['addr']:04x}>"

            if 'text' in instruction:
                out += instruction['text']
            else:
                code = instruction['code']

                if code == 0x00:
                    if instruction['addr'] + 1 < self.end_addr:
                        out += "<END>\n"
                elif code == 0x01: # Newline
                    if self._data[instruction['addr'] - self.base_addr + 1] == 0x01:
                        out += "<N>\n"
                    else:
                        out += "\n"
                elif code == 0x03: # Wait for keypress (implicit newline)
                    out += "<WAIT>\n"
                elif code == 0x05: # Page break
                    if self._data[instruction['addr'] - self.base_addr - 1] == 0x01:
                        out += "<PAGE>\n"
                    else:
                        out += "\n\n"
                elif code == 0x06: # Return inline
                    out += "<RET_IL>"
                elif code == 0x07: # Return with newline
                    out += "<RETN>"
                elif code == 0x09: # Party member name
                    out += f"<CH{instruction['data'][0]}>"
                elif code == 0x0f: # Jump
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<JUMP{arg:04x}>"
                    jumps.add(arg)
                elif code == 0x10: # Subroutine
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<CALL{arg:04x}>"
                elif code == 0x11: # Conditional, inverted?
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<IF_NOT{arg:04x}>"
                elif code == 0x12: # Conditional
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<IF{arg:04x}>"
                elif code == 0x13: # Clear flag
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<CLEAR{arg:04x}>"
                elif code == 0x14: # Set flag
                    arg = int.from_bytes(instruction['data'], byteorder='little')
                    out += f"<SET{arg:04x}>"
                elif code == 0x15: # ASM call
                    arg = int.from_bytes(instruction['data'], byteorder='little')

                    no_return = instruction['addr'] + 3 > self.end_addr

                    out += "<ASM{0}{1:04x}>".format("_NORET" if no_return else "", arg)
                elif code == 0x16: # Call based on party member (includes name)
                    out += "<LEADER"
                    for ref_index in range(5):
                        arg = int.from_bytes(instruction['data'][ref_index*2:ref_index*2+2], 'little')
                        if ref_index > 0:
                            out += ","
                        out += f"{arg:04x}"
                    out += ">"
                else:
                    out += f"<X{code:02x}{instruction['data'].hex()}>"

                if 'continue' in instruction:
                    out += "\n<CONT>"

        return out

    def set_continuation_extent(self, extent_end_addr):
        if self._continuation_extent_end_addr is None or self._continuation_extent_end_addr < extent_end_addr:
            self._continuation_extent_end_addr = extent_end_addr

            self._length = None
            self._outgoing_links = []

            self._explore()

    def _context_is_equivalent(self, c1, c2):
        c1_continuations = 0 if c1 is None or 'continuations' not in c1 else c1['continuations']
        c2_continuations = 0 if c2 is None or 'continuations' not in c2 else c2['continuations']
        return c1_continuations == c2_continuations


class DS62_StandardEventCodeHook(X86CodeHook):
    def should_handle(self, instruction):
        if (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM:
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x12e2, 0x12e7, 0x3234, 0x3249 ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_SI in registers:
            event_addr = registers[X86_REG_SI]['value']

            if block_pool.domain_contains("event", event_addr):

                disassembly = disassemble_event(block_pool.get_domain_data("event"), block_pool.get_domain_base_addr("event"), event_addr)

                if 'source_addr' in registers[X86_REG_SI]:

                    event_link = Link(registers[X86_REG_SI]['source_addr'], event_addr)
                    event_link.connect_blocks(current_block, block_pool.get_block("event", event_addr))

                    registers[X86_REG_SI]['continue_from_addr'] = event_addr
                    registers[X86_REG_SI]['value'] = disassembly[-1]['addr'] + disassembly[-1]['length']

                    del registers[X86_REG_SI]['source_addr']
                else:
                    current_block = block_pool.get_block("event", registers[X86_REG_SI]['continue_from_addr'])
                    current_block.set_continuation_extent(event_addr)

                    registers[X86_REG_SI]['value'] = disassembly[-1]['addr'] + disassembly[-1]['length']
            else:
                global_event_link = Link(registers[X86_REG_SI]['source_addr'], event_addr)
                global_event_link.connect_blocks(current_block, None)
                current_block.add_global_reference(registers[X86_REG_SI]['source_addr'], event_addr, is_event=True)

        else:
            print(registers)
            raise Exception(f"No known event address for event call at {instruction.address:04x}")


# Seems to be used for normal NPCs walking around
class DS62_NpcTable1370CodeHook(X86CodeHook):
    def should_handle(self, instruction):
        if (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM:
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x1370 ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_DX in registers:
            table_destination = registers[X86_REG_DX]['value']

            table_destination -=  block_pool.get_domain_base_addr("event")
            table_size = int.from_bytes(block_pool.get_domain_data("code")[table_destination:table_destination+2], byteorder='little') - 1
            for table_index in range(table_size):
                table_entry = int.from_bytes(block_pool.get_domain_data("code")[table_destination + 2 + table_index*2:table_destination + 2 + (table_index + 1)*2], byteorder='little')
                if block_pool.domain_contains("code", table_entry):
                    link = Link(table_destination + 2 + table_index*2 + current_block.base_addr, table_entry)
                    link.connect_blocks(current_block, block_pool.get_block("code", table_entry))
        else:
            raise Exception("Don't know what the table address was!!")


# Seems to be used for shops and other stationary NPCs/objects
class DS62_NpcTable13e7CodeHook(X86CodeHook):
    def should_handle(self, instruction):
        if (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM:
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x13e7 ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_SI in registers:
            table_destination = registers[X86_REG_SI]['value']

            table_destination -=  block_pool.get_domain_base_addr("event")

            data = block_pool.get_domain_data("code")
            table_offset = 0

            while True:
                first_byte = data[table_destination + table_offset]

                if first_byte == 0xff:
                    break

                handler_pointer_addr = table_destination + table_offset + (5 if first_byte & 0x40 != 0 else 3)

                handler_addr = int.from_bytes(data[handler_pointer_addr:handler_pointer_addr + 2], byteorder='little')

                #print(f"First byte of object table record is {data[table_destination + table_offset]:02x} ({data[table_destination + table_offset]:08b})")
                #print(f"Pointer is {handler_addr:04x}")

                if block_pool.domain_contains("code", handler_addr):
                    link = Link(handler_pointer_addr, handler_addr)
                    link.connect_blocks(current_block, block_pool.get_block("code", handler_addr))
                table_offset += (7 if first_byte & 0x40 != 0 else 5)
        else:
            raise Exception("Don't know what the table address was!!")


class DS62_SellToShopCodeHook(X86CodeHook):
    def should_handle(self, instruction):
        if (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM:
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x18dd ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_BX in registers:
            table_destination = registers[X86_REG_BX]['value']

            table_destination -=  block_pool.get_domain_base_addr("event")

            data = block_pool.get_domain_data("code")

            # Four pointers to events - "What do you want to sell?" / "Is this price okay?" / "Too bad" / "Thanks"
            for entry_index in range(4):
                event_pointer_addr = table_destination + entry_index*2
                event_addr = int.from_bytes(data[event_pointer_addr:event_pointer_addr + 2], byteorder='little')
                if block_pool.domain_contains("event", event_addr):
                    link = Link(event_pointer_addr, event_addr)
                    link.connect_blocks(current_block, block_pool.get_block("event", event_addr))
        else:
            raise Exception("Don't know what the table address was!!")


class DS62_BuyFromShopCodeHook(X86CodeHook):
    def should_handle(self, instruction):
        if (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM:
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x1863 ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_BX in registers:
            table_destination = registers[X86_REG_BX]['value']

            table_destination -=  block_pool.get_domain_base_addr("event")

            data = block_pool.get_domain_data("code")

            # Three pointers to events - "You can't hold any more" / "What do you want to buy?" / "Thank you"
            for entry_index in range(3):
                event_pointer_addr = table_destination + entry_index*2
                event_addr = int.from_bytes(data[event_pointer_addr:event_pointer_addr + 2], byteorder='little')
                if block_pool.domain_contains("event", event_addr):
                    link = Link(event_pointer_addr, event_addr)
                    link.connect_blocks(current_block, block_pool.get_block("event", event_addr))
        else:
            raise Exception("Don't know what the table address was!!")