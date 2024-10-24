from capstone import *
from capstone.x86 import *
from dataclasses import dataclass
import typing

from code_analysis_util import Block, BlockPool, Link, X86CodeHook


def read_sjis_char(data:typing.ByteString, addr:int) -> tuple[str, int]:
    try:
        if data[addr] >= 0xe0: # Kanji block above 0xe0 is two bytes each.
            return data[addr:addr+2].decode('cp932'), addr + 2
        elif data[addr] >= 0xa0: # Half-width katakana are between 0xa0 and 0xdf. One byte each.
            return data[addr:addr+1].decode('cp932'), addr + 1
        elif data[addr] >= 0x80:
            return data[addr:addr+2].decode('cp932'), addr + 2
        elif data[addr] >= 0x20:
            return data[addr:addr+1].decode('cp932'), addr + 1
    except UnicodeDecodeError as e:
        print(f"Unable to interpret SJIS sequence {data[addr:addr+2].hex()}")
        raise e


@dataclass(kw_only=True)
class EventCodeInfo:
    length:int
    mnemonic:str|None = None
    newline:bool = False
    terminator:bool = False


EVENT_CODE_INFO = {
    0x00: EventCodeInfo(mnemonic="END",      length=1,  newline=True, terminator=True),
    0x01: EventCodeInfo(mnemonic="N",        length=1,  newline=True),
    0x02: EventCodeInfo(mnemonic="ACTOR",    length=1),
    0x03: EventCodeInfo(mnemonic="WAIT",     length=1,  newline=True),
    0x04: EventCodeInfo(mnemonic="C_NONE",   length=1),
    0x05: EventCodeInfo(mnemonic="PAGE",     length=1,  newline=True),
    0x06: EventCodeInfo(mnemonic="RET",      length=1,  terminator=True),
    0x07: EventCodeInfo(mnemonic="RET_N",    length=1,  terminator=True),
    0x08: EventCodeInfo(mnemonic="CLEAR",    length=1),
    0x09: EventCodeInfo(mnemonic="CH",       length=2),
    0x0a: EventCodeInfo(mnemonic="RET_PAGE", length=1,  terminator=True),
    0x0b: EventCodeInfo(mnemonic="PARTY",    length=1),
    0x0c: EventCodeInfo(mnemonic="SND",      length=3),
    0x0d: EventCodeInfo(                     length=1,  terminator=True),
    0x0e: EventCodeInfo(mnemonic="ITEM",     length=1),
    0x0f: EventCodeInfo(mnemonic="JUMP",     length=3),
    0x10: EventCodeInfo(mnemonic="CALL",     length=3),
    0x11: EventCodeInfo(mnemonic="IF_NOT",   length=3),
    0x12: EventCodeInfo(mnemonic="IF",       length=3),
    0x13: EventCodeInfo(mnemonic="UNSET",    length=3),
    0x14: EventCodeInfo(mnemonic="SET",      length=3),
    0x15: EventCodeInfo(mnemonic="ASM",      length=3),
    0x16: EventCodeInfo(mnemonic="LEADER",   length=11),
    0x1a: EventCodeInfo(mnemonic="C_RED",    length=1),
    0x1c: EventCodeInfo(mnemonic="C_GREEN",  length=1),
    0x1e: EventCodeInfo(mnemonic="C_YELLOW", length=1),
    0x1f: EventCodeInfo(                     length=1),

    # New codes for DS6-2
    0xf0: EventCodeInfo(length=2),
    0xf1: EventCodeInfo(length=2),
    0xf2: EventCodeInfo(length=3),
    0xf3: EventCodeInfo(length=3),
    0xf4: EventCodeInfo(length=4),
    0xf5: EventCodeInfo(length=4),
    0xf6: EventCodeInfo(length=3),
    0xf7: EventCodeInfo(length=1),
    0xf8: EventCodeInfo(length=4),
    0xf9: EventCodeInfo(length=4),
    0xfb: EventCodeInfo(length=5),
}


@dataclass(kw_only=True)
class DS6InstructionBase:
    addr:int
    continuation:bool = False

@dataclass(kw_only=True)
class DS6TextInstruction(DS6InstructionBase):
    text:str

@dataclass(kw_only=True)
class DS6CodeInstruction(DS6InstructionBase):
    code:int
    data:typing.ByteString = b''

    @property
    def length(self):
        return len(self.data) + 1

    @property
    def arg_as_int(self):
        return int.from_bytes(self.data, byteorder='little')


def disassemble_event(scenario_data, base_addr, start_addr, continuation_extent_end_addr=None) -> list[DS6InstructionBase]:

    addr = start_addr - base_addr
    instructions:list[DS6InstructionBase] = []

    jumps = set()

    while True:
        if addr+base_addr in jumps:
            jumps.remove(addr+base_addr)

            # Split up text if a jump lands in the middle of a block of text.
            if len(instructions) > 0 and isinstance(instructions[-1], DS6TextInstruction):
                instructions.append(DS6TextInstruction(addr=addr+base_addr, text=""))

        if scenario_data[addr] < 0x20 or scenario_data[addr] >= 0xf0:
            code = scenario_data[addr]

            if code not in EVENT_CODE_INFO:
                raise Exception(f"Unknown code {scenario_data[addr]:02x} at {addr+base_addr:03x}!")

            code_info = EVENT_CODE_INFO[code]

            instructions.append(DS6CodeInstruction(addr=addr+base_addr, code=code, data=scenario_data[addr+1:addr+1+code_info.length - 1]))

            addr += code_info.length

            if code == 0x0f:
                jumps.add(instructions[-1].arg_as_int)
            elif code == 0x15: # ASM call
                if instructions[-1].arg_as_int == 0xe887:
                    break
            elif code_info.terminator:
                if addr+base_addr in jumps and continuation_extent_end_addr is not None and addr+base_addr <= continuation_extent_end_addr:
                    raise Exception(f"Event at {start_addr:04x} has both a jump to the end and a continuation. So confusing...")
                elif addr+base_addr in jumps:
                    jumps.remove(addr+base_addr)
                elif continuation_extent_end_addr is not None and addr+base_addr <= continuation_extent_end_addr:
                    instructions[-1].continuation = True
                else:
                    break
        else:
            if len(instructions) == 0 or not isinstance(instructions[-1], DS6TextInstruction):
                instructions.append(DS6TextInstruction(addr=addr+base_addr, text=""))

            try:
                ch, addr = read_sjis_char(scenario_data, addr)
                instructions[-1].text += ch
            except UnicodeDecodeError as e:
                print(f"Unable to interpret SJIS sequence {scenario_data[addr:addr+2].hex()} at {addr+base_addr:04x} while disassembling event at {start_addr:04x}")
                raise e

    return instructions


@dataclass
class EncodedEventLocationMarker:
    offset:int
    addr:int

def encode_event_string(text:str, max_length=None) -> tuple[typing.ByteString, list[EncodedEventLocationMarker], list[EncodedEventLocationMarker]]:

    encoded = bytearray()
    references:list[EncodedEventLocationMarker] = []
    locators:list[EncodedEventLocationMarker] = []

    terminated = False

    text = text.replace("\r", "")

    while len(text) > 0:

        terminated = False

        if text.startswith("\n<CONT>"):
            current_encoded_bytes = b''
            text = text[7:]
            continue

        current_encoded_bytes = None

        if text.startswith("<"):
            tag_end_loc = text.find(">")
            if tag_end_loc < 0:
                raise Exception(f"Tag starting at {text[:10]} does not seem to be closed.")
            tag_contents = text[1:tag_end_loc]

            if tag_contents.startswith("LOC"):
                if len(tag_contents) != 7:
                    raise Exception(f"Tag <{tag_contents}> has the incorrect data length.")
                loc_addr = int(tag_contents[3:7], base=16)
                loc_offset = len(encoded)
                #locators[loc_addr] = loc_offset
                locators.append(EncodedEventLocationMarker(loc_offset, loc_addr))
                current_encoded_bytes = b''
                text = text[tag_end_loc + 1:]
            elif tag_contents.startswith("X"):
                code = int(tag_contents[1:3], base=16)
                current_encoded_bytes = bytes([code]) + bytes.fromhex(tag_contents[3:])

                code_info = EVENT_CODE_INFO[code]
                if code_info.terminator:
                    terminated = True
                text = text[tag_end_loc + 1:]
            else:
                code, code_info = None, None

                for c, i in EVENT_CODE_INFO.items():
                    if i.mnemonic is not None and tag_contents.startswith(i.mnemonic):
                        if code_info is None:
                            assert(code is None)
                            code, code_info = c, i
                        elif len(i.mnemonic) > len(code_info.mnemonic):
                            code, code_info = c, i

                if code is None or code_info is None:
                    raise Exception(f"Unrecognized tag <{tag_contents}>")

                current_encoded_bytes = bytes([code])

                data_length = code_info.length - 1
                arg_str = tag_contents[len(code_info.mnemonic):]
                if data_length == 0:
                    if len(arg_str) > 0:
                        raise Exception(f"Unexpected argument text \"{arg_str}\" following tag <{code_info.mnemonic}>")
                elif data_length == 1:
                    # Should only be used for character name
                    if len(arg_str) != 1:
                        raise Exception(f"Argument text \"{arg_str}\" following tag <{code_info.mnemonic}> has the wrong length")
                    arg = int(arg_str)
                    current_encoded_bytes += int.to_bytes(arg, length=1, byteorder='little')
                elif data_length == 2:
                    # Used for a bunch of things that need pointers
                    if len(arg_str) != 4:
                        raise Exception(f"Argument text \"{arg_str}\" following tag <{code_info.mnemonic}> has the wrong length")
                    arg = int(arg_str, base=16)
                    current_encoded_bytes += int.to_bytes(arg, length=2, byteorder='little')

                    if code == 0x0f: # Jump
                        #references.append((len(encoded) + 1, arg))
                        references.append(EncodedEventLocationMarker(len(encoded) + 1, arg))
                        if len(text) == 0:
                            terminated = True
                    elif code == 0x10: # Call
                        #references.append((len(encoded) + 1, arg))
                        references.append(EncodedEventLocationMarker(len(encoded) + 1, arg))


                elif data_length == 10:
                    # Used for the "LEADER" code
                    if len(tag_contents) != 30:
                        raise Exception(f"Argument text \"{arg_str}\" following tag <{code_info.mnemonic}> has the wrong length")
                    for ref_index in range(5):
                        call_addr = int(tag_contents[6 + ref_index*5:6 + ref_index*5 + 4], base=16)
                        #references.append((len(encoded) + ref_index*2 + 1, call_addr))
                        references.append(len(encoded) + ref_index*2 + 1, call_addr)
                        current_encoded_bytes += int.to_bytes(call_addr, 2, 'little')
                else:
                    raise Exception(f"Unexpected data length {code_info.length} for code {code:02x} ({code_info.mnemonic})")

                if code_info.terminator:
                    terminated = True

                text = text[tag_end_loc + 1:]

                if code_info.newline:
                    if text[0] != "\n":
                        raise Exception(f"Tag <{code_info.mnemonic}> should be followed by a newline.")
                    text = text[1:]
        elif text.startswith("\n\n"):
                current_encoded_bytes = b'\x05'
                text = text[2:]
        elif text.startswith("\n"):
            current_encoded_bytes = b'\x01'
            text = text[1:]
        else:
            current_encoded_bytes = text[0].encode(encoding='cp932')
            text = text[1:]

        if not terminated and max_length is not None and len(encoded) + len(current_encoded_bytes) > max_length - 1:
            print("Text is too long! Truncating.")
            break
        elif terminated and max_length is not None and len(encoded) + len(current_encoded_bytes) > max_length:
            raise Exception("Terminated text is too long!")
        else:
            encoded += current_encoded_bytes

    if not terminated:
        encoded += b'\x00'

    return encoded, references, locators


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

            print(f"{instruction.addr:04x}  ", end='')

            if isinstance(instruction, DS6TextInstruction):
                print(instruction.text, end='')
            elif EVENT_CODE_INFO[instruction.code].mnemonic is not None:
                print(f"{EVENT_CODE_INFO[instruction.code].mnemonic:8} {instruction.data.hex()} ", end='')
            else:
                print(f"{instruction.code:02x}       {instruction.data.hex()} ", end='')

            if True in [not isinstance(out_link, Link) and 'source_addr' in out_link and instruction['addr'] == out_link['source_addr'] for out_link in self._outgoing_links]:
                print("--> ", end='')
            else:
                print("    ", end='')

            print()
        print()


    def _explore(self):
        for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, self._continuation_extent_end_addr):
            pass

        self._length = instruction.addr + instruction.length - self._start_addr

    def link(self, block_pool:BlockPool):
        for link, link_path in zip(self._incoming_links, self._incoming_link_path_index):
            link_path_info = self._link_paths[link_path]
            if 'is_linked' in link_path_info:
                continue

            link_target_addr = link.target_addr
            execution_context = link.execution_context

            jump_map = {}

            for instruction in disassemble_event(self._data, self.base_addr, self.start_addr, 0):
                if instruction.addr in jump_map:
                    self.add_internal_reference(jump_map[instruction.addr] + 1, instruction.addr, source_instruction_addr=jump_map[instruction.addr])
                    del jump_map[instruction.addr]

                if isinstance(instruction, DS6CodeInstruction):
                    code = instruction.code
                    if code == 0x0f: # Jump
                        arg = instruction.arg_as_int
                        jump_map[arg] = instruction.addr
                    elif code == 0x10: # Subroutine
                        arg = instruction.arg_as_int
                        link = Link(instruction.addr + 1, arg, source_instruction_addr=instruction.addr)
                        if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                            link.connect_blocks(self, None)
                            self.add_global_reference(instruction.addr + 1, arg)
                        else:
                            link.connect_blocks(self, block_pool.get_block("event", arg))

                    elif code == 0x15: # ASM call
                        arg = instruction.arg_as_int
                        link = Link(instruction.addr + 1, arg, source_instruction_addr=instruction.addr)
                        if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                            link.connect_blocks(self, None)
                            self.add_global_reference(instruction.addr + 1, arg)
                        else:
                            link.connect_blocks(self, block_pool.get_block("code", arg))

                    elif code == 0x16: # Subroutine call based on leader
                        for ref_index in range(5):
                            arg = int.from_bytes(instruction.data[ref_index*2:ref_index*2+2], 'little')
                            link = Link(instruction.addr + ref_index*2 + 1, arg, source_instruction_addr=instruction.addr)
                            if (arg < self._base_addr or arg >= self._base_addr + len(self._data)):
                                link.connect_blocks(self, None)
                                self.add_global_reference(instruction.addr + ref_index*2 + 1, arg)
                            else:
                                link.connect_blocks(self, block_pool.get_block("event", arg))

            for jump_target, jump_source in jump_map.items():
                link = Link(jump_source + 1, jump_target, source_instruction_addr=jump_source)
                if (jump_target < self._base_addr or jump_target >= self._base_addr + len(self._data)):
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
            if instruction.addr in jumps:
                jumps.remove(instruction.addr)
                if len(out) > 0:
                    out += f"<LOC{instruction.addr:04x}>"
            elif instruction.addr in external_locators:
                if len(out) > 0:
                    out += f"<LOC{instruction.addr:04x}>"

            if isinstance(instruction, DS6TextInstruction):
                out += instruction.text
            else:
                code = instruction.code
                if code not in EVENT_CODE_INFO:
                    raise Exception(f"Unknown code {code:02x} at {instruction.addr:04x}!")

                code_info = EVENT_CODE_INFO[code]

                if code == 0x00 and instruction.addr == self.end_addr:
                    # No <END> tag at the end of the string.
                    pass
                elif code == 0x01 and self._data[instruction.addr - self.base_addr + 1] != 0x01:
                    out += "\n"
                elif code == 0x05 and self._data[instruction.addr - self.base_addr - 1] != 0x01:
                    out += "\n\n"
                elif code_info.mnemonic is None:
                    out += f"<X{code:02x}{instruction.data.hex()}>"
                else:
                    mnemonic = code_info.mnemonic
                    data_length = code_info.length - 1
                    if data_length == 0:
                        out += f"<{mnemonic}>"
                    elif data_length == 1:
                        # Should only be used for character name
                        out += f"<{mnemonic}{instruction.arg_as_int}>"
                    elif data_length == 2:
                        # Used for a bunch of things that need pointers
                        out += f"<{mnemonic}{instruction.arg_as_int:04x}>"
                    elif data_length == 10:
                        # Used for the "LEADER" code
                        out += f"<{mnemonic}"
                        for ref_index in range(5):
                            arg = int.from_bytes(instruction.data[ref_index*2:ref_index*2+2], 'little')
                            if ref_index > 0:
                                out += ","
                            out += f"{arg:04x}"
                        out += ">"
                    else:
                        raise Exception(f"Unexpected data length {code_info.length} for code {code:02x} ({mnemonic})")

                    if code_info.newline:
                        out += "\n"

                if code == 0x0f:
                    jumps.add(instruction.arg_as_int)

                if instruction.continuation:
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
            return (instruction.operands[0].value.imm & 0xffff) in [ 0x12e2, 0x12e7, 0x3160, 0x31da, 0x3234, 0x3249 ]

    def generate_links(self, instruction, block_pool, current_block, registers):
        if X86_REG_SI in registers:
            event_addr = registers[X86_REG_SI]['value']

            if block_pool.domain_contains("event", event_addr):

                disassembly = disassemble_event(block_pool.get_domain_data("event"), block_pool.get_domain_base_addr("event"), event_addr)

                if 'source_addr' in registers[X86_REG_SI]:

                    event_link = Link(registers[X86_REG_SI]['source_addr'], event_addr)
                    event_link.connect_blocks(current_block, block_pool.get_block("event", event_addr))

                    registers[X86_REG_SI]['continue_from_addr'] = event_addr
                    registers[X86_REG_SI]['value'] = disassembly[-1].addr + disassembly[-1].length

                    del registers[X86_REG_SI]['source_addr']
                else:
                    current_block = block_pool.get_block("event", registers[X86_REG_SI]['continue_from_addr'])
                    current_block.set_continuation_extent(event_addr)

                    registers[X86_REG_SI]['value'] = disassembly[-1].addr + disassembly[-1].length
            else:
                global_event_link = Link(registers[X86_REG_SI]['source_addr'], event_addr)
                global_event_link.connect_blocks(current_block, None)
                current_block.add_global_reference(registers[X86_REG_SI]['source_addr'], event_addr, is_event=True)

        else:
            print(f"No known event address for event call at {instruction.address:04x}")
            print("Current registers:")
            print(registers)


class DS62_OverrideRegister(X86CodeHook):
    def __init__(self, addr:int, register:int, force_to_value:int, force_to_source_addr:int):
        super().__init__()

        self._addr = addr
        self._register = register
        self._force_to_value = force_to_value
        self._force_to_source_addr = force_to_source_addr

    def should_handle(self, instruction:CsInsn) -> bool:
        return instruction.address == self._addr

    def generate_links(self, instruction:CsInsn, block_pool: BlockPool, current_block: Block, registers) -> None:
        registers[self._register] = { 'source_addr': self._force_to_source_addr, 'value': self._force_to_value }


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


class DS62_OverworldDestinationTableCodeHook(X86CodeHook):

    def __init__(self, addr:int, entry_size:int=0xc, next_addr:int|None=None):
        super().__init__()

        self._addr = addr
        self._entry_size = entry_size
        self._next_addr = next_addr

    def should_handle(self, instruction:CsInsn) -> bool:
        return instruction.address == self._addr

    def get_next_ip(self, instruction:CsInsn) -> int:
        return self._next_addr

    def generate_links(self, instruction:CsInsn, block_pool:BlockPool, current_block:Block, registers) -> None:
        addr = registers[X86_REG_SI]['value']
        entry_count = registers[X86_REG_CX]['value']
        base_addr = block_pool.get_domain_base_addr("event")

        for table_index in range(entry_count):
            code_addr = addr - block_pool.get_domain_base_addr("event") + block_pool.get_domain_base_addr("code")

            entry_data = block_pool.get_domain_data("event")[addr-base_addr:addr-base_addr+self._entry_size]

            handler_code_addr = int.from_bytes(entry_data[0x8:0xa], byteorder='little')
            name_event_addr = int.from_bytes(entry_data[0xa:0xc], byteorder='little')

            if block_pool.domain_contains("code", handler_code_addr):
                link = Link(code_addr + 0x8, handler_code_addr)
                link.connect_blocks(current_block, block_pool.get_block("code", handler_code_addr))

            if block_pool.domain_contains("event", name_event_addr):
                    link = Link(code_addr + 0xa, name_event_addr)
                    link.connect_blocks(current_block, block_pool.get_block("event", name_event_addr))

            addr += self._entry_size


class DS62_PointerTableCodeHook(X86CodeHook):
    def __init__(self, addr:int, table_addr:int, entry_size:int=0x2, next_addr:int|None=None, table_domain:str = "event"):
        super().__init__()

        self._addr = addr
        self._table_addr = table_addr
        self._entry_size = entry_size
        self._next_addr = next_addr
        self._table_domain = table_domain

    def should_handle(self, instruction):
        return instruction.address == self._addr

    def get_next_ip(self, instruction:CsInsn) -> int:
        return None

    def generate_links(self, instruction, block_pool, current_block, registers):
        for table_index in range(5):
            entry_pointer_addr = self._table_addr + 2 * table_index
            entry_addr = int.from_bytes(block_pool.get_domain_data(self._table_domain)[entry_pointer_addr:entry_pointer_addr+2], byteorder='little')

            link = Link(entry_pointer_addr, entry_addr)
            link.connect_blocks(current_block, block_pool.get_block("code", entry_addr))

