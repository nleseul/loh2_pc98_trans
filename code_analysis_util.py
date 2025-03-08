from dataclasses import dataclass, field
import typing

from capstone import *
from capstone.x86 import *

class Link:
    def __init__(self, source_addr:int, target_addr:int, source_instruction_addr:int=None, execution_context:dict={}):
        self._source_addr = source_addr
        self._target_addr = target_addr

        self._source_instruction_addr = source_instruction_addr
        self._execution_context = execution_context

        self._source_block:'Block' = None
        self._target_block:'Block' = None

    @property
    def source_addr(self) -> int:
        return self._source_addr

    @property
    def source_instruction_addr(self) -> int:
        return self._source_instruction_addr

    @property
    def execution_context(self) -> dict:
        return self._execution_context

    @property
    def source_block(self) -> 'Block':
        return self._source_block

    @property
    def target_addr(self) -> int:
        return self._target_addr

    @property
    def target_block(self) -> 'Block':
        return self._target_block

    def connect_blocks(self, source_block:'Block', target_block:'Block') -> None:
        self._source_block = source_block
        self._target_block = target_block

        if source_block is not None:
            source_block.connect_outgoing_link(self)
        if target_block is not None:
            target_block.connect_incoming_link(self)


class Block:
    def __init__(self, data:typing.ByteString, base_addr:int, start_addr:int, params:dict|None = None):
        self._data = data
        self._base_addr = base_addr
        self._start_addr = start_addr
        self._length:int = None

        self._incoming_links:typing.List[Link] = []
        self._outgoing_links:typing.List[Link] = []
        self._internal_references = []
        self._global_references = []

        self._incoming_link_path_index = []
        self._link_paths = []

        self._explore()

    def __str__(self) -> str:
        str = f"<{type(self).__name__} {self._start_addr:04x}"

        if self._length is not None:
            str += f"~{self.end_addr:04x}"

        str += f", {len(self._incoming_links)} incoming, {len(self._outgoing_links)} outgoing>"

        return str

    @property
    def base_addr(self) -> int:
        return self._base_addr

    @property
    def start_addr(self) -> int:
        return self._start_addr

    @property
    def end_addr(self) -> int:
        return None if self._length is None else self._start_addr + self._length - 1

    @property
    def length(self) -> int:
        return self._length

    @property
    def is_explored(self) -> bool:
        return self._length is not None

    @property
    def is_linked(self) -> bool:
        return False not in ['is_linked' in link_path_info for link_path_info in self._link_paths]

    @property
    def is_relocatable(self) -> bool:
        return False not in [link.source_addr is not None for link in self._incoming_links]

    def dump(self) -> None:
        raise NotImplementedError("Implement this in a subclass!")

    def _explore(self) -> None:
        raise NotImplementedError("Implement this in a subclass!")

    def link(self, block_pool) -> None:
        raise NotImplementedError("Implement this in a subclass!")

    def _context_is_equivalent(self, c1:dict, c2:dict):
        raise NotImplementedError("Implement this in a subclass!")

    def move_start_addr(self, new_addr:int) -> None:
        self._start_addr = new_addr
        self._length = None

        self._explore()

    def connect_incoming_link(self, link:Link) -> None:

        link_key = (link.target_addr, link.execution_context)
        link_path = None
        for existing_link_index, existing_link in enumerate(self._incoming_links):
            existing_link_path = self._incoming_link_path_index[existing_link_index]
            existing_link_path_info = self._link_paths[existing_link_path]

            if existing_link_path_info['key'] == link_key:
                link_path = existing_link_path
                break

        if link_path is None:
            link_path = len(self._link_paths)
            self._link_paths.append( { 'key': link_key } )

        self._incoming_link_path_index.append(link_path)
        self._incoming_links.append(link)

    def connect_outgoing_link(self, link:Link) -> None:
        self._outgoing_links.append(link)

    def add_internal_reference(self, source_addr:int, dest_addr:int, **kwargs) -> None:
        ref = { 'source_addr': source_addr, 'dest_addr': dest_addr }

        for key, value in kwargs.items():
            ref[key] = value

        self._internal_references.append(ref)

    def get_internal_references(self) -> typing.Iterable[dict]:
        for ref in self._internal_references:
            yield ref

    def add_global_reference(self, source_addr:int, dest_addr:int, **kwargs) -> None:
        ref = { 'source_addr': source_addr, 'dest_addr': dest_addr }

        for key, value in kwargs.items():
            ref[key] = value

        self._global_references.append(ref)

    def get_global_references(self) -> typing.Iterable[dict]:
        for ref in self._global_references:
            yield ref

    def contains(self, addr:int) -> bool:
        if self._length is None:
            return addr == self._start_addr
        else:
            return addr >= self._start_addr and addr <= self.end_addr

    def get_incoming_links(self) -> typing.Iterable[Link]:
        for link in self._incoming_links:
            yield link

    def get_outgoing_links(self) -> typing.Iterable[Link]:
        for link in self._outgoing_links:
            yield link


class BlockPool:

    @dataclass
    class DomainInfo:
        data: typing.ByteString
        base_addr: int
        create_block_func: typing.Callable[[], Block]
        params: dict = field(default_factory=dict)
        blocks: typing.List[Block] = field(default_factory=list)

    def __init__(self):
        self._domains:typing.Dict[str, BlockPool.DomainInfo] = {}

    def register_domain(self, name:str, data:typing.ByteString, base_addr:int, create_block_func, params:dict|None = None):
        if name in self._domains:
            raise Exception(f"Domain named {name} is already registered in this block pool.")
        self._domains[name] = BlockPool.DomainInfo(data, base_addr, create_block_func)
        if params is not None:
            self._domains[name].params = params

    def get_domain_base_addr(self, domain:str) -> int:
        return self._domains[domain].base_addr

    def get_domain_data(self, domain:str) -> typing.ByteString:
        return self._domains[domain].data

    def read_data_from_domain(self, domain:str, addr:int, length:int) -> typing.ByteString:
        base_addr = self.get_domain_base_addr(domain)
        data = self.get_domain_data(domain)

        if not self.domain_contains(domain, addr):
            raise Exception(f"Trying to read data at address {addr:04x} in domain {domain}, which is only defined in range {base_addr:04x}~{base_addr+len(data):04x}.")

        return data[addr-base_addr:addr-base_addr+length]

    def domain_contains(self, domain:str, addr:int) -> bool:
        domain_info = self._domains[domain]
        return addr >= domain_info.base_addr and addr < domain_info.base_addr + len(domain_info.data)


    def get_block(self, domain:str, addr:int) -> Block:
        domain_info = self._domains[domain]

        for block in domain_info.blocks:
            if block.contains(addr):
                return block

        new_block = domain_info.create_block_func(domain_info.data, domain_info.base_addr, addr, domain_info.params)

        for block in domain_info.blocks:
            if new_block.contains(block.start_addr):
                block.move_start_addr(new_block.start_addr)
                return block

        domain_info.blocks.append(new_block)
        return new_block

    def get_blocks(self, domain:str|None = None) -> typing.Iterable[Block]:
        if domain is None:
            for domain_info in self._domains.values():
                for block in domain_info.blocks:
                    yield block
        else:
            for block in self._domains[domain].blocks:
                yield block

    def get_unexplored_blocks(self) -> typing.Iterable[Block]:
        for block in self.get_blocks():
            if not block.is_explored:
                yield block

    def get_unlinked_blocks(self) -> typing.Iterable[Block]:
        for block in self.get_blocks():
            if not block.is_linked:
                yield block


class X86CodeHook:
    def should_handle(self, instruction:CsInsn) -> bool:
        raise NotImplementedError("Handle this in a subclass")

    def get_next_ip(self, instruction:CsInsn) -> int:
        if instruction.id == X86_INS_JMP or instruction.id == X86_INS_LJMP or X86_GRP_RET in instruction.groups:
            return None
        else:
            return instruction.address + instruction.size

    def generate_links(self, instruction:CsInsn, block_pool:BlockPool, current_block:Block, registers) -> None:
        pass


class EmptyHook(X86CodeHook):
    def __init__(self, addr:int, is_call:bool, next_ip:int=None, stop:bool = False):
        self._addr = addr
        self._is_call = is_call
        self._next_ip = next_ip
        self._stop = stop

    def get_next_ip(self, instruction):
        if self._stop:
            return None
        elif self._next_ip is None:
            return super().get_next_ip(instruction)
        else:
            return self._next_ip

    def should_handle(self, instruction):
        if self._is_call:
            return (X86_GRP_CALL in instruction.groups or X86_GRP_JUMP in instruction.groups) and instruction.operands[0].type == CS_OP_IMM and instruction.operands[0].imm == self._addr
        else:
            return instruction.address == self._addr

    def generate_links(self, instruction, block_pool, current_block, registers):
        pass


class X86CodeBlock(Block):

    _hooks:typing.List[X86CodeHook] = []

    def __init__(self, data:typing.ByteString, base_addr:int, start_addr:int, params:dict):
        if 'hooks' in params and params['hooks'] is not None:
            self._hooks = params['hooks']

        super().__init__(data, base_addr, start_addr, params)


    def dump(self):
        disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
        disassembler.detail = True
        disasm_iter = disassembler.disasm(self._data[self.start_addr - self.base_addr:], self.start_addr)

        done = False
        while not done:
            instruction = next(disasm_iter)

            if True in [isinstance(in_link, Link) and instruction.address == in_link.target_addr for in_link in self._incoming_links]:
                print("--> ", end='')
            else:
                print("    ", end='')

            hook_found = False
            for hook in self._hooks:
                if hook.should_handle(instruction):
                    hook_found = True

                    print(f"{instruction.address:04x}  Hook: {hook}", end='')

                    next_ip = hook.get_next_ip(instruction)
                    if next_ip is None:
                        done = True
                    else:
                        disasm_iter = disassembler.disasm(self._data[next_ip - self._base_addr:], next_ip)

                    break

            if not hook_found:
                print(f"{instruction.address:04x}  {instruction.mnemonic:6} {instruction.op_str:25}", end='')

                if self.end_addr is None or instruction.address + instruction.size > self.end_addr:
                    done = True

            if True in [isinstance(out_link, Link) and out_link.source_instruction_addr is not None and instruction.address == out_link.source_instruction_addr for out_link in self._outgoing_links]:
                print("--> ", end='')
            else:
                print("    ", end='')

            print()

        if self.end_addr is None:
            print("    (Unexplored)")

        print()

    def _explore(self):
        disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
        disassembler.detail = True

        disasm_iter = disassembler.disasm(self._data[self._start_addr - self._base_addr:], self._start_addr)
        next_ip = None

        done = False
        while not done:
            try:
                instruction = next(disasm_iter)
            except StopIteration:
                print(f"Disassembly ended without terminator in code block starting at {self._start_addr:04x}")
                break

            hook_found = False
            for hook in self._hooks:
                if hook.should_handle(instruction):
                    hook_found = True

                    next_ip = hook.get_next_ip(instruction)
                    if next_ip is None:
                        done = True
                        next_ip = instruction.address + instruction.size
                    else:
                        disasm_iter = disassembler.disasm(self._data[next_ip - self._base_addr:], next_ip)

                    break

            if not hook_found:
                next_ip = instruction.address + instruction.size

                if instruction.id == X86_INS_JMP or instruction.id == X86_INS_LJMP:
                    done = True
                elif X86_GRP_RET in instruction.groups:
                    done = True

        self._length = next_ip - self.start_addr


    def link(self, block_pool):
        disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
        disassembler.detail = True

        for link, link_path in zip(self._incoming_links, self._incoming_link_path_index):
            link_path_info = self._link_paths[link_path]
            if 'is_linked' in link_path_info:
                continue

            link_target_addr = link.target_addr

            disasm_iter = disassembler.disasm(self._data[link_target_addr - self._base_addr:], link_target_addr)
            next_ip = None

            registers = link.execution_context.copy()

            done = False
            while not done:
                try:
                    instruction = next(disasm_iter)
                except StopIteration:
                    print(f"Disassembly ended without terminator in code block starting at {self._start_addr:04x}")
                    break

                hook_found = False
                for hook in self._hooks:
                    if hook.should_handle(instruction):
                        hook_found = True

                        hook.generate_links(instruction, block_pool, self, registers)

                        next_ip = hook.get_next_ip(instruction)
                        if next_ip is None:
                            done = True
                        else:
                            disasm_iter = disassembler.disasm(self._data[next_ip - self._base_addr:], next_ip)

                        break

                if not hook_found:
                    next_ip = instruction.address + instruction.size

                    (_, written_regs) = instruction.regs_access()
                    for r in written_regs:
                        if r in registers:
                            del registers[r]


                    if X86_GRP_JUMP in instruction.groups: # X86_GRP_JUMP
                        if instruction.operands[0].type == CS_OP_IMM:
                            destination = instruction.operands[0].value.imm

                            link = Link(instruction.address + 1, destination, source_instruction_addr=instruction.address, execution_context=registers.copy())

                            if (destination < self._base_addr or destination >= self._base_addr + len(self._data)):
                                link.connect_blocks(self, None)
                                self.add_global_reference(instruction.address + 1, destination)
                            else:
                                link.connect_blocks(self, block_pool.get_block("code", destination))
                        else:
                            print(f"Jump to non-immediate address from {instruction.address:04x}!!")

                        if instruction.id == X86_INS_JMP or instruction.id == X86_INS_LJMP:
                            break
                    elif instruction.id == X86_INS_LOOP:
                        if instruction.operands[0].type == CS_OP_IMM:
                            destination = instruction.operands[0].value.imm
                            link = Link(instruction.address + 1, destination, source_instruction_addr=instruction.address, execution_context=registers.copy())
                            if (destination < self._base_addr or destination >= self._base_addr + len(self._data)):
                                raise Exception(f"Global loop?? {instruction.addr:04x}")
                            else:
                                link.connect_blocks(self, block_pool.get_block("code", destination))
                        else:
                            print(f"Loop to non-immediate address from {instruction.address:04x}!!")
                    elif X86_GRP_CALL in instruction.groups:
                        if instruction.operands[0].type == CS_OP_IMM:
                            destination = instruction.operands[0].value.imm

                            link = Link(instruction.address + 1, destination, source_instruction_addr=instruction.address, execution_context=registers.copy())

                            if (destination < self._base_addr or destination >= self._base_addr + len(self._data)):
                                link.connect_blocks(self, None)
                                self.add_global_reference(instruction.address + 1, destination)
                            else:
                                target_block = block_pool.get_block("code", destination)
                                link.connect_blocks(self, target_block)

                            # Subroutine calls might do anything, so nuke everything we know about the registers at this point.
                            for r in list(registers.keys()):
                                del registers[r]
                        else:
                            print(f"Call to non-immediate address from {instruction.address:04x}!!")

                    elif X86_GRP_RET in instruction.groups:
                        done = True

                    elif instruction.id == X86_INS_MOV and instruction.operands[0].type == CS_OP_REG and instruction.operands[1].type == CS_OP_IMM:
                        reg_id = instruction.operands[0].value.reg
                        value = instruction.operands[1].value.imm
                        registers[reg_id] = { 'source_addr': instruction.address + 1, 'value': value }

            link_path_info['is_linked'] = True


class DataBlock(Block):
    def dump(self) -> None:
        addr = self.start_addr
        while addr < self.start_addr + self.length:
            line_end_addr = min(addr + 16, self.start_addr + self.length)
            print(f"{addr:04x}  {self._data[addr - self._base_addr:line_end_addr - self._base_addr].hex(' ')}")
            addr += 16

    def set_length(self, length:int) -> None:
        self._length = length

    @property
    def data(self) -> bytes:
        return self._data[self._start_addr-self._base_addr:self._start_addr-self._base_addr+self._length]

    def _explore(self) -> None:
        if self._length is None:
            self._length = 1

    def link(self, block_pool) -> None:
        for link, link_path in zip(self._incoming_links, self._incoming_link_path_index):
            link_path_info = self._link_paths[link_path]

            link_path_info['is_linked'] = True

    def _context_is_equivalent(self, c1:dict, c2:dict):
        return False
