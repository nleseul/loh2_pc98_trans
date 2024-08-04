from bitarray import bitarray

def decompress_bzh(in_file):

    class FlagStream:
        def __init__(self, flag_source):
            self._flags = bitarray(endian='little')

            new_flags = flag_source.read(1)
            self._flags.frombytes(new_flags)


        def next_flag(self, flag_source):
            if len(self._flags) == 0:
                new_flags = flag_source.read(2)
                self._flags.frombytes(new_flags)
            flag = self._flags[0]
            self._flags = self._flags[1:]
            return (flag != 0)

        def next_int(self, flag_source, bit_count):
            value = 0
            for _ in range(bit_count):
                value <<= 1
                value += 1 if self.next_flag(flag_source) else 0
            return value

    output = bytearray()

    file_size = int.from_bytes(in_file.read(3), byteorder='little')

    flag_stream = FlagStream(in_file)

    while True:
        if flag_stream.next_flag(in_file):

            duplicate_offset = None

            if flag_stream.next_flag(in_file): # Path: 1-1
                value = (flag_stream.next_int(in_file, 5) << 8) + int.from_bytes(in_file.read(1), byteorder='little')

                # When value = 1, read an RLE segment
                if value == 1:
                    repeat_count = 0
                    if flag_stream.next_flag(in_file):
                        repeat_count = (flag_stream.next_int(in_file, 4) << 8) + int.from_bytes(in_file.read(1), byteorder='little') + 14
                    else:
                        repeat_count = flag_stream.next_int(in_file, 4) + 14
                    value_to_repeat = int.from_bytes(in_file.read(1), byteorder='little')

                    repeating_bytes = bytes([value_to_repeat] * repeat_count)
                    output += repeating_bytes

                # When value = 0, this indicates the end of the data.
                elif value == 0:
                    break

                # For any other value, it's the offset for a dupicated segment.
                else:
                    duplicate_offset = value

            else: # Path: 1-0
                # Read one byte; use it as the offset for a duplicated segment.
                duplicate_offset = int.from_bytes(in_file.read(1), byteorder='little')

            # However we detect a duplicate segment, it's handled the same way:
            # - Counts between 2 and 5 are indicated by a sequence of 0-3 0 bits, followed by a 1 bit.
            # - Counts 6 or higher are indicated by four 0 bits in a row.
            # - If the next bit after that is a 1, we read a 3-bit value from the flags.
            # - Otherwise, we read a normal byte from the file.
            if duplicate_offset is not None:
                duplicate_count = 2

                while True:
                    flag = flag_stream.next_flag(in_file)
                    if flag:
                        break
                    elif duplicate_count > 4:
                        if flag_stream.next_flag(in_file):
                            duplicate_count = 6 + flag_stream.next_int(in_file, 3)
                        else:
                            duplicate_count = int.from_bytes(in_file.read(1), byteorder='little') + 14
                        break
                    else:
                        duplicate_count += 1

                for _ in range(duplicate_count):
                    output.append(output[-duplicate_offset])

        else: # Path: 0
            output_bytes = in_file.read(1)
            output += output_bytes

    if in_file.tell() != file_size:
        raise Exception(f"Ended at byte {in_file.tell()}, which does not match the expected file size {file_size})")

    return output