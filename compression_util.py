from bitarray import bitarray
import typing

def decompress_bzh(in_file:typing.BinaryIO) -> typing.ByteString:

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


def compress_bzh(input:typing.ByteString) -> typing.ByteString:
    class FlagStreamWriter:
        def __init__(self, output):
            self._flag_offset = len(output)
            self._flags_size = 1
            self._flag_shift = 0
            output += b"\x00"

        def write_flag(self, output, flag):

            if self._flag_shift >= self._flags_size * 8:
                self._flag_shift = 0
                self._flags_size = 2
                self._flag_offset = len(output)
                output += b"\x00\x00"

            temp = int.from_bytes(output[self._flag_offset:self._flag_offset + self._flags_size], byteorder='little')
            if flag != 0:
                temp |= 1 << self._flag_shift
            output[self._flag_offset:self._flag_offset + self._flags_size] = temp.to_bytes(self._flags_size, byteorder='little')

            self._flag_shift += 1

        def write_int(self, output, value, size):
            if value >= 2 ** size:
                raise Exception(f"Cannot encode value {value} using {size} bits.")

            for bit_index in range(size - 1, -1, -1):
                bit = 0 if value & (1 << bit_index) == 0 else 1
                self.write_flag(output, bit)

    input_processed = bytearray()
    output = bytearray()

    flag_writer = FlagStreamWriter(output)

    while len(input) > 0:

        best_length = 0
        best_start_offset = None
        for duplicate_scan_start_offset in range(1, min(len(input_processed), 8192)):
            candidate = input_processed[-duplicate_scan_start_offset:]
            match_count = 0
            for i, o in zip(candidate, input):
                if match_count > 255 + 14:
                    break
                elif i == o:
                    match_count += 1
                else:
                    break
            if match_count > best_length:
                best_length = match_count
                best_start_offset = duplicate_scan_start_offset

        repeat_count = 0
        for i in input:
            if i == input[0]:
                repeat_count += 1
            else:
                break

        if repeat_count >= 14 and repeat_count >= best_length:
            flag_writer.write_flag(output, 1)
            flag_writer.write_flag(output, 1)
            flag_writer.write_int(output, 0, 5)
            output.append(1)
            if repeat_count >= 16 + 14:
                flag_writer.write_flag(output, 1)
                value_to_write = repeat_count - 14
                flag_writer.write_int(output, value_to_write >> 8, 4)
                output.append(value_to_write % 256)
            else:
                flag_writer.write_flag(output, 0)
                flag_writer.write_int(output, repeat_count - 14, 4)
            output.append(input[0])

            input_processed += input[:repeat_count]
            input = input[repeat_count:]

        elif best_length >= 2:
            if best_start_offset >= 256:
                flag_writer.write_flag(output, 1)
                flag_writer.write_flag(output, 1)
                flag_writer.write_int(output, best_start_offset >> 8, 5)
                output.append(best_start_offset % 256)
            else:
                flag_writer.write_flag(output, 1)
                flag_writer.write_flag(output, 0)
                output.append(best_start_offset)

            if best_length >= 6:
                flag_writer.write_flag(output, 0)
                flag_writer.write_flag(output, 0)
                flag_writer.write_flag(output, 0)
                flag_writer.write_flag(output, 0)
                if best_length >= 14:
                    flag_writer.write_flag(output, 0)
                    output.append(best_length - 14)
                else:
                    flag_writer.write_flag(output, 1)
                    flag_writer.write_int(output, best_length - 6, 3)
            else:
                for _ in range(best_length - 2):
                    flag_writer.write_flag(output, 0)
                flag_writer.write_flag(output, 1)

            input_processed += input[:best_length]
            input = input[best_length:]
        else:
            flag_writer.write_flag(output, 0)
            output.append(input[0])
            input_processed.append(input[0])
            input = input[1:]

    flag_writer.write_flag(output, 1)
    flag_writer.write_flag(output, 1)

    for _ in range(5):
        flag_writer.write_flag(output, 0)
    output += b"\x00"

    length = len(output) + 3
    output = length.to_bytes(3, byteorder='little') + output

    return output
