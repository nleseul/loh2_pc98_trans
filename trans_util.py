import csv
from dataclasses import dataclass, asdict, field
import os
import typing
import yaml


@dataclass
class CodeReference:
    source_addr:int
    target_addr:int


@dataclass
class TranslationEntry:
    original:str = ""
    translated:str|None = None

    original_byte_length:int|None = None

    is_relocatable:bool = True
    references:list[CodeReference] = field(default_factory=list)
    max_byte_length:int|None = None

    @property
    def text(self) -> str:
        return self.translated if self.translated is not None else self.original


class TranslationCollection:
    def __init__(self):
        self._note = ""
        self._end_of_file_addr = None
        self._entries:dict[int, TranslationEntry] = {}

    def __getitem__(self, key:int) -> TranslationEntry:
        if key not in self._entries:
            self._entries[key] = TranslationEntry()
        return self._entries[key]

    @property
    def empty(self) -> bool:
        return len(self._entries) == 0 and len(self._note) == 0

    @property
    def note(self) -> str:
        return self._note

    @note.setter
    def note(self, value:str) -> None:
        self._note = value

    @property
    def end_of_file_addr(self) -> int:
        return self._end_of_file_addr

    @end_of_file_addr.setter
    def end_of_file_addr(self, value:str) -> None:
        self._end_of_file_addr = value

    @property
    def keys(self) -> typing.Generator[int, None, None]:
        yield from self._entries.keys()

    def import_translations(self, other:'TranslationCollection') -> None:
        self._note = other.note

        for key in self._entries.keys():
            if key in other._entries:
                self._entries[key].translated = other._entries[key].translated

    def save(self, filename:str) -> None:
        out_dict_entries = {}

        for key, entry in self._entries.items():
            out_dict_entries[f"{key:04x}"] = asdict(entry)

        out_dict = {
            'note': self._note,
            'end_of_file_addr': self._end_of_file_addr,
            'entries': out_dict_entries
        }

        with open(filename, 'w+', encoding='utf-8') as out_file:
            yaml.dump(out_dict, out_file, allow_unicode=True, default_style='|')

    def load(filename:str) -> 'TranslationCollection':
        trans = TranslationCollection()
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as in_file:
                yaml_in = yaml.safe_load(in_file)

            trans._note = yaml_in['note']
            trans.end_of_file_addr = yaml_in['end_of_file_addr']

            for key_string, entry_dict in yaml_in['entries'].items():
                key = int(key_string, base=16)
                entry = TranslationEntry(**entry_dict)
                for ref_index in range(len(entry.references)):
                    entry.references[ref_index] = CodeReference(**entry.references[ref_index])

                trans._entries[key] = entry

        return trans
