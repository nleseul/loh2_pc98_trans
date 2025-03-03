import csv
from dataclasses import dataclass, asdict, field
import os
import typing
import yaml



@dataclass
class BaseReference:
    source_addr:int
    target_addr:int

@dataclass
class CodeReference(BaseReference, yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!CodeReference'

@dataclass
class DataReference(BaseReference, yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!DataReference'


@dataclass
class BaseEntry:
    pass

@dataclass
class RelocatableEntry:
    references:list[BaseReference] = field(default_factory=list)

    original_byte_length:int = 0

@dataclass
class RelocatableRawDataEntry(RelocatableEntry, yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!RelocatableRawDataEntry'

    data:bytes = b''

    def __init__(self, references:list[BaseReference], data:bytes):
        super().__init__(references, len(data))

        self.data = data

@dataclass
class TranslatableEntry(BaseEntry):
    original:str = ""
    translated:str|None = None

    @property
    def text(self) -> str:
        return self.translated if self.translated is not None else self.original

@dataclass
class FixedTranslatableEntry(TranslatableEntry, yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!FixedTranslatableEntry'

    max_byte_length:int = 0

@dataclass
class RelocatableTranslatableEntry(TranslatableEntry, RelocatableEntry, yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!RelocatableTranslatableEntry'


class TranslationCollection(yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_tag = '!TranslationCollection'

    def __init__(self):
        self._note = ""
        self._end_of_file_addr = None
        self._entries:dict[int, BaseEntry] = {}

    def add_entry(self, key:int, entry:BaseEntry) -> None:
        if key in self._entries:
            raise Exception(f"TranslationCollection already contains an entry for key {key:04x}")
        self._entries[key] = entry

    def get_entry(self, key:int) -> BaseEntry|None:
        if key in self._entries:
            return self._entries[key]
        else:
            return None

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

    #@property
    #def keys(self) -> typing.Generator[int, None, None]:
    #    yield from self._entries.keys()

    def translatables(self) -> typing.Generator[tuple[int, TranslatableEntry], None, None]:
        for key, entry in self._entries.items():
            if isinstance(entry, TranslatableEntry):
                yield key, entry

    def relocatables(self) -> typing.Generator[tuple[int, RelocatableEntry], None, None]:
        for key, entry in self._entries.items():
            if isinstance(entry, RelocatableEntry):
                yield key, entry

    def import_translations(self, other:'TranslationCollection') -> None:
        self._note = other.note

        #for key in self._entries.keys():
        #    if key in other._entries:
        #        self._entries[key].translated = other._entries[key].translated
        for key, entry in self.translatables():
            other_entry = other.get_entry(key)
            if other_entry is not None and isinstance(other_entry, TranslatableEntry):
                entry.translated = other_entry.translated

    def save(self, filename:str) -> None:
        #out_dict_entries = {}

        #for key, entry in self._entries.items():
        #    out_dict_entries[f"{key:04x}"] = asdict(entry)

        #out_dict = {
        #    'note': self._note,
        #    'end_of_file_addr': self._end_of_file_addr,
        #    'entries': out_dict_entries
        #}

        with open(filename, 'w+', encoding='utf-8') as out_file:
            #yaml.dump(out_dict, out_file, allow_unicode=True, default_style='|')
            yaml.dump(self, out_file, allow_unicode=True, default_style='|')

    #def load(filename:str) -> 'TranslationCollection':
    def load(filename:str) -> 'TranslationCollection':
        trans = TranslationCollection()

        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as in_file:
                #yaml_in = yaml.safe_load(in_file)
                yaml_in = yaml.safe_load(in_file)

            if isinstance(yaml_in, TranslationCollection):
                trans = yaml_in
            else:
                trans._note = yaml_in['note']
                trans.end_of_file_addr = yaml_in['end_of_file_addr']

                for key_string, entry_dict in yaml_in['entries'].items():
                    key = int(key_string, base=16)
                    #entry = TranslationEntry(**entry_dict)
                    if entry_dict['is_relocatable']:
                        entry = RelocatableTranslatableEntry(original=entry_dict['original'],
                                                            translated=entry_dict['translated'],
                                                            original_byte_length=entry_dict['original_byte_length'])
                        for ref_dict in entry_dict['references']:
                            entry.references.append(CodeReference(**ref_dict))
                    else:
                        entry = FixedTranslatableEntry(original=entry_dict['original'],
                                                    translated=entry_dict['translated'],
                                                    max_byte_length=entry_dict['max_byte_length'])

                    trans._entries[key] = entry
        else:
            trans = TranslationCollection()

        return trans
