import csv
from dataclasses import dataclass
import os
import typing


@dataclass
class TranslationEntry:
    original:str = ""
    translated:str = ""


def load_csv(filename:str) -> typing.Dict[int, TranslationEntry]:
    csv_data = {}
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf8', newline='') as csv_in:
            csv_reader = csv.reader(csv_in, quoting=csv.QUOTE_ALL, lineterminator=os.linesep)
            for row in csv_reader:
                key = int(row[0], base=16)
                entry = TranslationEntry(row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else "")
                csv_data[key] = entry
    return csv_data


def add_csv_original(csv_data:typing.Dict[int, TranslationEntry], key:int, new_original_text:str) -> None:
    if key not in csv_data:
        csv_data[key] = TranslationEntry()
    csv_data[key].original = new_original_text


def add_csv_translated(csv_data:typing.Dict[int, TranslationEntry], key:int, new_translated_text:str) -> None:
    if key not in csv_data:
        csv_data[key] = TranslationEntry()
    csv_data[key].translated = new_translated_text


def save_csv(filename:str, text:typing.Dict[int, TranslationEntry]) -> None:
    with open(filename, 'w+', encoding='utf8', newline='') as csv_out:
        csv_writer = csv.writer(csv_out, quoting=csv.QUOTE_ALL, lineterminator=os.linesep)
        for key in text.keys():
            csv_writer.writerow([f"{key:04x}", text[key].original, text[key].translated])
