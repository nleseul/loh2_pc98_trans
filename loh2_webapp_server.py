import configparser
import difflib
import flask
import flask_httpauth
import json
import markupsafe
import operator
import os
import re
import typing

from ds6_event_util import *
from trans_util import *

app = flask.Flask(__name__)
auth = flask_httpauth.HTTPBasicAuth()


def get_config() -> configparser.SectionProxy:
    if 'config' not in flask.g:
        configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        configfile.read("loh2_patch.conf")
        flask.g.config = configfile["WebApp"]
    return flask.g.config

@auth.verify_password
def verify(username, password):
    correct_password = get_config()["Password"]
    if password == correct_password:
        return True
    else:
        return False


class TextRenderer:
    def __init__(self, width:int, lines_per_page:int = 4, fudge_characters:list[str] = []):
        self._width = width
        self._lines_per_page = lines_per_page
        self._fudge_characters = fudge_characters

        self._pages = []
        self._current_page_text = ""

        self._page_line_count = 0
        self._line_char_count = 0
        self._has_active_style = False

    @property
    def pages(self) -> typing.Generator[str, None, None]:
        yield from self._pages

        if len(self._current_page_text):
            if self._has_active_style:
                yield self._current_page_text + "</span>"
            else:
                yield self._current_page_text

    @property
    def page_count(self) -> int:
        return len(self._pages) + (1 if len(self._current_page_text) > 0 else 0)

    def add_text(self, text:str) -> None:
        for ch_index, ch in enumerate(text):
            if ch == " ":
                self._current_page_text += "&nbsp;"
            else:
                self._current_page_text += ch
            self._line_char_count += len(ch.encode('cp932'))

            if self._line_char_count < self._width:
                pass
            elif self._line_char_count > self._width:
                self.add_newline()
            elif ch_index < len(text) - 1 and text[ch_index+1] in self._fudge_characters:
                pass
            else:
                self.add_newline()

    def add_debug_text(self, text) -> None:
        self._current_page_text += text

    def add_newline(self) -> None:
        if self._page_line_count + 1 == self._lines_per_page:
            self.add_page_break()
        else:
            self._current_page_text += "<br/>"
            self._page_line_count += 1
            self._line_char_count = 0

    def add_page_break(self, allow_blank_page:bool = True) -> None:
        if not allow_blank_page and len(self._current_page_text) == 0:
            return

        if self._has_active_style:
            self.cancel_text_style()
        self._pages.append(self._current_page_text)

        self._current_page_text = ""
        self._page_line_count = 0
        self._line_char_count = 0

    def change_text_style(self, style:str) -> None:
        if self._has_active_style:
            self.cancel_text_style()
        self._current_page_text += f"<span class=\"{style}\">"
        self._has_active_style = True

    def cancel_text_style(self) -> None:
        self._current_page_text += f"</span>"
        self._has_active_style = False


def make_condition_description(code:int, data:bytes) -> str | None:
    if code == 0x11 or code == 0x12:
        return data[::-1].hex()
    elif code == 0xf2:
        return f"notEnoughMoney({data[1::-1].hex()})"
    elif code == 0xf6:
        loc = int.from_bytes(data, byteorder='little')
        if loc == 0x1753:
            return "noRoomInInventory()"
        elif loc == 0x2992:
            return "choseNo()"
        else:
            return f"asmCheck({loc:04x})"
    elif code == 0xf8:
        loc = int.from_bytes(data[1:], byteorder='little')
        arg = int.from_bytes(data[:1], byteorder='little')
        if loc == 0x1774:
            return f"notCarryingItem({arg:02x})"
        elif loc == 0x17af:
            return f"notCarryingItem2({arg:02x})"
        return f"asmCheck({loc:04x},{arg:02x})"


def render_text_html(trans:TranslationCollection, entry_point_key:int, max_pages:int|None = None, translated:bool = True,
                     active_conditions:list[str] = [], window_width:int = 34, window_height:int = 4) -> tuple[list[str], list[str]]:
    fudge_characters = [".", ",", "!"] if translated else ["。", "!"]
    renderer = TextRenderer(window_width, window_height, fudge_characters)

    locator_to_key_and_offset = {}
    encoded_events = {}

    for key, data in trans.translatables():
        event_string = data.translated if translated else data.original

        if event_string is None:
            encoded_event, locators = b'', []
        else:
            encoded_event, _, locators = encode_event_string(data.translated if translated else data.original)

        encoded_events[key] = encoded_event
        locator_to_key_and_offset[key] = (key, 0)
        for locator in locators:
            locator_to_key_and_offset[locator.addr] = (key, locator.offset)

    disassembled_events = disassemble_event(encoded_events[entry_point_key], entry_point_key, entry_point_key)
    instruction_index = 0

    call_stack = []

    condition_was_true = None
    conditions_checked = set()

    jump_history = set()

    pending_text = ""

    while instruction_index < len(disassembled_events):
        instruction = disassembled_events[instruction_index]
        instruction_index += 1
        if isinstance(instruction, DS6TextInstruction):
            pending_text += instruction.text
        elif isinstance(instruction, DS6CodeInstruction):
            if len(pending_text) > 0:
                renderer.add_text(pending_text)
                pending_text = ""
            code = instruction.code
            if code == 0x00:
                break
            elif code == 0x01:
                renderer.add_newline()
            elif code == 0x03:
                renderer.add_newline() # Wait, includes implied newline
            elif code == 0x04:
                renderer.cancel_text_style()
            elif code == 0x05:
                renderer.add_page_break()
            elif code == 0x06 or code == 0x07 or code == 0x0a:
                if len(call_stack) > 0:
                    disassembled_events, instruction_index = call_stack.pop()

                    if code == 0x07:
                        renderer.add_newline()
                    elif code == 0x0a:
                        renderer.add_page_break()
                else:
                    break
            elif code == 0x08:
                renderer.add_page_break(allow_blank_page=False)
            elif code == 0x09:
                character_index = int.from_bytes(instruction.data, byteorder='little')
                if translated:
                    character_name = ["Atlas", "Landor", "Flora", "Cindy"][character_index]
                else:
                    character_name = ["アトラス", "ランドー", "フローラ", "シンディ"][character_index]
                renderer.change_text_style("text_yellow")
                renderer.add_text(character_name)
                renderer.cancel_text_style()

            elif code == 0x0b:
                renderer.change_text_style("text_yellow")
                renderer.add_text("Landor" if translated else "ランドー")
                renderer.cancel_text_style()
                renderer.add_text("'s party" if translated else "たち")

            elif code == 0x0e:
                renderer.change_text_style("text_yellow")
                renderer.add_text("Leather Shield")
                renderer.cancel_text_style()

            elif code == 0x0f:
                if condition_was_true is None or condition_was_true:
                    jump_target = int.from_bytes(instruction.data, byteorder='little')
                    if jump_target in jump_history:
                        renderer.add_newline()
                        renderer.change_text_style("unknown_tag")
                        renderer.add_debug_text(f"Cycle detected when jumping")
                        renderer.add_newline()
                        renderer.add_debug_text(f"to {jump_target:04x} from {instruction.addr:04x}!")
                        renderer.cancel_text_style()
                        break

                    if jump_target not in locator_to_key_and_offset:
                        renderer.add_newline()
                        renderer.change_text_style("unknown_tag")
                        renderer.add_debug_text(f"Unknown jump target address {jump_target:04x}!")
                        renderer.cancel_text_style()
                        break

                    #print(f"Jump to {jump_target:04x} from {instruction.addr:04x}")
                    jump_history.add(jump_target)

                    jump_target_key, jump_target_offset = locator_to_key_and_offset[jump_target]
                    #print(f"key={jump_target_key:04x}, offset={jump_target_offset}")
                    disassembled_events = disassemble_event(encoded_events[jump_target_key], jump_target_key, jump_target_key+jump_target_offset)
                    instruction_index = 0
                #else:
                #    print("Skipping jump due to false condition")
                condition_was_true = None
            elif code == 0x10:
                if condition_was_true is None or condition_was_true:
                    call_target = int.from_bytes(instruction.data, byteorder='little')
                    if call_target not in locator_to_key_and_offset:
                        renderer.add_newline()
                        renderer.change_text_style("unknown_tag")
                        renderer.add_debug_text(f"Unknown call target address {call_target:04x}!")
                        renderer.cancel_text_style()
                        break
                    #print(f"Call to {call_target:04x} from {instruction.addr:04x}")

                    call_stack.append((disassembled_events, instruction_index))

                    call_target_key, call_target_offset = locator_to_key_and_offset[call_target]
                    #print(f"key={call_target_key:04x}, offset={call_target_offset}")
                    disassembled_events = disassemble_event(encoded_events[call_target_key], call_target_key, call_target_key+call_target_offset)
                    instruction_index = 0
                condition_was_true = None
            elif code == 0x11:
                condition = make_condition_description(code, instruction.data)
                condition_was_true = condition not in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true} (inverted)")
            elif code == 0x12:
                condition = make_condition_description(code, instruction.data)
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code == 0x1a:
                renderer.change_text_style("text_red")
            elif code == 0x1c:
                renderer.change_text_style("text_green")
            elif code == 0x1e:
                renderer.change_text_style("text_yellow")
            elif code == 0x1f:
                renderer.change_text_style("text_white")
            elif code == 0xf2:
                # This appears to check if your current gold is at least the
                # value at the given memory address. Usually paired with 0xf3,
                # which probably deducts that amount from your current gold.
                condition = make_condition_description(code, instruction.data)
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code == 0xf6:
                # I think this is probably making an asm call and checking the return
                # value of that? Data is the address of the call.
                condition = make_condition_description(code, instruction.data)
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code == 0xf8:
                # I think this is probably making an asm call and checking the return
                # value of that? First byte is a parameter, second two bytes are the
                # call address. Mostly used for checking if you're carrying an item.
                condition = make_condition_description(code, instruction.data)
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code in [0x0c, 0x13, 0x14, 0x15, 0xf0, 0xf1, 0xf3, 0xf5, 0xf7, 0xf9]:
                # Control codes that don't need to affect text preview rendering.
                pass
            else:
                renderer.change_text_style("unknown_tag")
                renderer.add_debug_text(f"{instruction.code:02x}{':' if len(instruction.data) > 0 else ''}{instruction.data.hex()} ")
                renderer.cancel_text_style()
        else:
            raise Exception("Unknown instruction type - " + instruction)

        if max_pages is not None and renderer.page_count >= max_pages:
            break

    if len(pending_text) > 0:
        renderer.add_text(pending_text)

    return list(renderer.pages), list(conditions_checked)


def render_opening_text_html(text:str) -> str:
    if text is None or len(text) == 0:
        return []
    else:
        return [page_text.replace("\n", "<br/>").replace(" ", "&nbsp;") for page_text in text.split("<PAGE>\n")]


def render_ending_text_html(text:str, is_end_credits:bool = False) -> str:

    if text is None:
        return []

    renderer = TextRenderer(26, 10) if is_end_credits else TextRenderer(60, 2)

    current_name = None

    while len(text) > 0:
        if text.startswith("<NAME>"):
            text = text[6:]
            name = ""
            while len(name.encode('cp932')) < 8:
                name += text[:1]
                text = text[1:]

            renderer.add_text(name + "  ")

            current_name = name

            text = text[8:]
        elif text.startswith("<PAUSE>"):
            text = text[7:]
        elif text.startswith("<PAGE>\n"):
            renderer.add_page_break(allow_blank_page=False)
            if current_name is not None:
                renderer.add_text("          ")
            text = text[7:]
        elif text.startswith("<PAGE_PAUSE>\n"):
            renderer.add_page_break(allow_blank_page=False)
            if current_name is not None:
                renderer.add_text("          ")
            text = text[13:]
        elif text.startswith("<PAGE_FULL>\n"):
            renderer.add_page_break(allow_blank_page=False)
            current_name = None
            text = text[12:]
        elif text.startswith("<CHANGE_FREYA_GRAPHIC>"):
            text = text[22:]
        elif text.startswith("<STAFF_ROLL_MARKER>"):
            text = text[19:]
        elif text.startswith("\n"):
            renderer.add_newline()
            if current_name is not None:
                renderer.add_text("          ")
            text = text[1:]
        else:
            renderer.add_text(text[:1])
            text = text[1:]

    return list(renderer.pages)


def get_yaml_path(folder_key:str, file_name:str) -> str:
    path = None
    if folder_key is None or len(folder_key) == 0:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    return path

def load_trans(folder_key:str, file_name:str) -> TranslationCollection:
    path = get_yaml_path(folder_key, file_name)
    return TranslationCollection.load(path)

def save_trans(folder_key:str, file_name:str, trans:TranslationCollection) -> None:
    path = get_yaml_path(folder_key, file_name)
    trans.save(path)

    update_index_cache(folder_key, file_name, trans)


def text_contains_japanese(text:str) -> bool:
    return re.search("[\u3040-\u30ff]", text) or re.search("[\u4e00-\u9faf]", text)

def calculate_progress(trans:TranslationCollection) -> float:
    total_items = 0
    items_done = 0
    for key, item in trans.translatables():
        total_items += 1
        if item.translated is not None and len(item.translated) > 0:
            if text_contains_japanese(item.translated):
                items_done += 0.5
            else:
                items_done += 1

    return items_done / total_items if total_items > 0 else 0


def create_index_cache() -> dict:
    index_cache = {}

    for folder_key in [None, "Scenarios", "Combats"]:
        dir_path = "yaml" if folder_key is None else f"yaml/{folder_key}"

        for file in os.listdir(dir_path):
            if not file.endswith(".yaml"):
                continue

            display_name = file[:-5]
            if display_name.endswith(".BZH"):
                display_name = display_name[:-4]

            trans = load_trans(folder_key, display_name)

            item_info = {
                'display_name': display_name,
                'note': trans.note,
                'progress': calculate_progress(trans)
            }

            cache_key = f"{folder_key}/{display_name}" if folder_key is not None else display_name
            index_cache[cache_key] = item_info

    os.makedirs("local/webapp", exist_ok=True)
    with open("local/webapp/index_cache.yaml", "w+") as out_file:
        yaml.safe_dump(index_cache, out_file)

    return index_cache

def load_index_cache() -> dict:
    if os.path.exists("local/webapp/index_cache.yaml"):
        print("Using stored index cache")
        with open("local/webapp/index_cache.yaml", "r") as in_file:
            return yaml.safe_load(in_file)

    print("Recreating index cache")
    return create_index_cache()

def update_index_cache(folder_key:str, file_name:str, trans:TranslationCollection) -> None:

    cache_key = file_name if folder_key is None or folder_key == "" else f"{folder_key}/{file_name}"
    print(f"Updating index cache for {cache_key}")

    index_cache = load_index_cache()

    index_cache[cache_key] = {
        'display_name': file_name,
        'note': trans.note,
        'progress': calculate_progress(trans)
    }

    with open("local/webapp/index_cache.yaml", "w+") as out_file:
        yaml.safe_dump(index_cache, out_file)


def full_path_to_folder_and_file_name(full_path:str) -> tuple[str, str]:
    first_sep = full_path.rfind("/")
    folder_path = "" if first_sep < 0 else full_path[:first_sep]
    file_name = full_path if first_sep < 0 else full_path[first_sep+1:]

    return folder_path, file_name


@app.route("/")
@auth.login_required
def index():
    return flask.render_template("index.html.jinja")

@app.route("/document")
@auth.login_required
def document():
    return flask.render_template("document.html.jinja")

@app.route("/unit")
@auth.login_required
def unit():
    return flask.render_template("unit.html.jinja")

@app.route("/search")
@auth.login_required
def search():
    return flask.render_template("search.html.jinja")


@app.route("/api/list_documents")
@auth.login_required
def list_documents():
    requested_folder_path = flask.request.args['folder_path'] if 'folder_path' in flask.request.args else ""

    index_cache = load_index_cache()

    files = []
    folders = set()

    for cache_key, info in index_cache.items():
        assert(isinstance(cache_key, str))
        folder_path, file_name = full_path_to_folder_and_file_name(cache_key)

        if folder_path == requested_folder_path:
            info = { 'full_path': cache_key,
                     'display_name': info['display_name'],
                     'note': info['note'],
                     'progress': info['progress'],
                     'is_folder': False }
            files.append(info)
        elif folder_path.startswith(requested_folder_path):
            folders.add(folder_path)

    for folder_name in folders:
        files.append( { 'display_name': folder_name, 'full_path': folder_name, 'is_folder': True})

    files.sort(key=lambda f: (not f['is_folder'], f['display_name']))

    return files

@app.route("/api/get_document_note")
@auth.login_required
def get_document_note():
    document_path = flask.request.args['document_path']

    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    trans = load_trans(folder_path, file_name)

    return trans.note

@app.route("/api/list_units")
@auth.login_required
def list_units():
    document_path = flask.request.args['document_path']

    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    trans = load_trans(folder_path, file_name)

    units = []
    for key, entry in trans.translatables():
        if file_name == "Opening":
            original_pages = render_opening_text_html(entry.original)
            translated_pages = render_opening_text_html(entry.translated)
        elif file_name == "Ending":
            original_pages = render_ending_text_html(entry.original)
            translated_pages = render_ending_text_html(entry.translated)
        elif isinstance(entry, FixedTranslatableWindowEntry):
            line_count = entry.forced_line_count if entry.forced_line_count is not None else entry.line_count
            original_pages, _ = render_text_html(trans, key, translated=False, window_width=entry.window_width, window_height=line_count)
            translated_pages, _ = render_text_html(trans, key, translated=True, window_width=entry.window_width, window_height=line_count)
        else:
            original_pages, _ = render_text_html(trans, key, 3, translated=False)
            translated_pages, _ = render_text_html(trans, key, 3, translated=True)

        has_translation = entry.translated is not None and len(entry.translated) > 0
        is_done = has_translation and not text_contains_japanese(entry.translated)
        is_in_progress = has_translation and not is_done

        units.append({
            'key': f"{key:04x}",
            'original': original_pages if len(original_pages) > 0 else None,
            'translated': translated_pages if len(translated_pages) > 0 else None,
            'translation_done': is_done,
            'translation_in_progress': is_in_progress
        })

    return units


@app.route("/api/get_unit_info")
@auth.login_required
def get_unit_info():
    document_path = flask.request.args['document_path']
    key_str = flask.request.args['key']

    key = int(key_str, base=16)

    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    trans = load_trans(folder_path, file_name)
    key_list = sorted([key for key, _ in trans.translatables()])

    key_index = key_list.index(key)

    prev_key = None if key_index == 0 else key_list[key_index - 1]
    next_key = None if key_index == len(key_list) - 1 else key_list[key_index + 1]

    prev_key_str = None if prev_key is None else f"{prev_key:04x}"
    next_key_str = None if next_key is None else f"{next_key:04x}"

    current_item_info = None

    conditions = set()
    for k in key_list:
        item = trans.get_entry(k)
        assert(isinstance(item, TranslatableEntry))

        if k == key:
            current_item_info = item

        if file_name != "Opening" and file_name != "Ending":
            encoded, _, _ = encode_event_string(item.original)
            for instruction in disassemble_event(encoded, k, k):
                if isinstance(instruction, DS6CodeInstruction):
                    condition_str = make_condition_description(instruction.code, instruction.data)
                    if condition_str is not None:
                        conditions.add(condition_str)
    condition_list = sorted(conditions)

    assert(current_item_info is not None)

    if file_name == "Opening":
        window_width, window_height = 62, 9
    elif file_name == "Ending":
        if key == 0x2b76:
            window_width, window_height = 26, 10
        else:
            window_width, window_height = 62, 2
    elif isinstance(current_item_info, FixedTranslatableWindowEntry):
        window_width = current_item_info.window_width
        window_height = current_item_info.forced_line_count if current_item_info.forced_line_count is not None else current_item_info.line_count
    else:
        window_width, window_height = 34, 4

    return {
        'file_name': file_name,
        'folder_path': folder_path,
        'key': key_str,
        'window_width': window_width,
        'window_height': window_height,
        'condition_list': condition_list,
        'prev_key': prev_key_str,
        'next_key': next_key_str,
        'original': current_item_info.original,
        'translation': current_item_info.translated
    }


@app.route("/api/search_units")
@auth.login_required
def search_units():

    search_term = markupsafe.escape(flask.request.args.get('search_term'))
    results = []

    for path, dirs, files in os.walk("yaml"):
        folder_key = path[5:] if len(path) > 5 else None
        for file in files:
            file_name = file[:-9] if file.endswith("BZH.yaml") else file[:-5]

            trans = TranslationCollection.load(os.path.join(path, file))

            for key, item in trans.translatables():
                if item.original is not None:
                    original_index = item.original.find(search_term)
                    if original_index >= 0:
                        excerpt_start_index = max(original_index - 20, 0)
                        excerpt_end_index = min(original_index + len(search_term) + 20, len(item.original))
                        results.append({'document_path': f"{folder_key}/{file_name}",
                                        'key': f"{key:04x}",
                                        'excerpt': markupsafe.escape(item.original[excerpt_start_index:excerpt_end_index]),
                                        'translated': False})

                if item.translated is not None:
                    translated_index = item.translated.find(search_term)
                    if translated_index >= 0:
                        excerpt_start_index = max(translated_index - 20, 0)
                        excerpt_end_index = min(translated_index + len(search_term) + 20, len(item.translated))
                        results.append({'document_path': f"{folder_key}/{file_name}",
                                        'key': f"{key:04x}",
                                        'excerpt': markupsafe.escape(item.translated[excerpt_start_index:excerpt_end_index]),
                                        'translated': True})
    return results

@app.route("/api/render_unit_text", methods=['POST'])
@auth.login_required
def render_unit_text():
    document_path = flask.request.form['document_path']
    key_str = flask.request.form['key']

    key = int(key_str, base=16)

    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    translated = True
    if 'which_text' in flask.request.form and flask.request.form['which_text'] == "original":
        translated = False

    active_conditions = json.loads(flask.request.form['active_conditions'])

    key = int(key_str, base=16)

    trans = load_trans(folder_path, file_name)
    entry = trans.get_entry(key)
    assert(isinstance(entry, TranslatableEntry))

    if file_name == "Opening":
        pages = render_opening_text_html(entry.translated if translated else entry.original)
        conditions_checked = []
    elif file_name == "Ending":
        pages = render_ending_text_html(entry.translated if translated else entry.original, key == 0x2b76)
        conditions_checked = []
    elif isinstance(entry, FixedTranslatableWindowEntry):
        line_count = entry.forced_line_count if entry.forced_line_count is not None else entry.line_count
        pages, conditions_checked = render_text_html(trans, key, translated=translated, active_conditions=active_conditions,
                                                     window_width=entry.window_width, window_height=line_count)
    else:
        pages, conditions_checked = render_text_html(trans, key, translated=translated, active_conditions=active_conditions)

    return { 'pages': pages, 'conditions_checked': conditions_checked }

@app.route("/api/update_unit_text", methods=['POST'])
@auth.login_required
def update_unit_text():
    document_path = flask.request.form['document_path']
    key_str = flask.request.form['key']

    key = int(key_str, base=16)
    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    new_text = flask.request.form['new_text']
    new_text = new_text.replace("\r\n", "\n")

    key = int(key_str, base=16)

    trans = load_trans(folder_path, file_name)
    entry = trans.get_entry(key)
    assert(isinstance(entry, TranslatableEntry))
    entry.translated = new_text
    save_trans(folder_path, file_name, trans)

    return flask.Response(status=200)

@app.route("/api/update_document_note", methods=['POST'])
@auth.login_required
def update_document_note():
    document_path = flask.request.form['document_path']
    new_note = flask.request.form['new_note']

    folder_path, file_name = full_path_to_folder_and_file_name(document_path)

    trans = load_trans(folder_path, file_name)
    trans.note = new_note
    save_trans(folder_path, file_name, trans)

    return flask.Response(status=200)

@app.route("/api/find_similar_units", methods=['POST'])
@auth.login_required
def find_similar_units():
    original_document_path = flask.request.form['document_path']
    original_key_str = flask.request.form['key']
    original_folder_path, original_file_name = full_path_to_folder_and_file_name(original_document_path)

    original_trans = load_trans(original_folder_path, original_file_name)

    original_key = int(original_key_str, base=16)
    original_entry = original_trans.get_entry(original_key)
    assert(isinstance(original_entry, TranslatableEntry))
    original_text = original_entry.original

    matcher = difflib.SequenceMatcher(a=original_text)

    results = []

    for path, dirs, files in os.walk("yaml"):
        folder_key = path[5:] if len(path) > 5 else ""

        for file in files:
            file_name = file[:-9] if file.endswith("BZH.yaml") else file[:-5]

            trans = TranslationCollection.load(os.path.join(path, file))

            for key, entry in trans.translatables():
                if key == original_key and file_name == original_file_name and folder_key == original_folder_path:
                    continue

                if entry.translated is not None and len(entry.translated) > 0:
                    matcher.set_seq2(entry.original)

                    if matcher.quick_ratio() > 0.6:
                        results.append( {
                            'document_path': f"{folder_key}/{file_name}",
                            'key': f"{key:04x}",
                            'original': entry.original,
                            'translated': entry.translated,
                            'similarity': matcher.ratio()
                        })

    results.sort(key=lambda r: r['similarity'], reverse=True)

    return results

