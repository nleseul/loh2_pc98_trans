import flask
import flask_httpauth
import json
import markupsafe
import operator
import os
import typing

from ds6_event_util import *
from trans_util import *

app = flask.Flask(__name__)
auth = flask_httpauth.HTTPBasicAuth()


@auth.verify_password
def verify(username, password):
    if password == "foo":
        return True
    else:
        return False


class TextRenderer:
    def __init__(self, width:int, lines_per_page:int = 4):
        self._width = width
        self._lines_per_page = lines_per_page

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
        for ch in text:
            if ch == " ":
                self._current_page_text += "&nbsp;"
            else:
                self._current_page_text += ch
            self._line_char_count += len(ch.encode('cp932'))
            if self._line_char_count >= self._width:
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

    def cancel_text_style(self) -> None:
        self._current_page_text += f"</span>"
        self._has_active_style = False


def render_text_html(trans:TranslationCollection, entry_point_key:int, max_pages:int|None = None, translated:bool = True, active_conditions:list[str] = []) -> tuple[list[str], list[str]]:
    renderer = TextRenderer(34, 4)

    locator_to_key_and_offset = {}
    encoded_events = {}

    for key in trans.keys:
        data = trans[key]
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

    while instruction_index < len(disassembled_events):
        instruction = disassembled_events[instruction_index]
        instruction_index += 1
        if isinstance(instruction, DS6TextInstruction):
            renderer.add_text(instruction.text)
        elif isinstance(instruction, DS6CodeInstruction):
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
                character_name = ["At?las", "Landor", "Flora", "Cindy"][character_index]
                renderer.change_text_style("text_yellow")
                renderer.add_text(character_name)
                renderer.cancel_text_style()

            elif code == 0x0e:
                renderer.change_text_style("text_yellow")
                renderer.add_text("Leather Shield")
                renderer.cancel_text_style()

            elif code == 0x0f:
                if condition_was_true is None or condition_was_true:
                    jump_target = int.from_bytes(instruction.data, byteorder='little')
                    if jump_target not in locator_to_key_and_offset:
                        raise Exception(f"Unknown jump target address {jump_target:04x}!")
                    #print(f"Jump to {jump_target:04x}")

                    jump_target_key, jump_target_offset = locator_to_key_and_offset[jump_target]
                    #print(f"key={jump_target_key:04x}, offset={jump_target_offset}")
                    disassembled_events = disassemble_event(encoded_events[jump_target_key], jump_target_key, jump_target_key+jump_target_offset)
                    instruction_index = 0
                #else:
                #    print("Skipping jump due to false condition")
                condition_was_true = None
            elif code == 0x10:
                call_target = int.from_bytes(instruction.data, byteorder='little')
                if call_target not in locator_to_key_and_offset:
                    raise Exception(f"Unknown call target address {call_target:04x}!")
                #print(f"Call to {call_target:04x}")

                call_stack.append((disassembled_events, instruction_index))

                call_target_key, call_target_offset = locator_to_key_and_offset[call_target]
                #print(f"key={call_target_key:04x}, offset={call_target_offset}")
                disassembled_events = disassemble_event(encoded_events[call_target_key], call_target_key, call_target_key+call_target_offset)
                instruction_index = 0
            elif code == 0x11:
                condition = instruction.data[::-1].hex()
                condition_was_true = condition not in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true} (inverted)")
            elif code == 0x12:
                condition = instruction.data[::-1].hex()
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code == 0x1c:
                renderer.change_text_style("text_green")
            elif code == 0x1e:
                renderer.change_text_style("text_yellow")
            elif code == 0xf6:
                # I think this is probably making an asm call and checking the return
                # value of that? Data is the address of the call.
                condition = f"asmCheck({instruction.data[1::-1].hex()})"
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code == 0xf8:
                # I think this is probably making an asm call and checking the return
                # value of that? First byte is a parameter, second two bytes are the
                # call address. Mostly used for checking if you're carrying an item.
                condition = f"asmCheck({instruction.data[2:0:-1].hex()},{instruction.data[:1].hex()})"
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                #print(f"Checking condition {condition}... was {condition_was_true}")
            elif code in [0x0c, 0x13, 0x14, 0x15, 0xf0, 0xf1, 0xf7, 0xf9]:
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
    if folder_key is None:
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
                'note': trans.note
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

    print(f"Updating index cache for {folder_key}/{file_name}")

    index_cache = load_index_cache()

    cache_key = f"{folder_key}/{file_name}" if folder_key is not None else file_name

    index_cache[cache_key] = {
        'display_name': file_name,
        'note': trans.note
    }

    with open("local/webapp/index_cache.yaml", "w+") as out_file:
        yaml.safe_dump(index_cache, out_file)


@app.route("/")
@auth.login_required
def index():

    index_cache = load_index_cache()

    folder_files = {}

    for cache_key, info in index_cache.items():
        if '/' in cache_key:
            folder_key, file_name = cache_key.split("/")
        else:
            folder_key, file_name = None, cache_key

        if folder_key in folder_files:
            folder_files[folder_key].append(info)
        else:
            folder_files[folder_key] = [info]

    files = []

    for folder_key, folder_file_list in folder_files.items():
        if folder_key is None:
            files += folder_file_list
        else:
            files.append({
                'display_name': folder_key,
                'folder_key': folder_key,
                'folder_items': sorted(folder_file_list, key=operator.itemgetter('display_name'))
            })

    files.sort(key=lambda f: ('' if 'folder_key' not in f else f['folder_key'], f['display_name']), reverse=True)

    return flask.render_template("index.html.jinja", files=files)


@app.route("/items/<file_name>")
@app.route("/items/<folder_key>/<file_name>")
@auth.login_required
def items(file_name, folder_key=None):
    trans = load_trans(folder_key, file_name)

    if 'new_note' in flask.request.args:
        trans.note = flask.request.args['new_note']
        save_trans(folder_key, file_name, trans)

    items = []
    for key in trans.keys:

        if file_name == "Opening":
            original_pages = render_opening_text_html(trans[key].original)
            translated_pages = render_opening_text_html(trans[key].translated)
        elif file_name == "Ending":
            original_pages = render_ending_text_html(trans[key].original)
            translated_pages = render_ending_text_html(trans[key].translated)
        else:
            original_pages, _ = render_text_html(trans, key, 3, translated=False)
            translated_pages, _ = render_text_html(trans, key, 3, translated=True)

        items.append({
            'key': f"{key:04x}",
            'original': original_pages if len(original_pages) > 0 else None,
            'translated': translated_pages if len(translated_pages) > 0 else None
        })

    return flask.render_template("items.html.jinja", items=items, file_name=file_name, folder_key=folder_key, note=trans.note)


@app.route("/edit_item/<file_name>/<key_str>")
@app.route("/edit_item/<folder_key>/<file_name>/<key_str>")
@auth.login_required
def edit_item(file_name, key_str, folder_key=None):
    key = int(key_str, base=16)

    trans = load_trans(folder_key, file_name)
    key_list = sorted(list(trans.keys))

    key_index = key_list.index(key)

    prev_key = None if key_index == 0 else key_list[key_index - 1]
    next_key = None if key_index == len(key_list) - 1 else key_list[key_index + 1]

    prev_key_str = None if prev_key is None else f"{prev_key:04x}"
    next_key_str = None if next_key is None else f"{next_key:04x}"

    conditions = set()
    if file_name != "Opening" and file_name != "Ending":
        for k in key_list:
            item = trans[k]
            encoded, _, _ = encode_event_string(item.original)
            for instruction in disassemble_event(encoded, k, k):
                if isinstance(instruction, DS6CodeInstruction):
                    if instruction.code == 0x11 or instruction.code == 0x12:
                        conditions.add(instruction.data[::-1].hex())
                    elif instruction.code == 0xf6:
                        conditions.add(f"asmCheck({instruction.data[1::-1].hex()})")
                    elif instruction.code == 0xf8:
                        conditions.add(f"asmCheck({instruction.data[2:0:-1].hex()},{instruction.data[:1].hex()})")
    condition_list = sorted(conditions)

    current_item_info = trans[key]

    if file_name == "Opening":
        window_width, window_height = 62, 9
    elif file_name == "Ending":
        if key == 0x2b76:
            window_width, window_height = 26, 10
        else:
            window_width, window_height = 62, 2
    else:
        window_width, window_height = 34, 4

    return flask.render_template("edit_item.html.jinja",
                                 file_name=file_name,
                                 folder_key=folder_key,
                                 key_str=key_str,
                                 window_width=window_width,
                                 window_height=window_height,
                                 condition_list=condition_list,
                                 prev_key=prev_key_str,
                                 next_key=next_key_str,
                                 original=current_item_info.original,
                                 translation=current_item_info.translated)


@app.route("/search")
@auth.login_required
def search():

    if 'search_term' in flask.request.args:
        search_term = markupsafe.escape(flask.request.args.get('search_term'))
        results = []

        for path, dirs, files in os.walk("yaml"):
            folder_key = path[5:] if len(path) > 5 else None
            for file in files:
                file_name = file[:-9] if file.endswith("BZH.yaml") else file[:-5]

                trans = TranslationCollection.load(os.path.join(path, file))

                for key in trans.keys:
                    item = trans[key]

                    if item.original is not None:
                        original_index = item.original.find(search_term)
                        if original_index >= 0:
                            excerpt_start_index = max(original_index - 20, 0)
                            excerpt_end_index = min(original_index + len(search_term) + 20, len(item.original))
                            results.append({'folder_key': folder_key,
                                            'file_name': file_name,
                                            'key_str': f"{key:04x}",
                                            'excerpt': markupsafe.escape(item.original[excerpt_start_index:excerpt_end_index]),
                                            'translated': False})

                    if item.translated is not None:
                        translated_index = item.translated.find(search_term)
                        if translated_index >= 0:
                            excerpt_start_index = max(translated_index - 20, 0)
                            excerpt_end_index = min(translated_index + len(search_term) + 20, len(item.translated))
                            results.append({'folder_key': folder_key,
                                            'file_name': file_name,
                                            'key_str': f"{key:04x}",
                                            'excerpt': markupsafe.escape(item.translated[excerpt_start_index:excerpt_end_index]),
                                            'translated': True})

        return flask.render_template("search.html.jinja", search_term=search_term, results=results)
    else:
        return flask.render_template("search.html.jinja")


@app.route("/api/render_item_text", methods=['POST'])
def render_item_text():
    folder_key = flask.request.form['folder_key'] if 'folder_key' in flask.request.form else None
    file_name = flask.request.form['file_name']
    key_str = flask.request.form['key']

    translated = True
    if 'which_text' in flask.request.form and flask.request.form['which_text'] == "original":
        translated = False

    active_conditions = json.loads(flask.request.form['active_conditions'])

    path = None
    if folder_key is None:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    key = int(key_str, base=16)

    trans = TranslationCollection.load(path)

    if file_name == "Opening":
        pages = render_opening_text_html(trans[key].translated if translated else trans[key].original)
        conditions_checked = []
    elif file_name == "Ending":
        pages = render_ending_text_html(trans[key].translated if translated else trans[key].original, key == 0x2b76)
        conditions_checked = []
    else:
        pages, conditions_checked = render_text_html(trans, key, translated=translated, active_conditions=active_conditions)

    return { 'pages': pages, 'conditions_checked': conditions_checked }

@app.route("/api/update_item_text", methods=['POST'])
def update_item_text():
    folder_key = flask.request.form['folder_key'] if 'folder_key' in flask.request.form else None
    file_name = flask.request.form['file_name']
    key_str = flask.request.form['key']

    new_text = flask.request.form['new_text']
    new_text = new_text.replace("\r\n", "\n")

    key = int(key_str, base=16)

    trans = load_trans(folder_key, file_name)
    trans[key].translated = new_text
    save_trans(folder_key, file_name, trans)

    return { }
