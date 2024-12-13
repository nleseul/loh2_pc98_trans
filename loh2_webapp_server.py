import flask
import flask_httpauth
import json
import markupsafe
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


def render_text_html(trans:TranslationCollection, entry_point_key:int, max_pages:int|None = None, translated:bool = True, active_conditions:list[int] = []) -> tuple[list[str], list[int]]:
    class TextRenderer:
        def __init__(self, width:int, lines_per_page:int = 4):
            self._width = width
            self._lines_per_page = 4

            self._pages = []
            self._current_page_text = ""

            #self._text = "<p>"
            self._page_line_count = 0
            self._line_char_count = 0
            self._has_active_style = False

        #@property
        #def text(self) -> str:
        #    return self._text + ("</span>" if self._has_active_style else "") + "</p>"
        @property
        def pages(self) -> typing.Generator[str, None, None]:
            yield from self._pages

            if len(self._current_page_text):
                if self._has_active_style:
                    yield self._current_page_text + "</span>"
                else:
                    yield self._current_page_text


        #@property
        #def line_count(self) -> int:
        #    return self._line_count

        @property
        def page_count(self) -> int:
            return len(self._pages) + (1 if len(self._current_page_text) > 0 else 0)

        def add_text(self, text:str) -> None:
            for ch in text:
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

        def add_page_break(self) -> None:
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


    #current_data = trans[entry_point_key]
    #encoded_event, _, locators = encode_event_string(current_data.original)
    #print(entry_point_key, locators)
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
            elif code == 0x04:
                renderer.cancel_text_style()
            elif code == 0x05:
                renderer.add_page_break()
            elif code == 0x06 or code == 0x07:
                if len(call_stack) > 0:
                    disassembled_events, instruction_index = call_stack.pop()

                    if code == 0x07:
                        renderer.add_newline()
                else:
                    break
            elif code == 0x09:
                character_index = int.from_bytes(instruction.data, byteorder='little')
                character_name = ["At?las", "Landor", "Flora", "Cindy"][character_index]
                renderer.change_text_style("text_yellow")
                renderer.add_text(character_name)
                renderer.cancel_text_style()

            elif code == 0x0f:
                if condition_was_true is None or condition_was_true:
                    jump_target = int.from_bytes(instruction.data, byteorder='little')
                    if jump_target not in locator_to_key_and_offset:
                        raise Exception(f"Unknown jump target address {jump_target:04x}!")
                    print(f"Jump to {jump_target:04x}")

                    jump_target_key, jump_target_offset = locator_to_key_and_offset[jump_target]
                    print(f"key={jump_target_key:04x}, offset={jump_target_offset}")
                    disassembled_events = disassemble_event(encoded_events[jump_target_key], jump_target_key, jump_target_key+jump_target_offset)
                    instruction_index = 0
                else:
                    print("Skipping jump due to false condition")
                condition_was_true = None
            elif code == 0x10:
                call_target = int.from_bytes(instruction.data, byteorder='little')
                if call_target not in locator_to_key_and_offset:
                    raise Exception(f"Unknown call target address {call_target:04x}!")
                print(f"Call to {call_target:04x}")

                call_stack.append((disassembled_events, instruction_index))

                call_target_key, call_target_offset = locator_to_key_and_offset[call_target]
                print(f"key={call_target_key:04x}, offset={call_target_offset}")
                disassembled_events = disassemble_event(encoded_events[call_target_key], call_target_key, call_target_key+call_target_offset)
                instruction_index = 0
            elif code == 0x12:
                condition = int.from_bytes(instruction.data, byteorder='little')
                condition_was_true = condition in active_conditions
                conditions_checked.add(condition)
                print(f"Checking condition {condition:04x}... was {condition_was_true}")
            elif code == 0x1c:
                renderer.change_text_style("text_green")
            elif code == 0x1e:
                renderer.change_text_style("text_yellow")
            else:
                renderer.change_text_style("unknown_tag")
                renderer.add_debug_text(f"{instruction.code:02x}{':' if len(instruction.data) > 0 else ''}{instruction.data.hex()} ")
                renderer.cancel_text_style()
        else:
            raise Exception("Unknown instruction type - " + instruction)

        if max_pages is not None and renderer.page_count >= max_pages:
            break

    return list(renderer.pages), list(conditions_checked)



@app.route("/")
@auth.login_required
def index():
    scenario_filenames = sorted([file[:-9] for file in os.listdir("yaml/Scenarios")])
    combat_filenames = sorted([file[:-9] for file in os.listdir("yaml/Combats")])
    root_filenames = sorted([file[:-5] for file in os.listdir("yaml") if file.endswith(".yaml")])

    files = [
        {'display': "Scenarios", 'folder_key': "Scenarios", 'folder_items': [{'display': name} for name in scenario_filenames]},
        {'display': "Combats", 'folder_key': "Combats", 'folder_items': [{'display': name} for name in combat_filenames]}
    ] + [{'display': name} for name in root_filenames]

    return flask.render_template("index.html.jinja", files=files)


@app.route("/items/<file_name>")
@app.route("/items/<folder_key>/<file_name>")
@auth.login_required
def items(file_name, folder_key=None):
    path = None
    if folder_key is None:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    trans = TranslationCollection.load(path)

    items = []
    for key in trans.keys:

        original_pages = render_text_html(trans, key, 3, translated=False)
        translated_pages = render_text_html(trans, key, 3, translated=True)

        items.append({
            'key': f"{key:04x}",
            'original': original_pages[0] if len(original_pages) > 0 else None,
            'translated': translated_pages[0] if len(translated_pages) > 0 else None
        })

    return flask.render_template("items.html.jinja", items=items, file_name=file_name, folder_key=folder_key)


@app.route("/edit_item/<file_name>/<key_str>")
@app.route("/edit_item/<folder_key>/<file_name>/<key_str>")
@auth.login_required
def edit_item(file_name, key_str, folder_key=None):

    path = None
    if folder_key is None:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    key = int(key_str, base=16)

    trans = TranslationCollection.load(path)
    key_list = sorted(list(trans.keys))

    key_index = key_list.index(key)

    prev_key = None if key_index == 0 else key_list[key_index - 1]
    next_key = None if key_index == len(key_list) - 1 else key_list[key_index + 1]

    prev_key_str = None if prev_key is None else f"{prev_key:04x}"
    next_key_str = None if next_key is None else f"{next_key:04x}"

    conditions = set()
    for k in key_list:
        item = trans[k]
        encoded, _, _ = encode_event_string(item.original)
        for instruction in disassemble_event(encoded, k, k):
            if isinstance(instruction, DS6CodeInstruction):
                if instruction.code == 0x11 or instruction.code == 0x12:
                    condition = int.from_bytes(instruction.data, byteorder='little')
                    conditions.add(f"{condition:04x}")
    condition_list = sorted(conditions)

    current_item_info = trans[key]

    return flask.render_template("edit_item.html.jinja",
                                 file_name=file_name,
                                 folder_key=folder_key,
                                 key_str=key_str,
                                 condition_list=condition_list,
                                 prev_key=prev_key_str,
                                 next_key=next_key_str,
                                 original=current_item_info.original,
                                 translation=current_item_info.translated)

@app.route("/api/render_item_text", methods=['POST'])
def render_item_text():
    folder_key = flask.request.form['folder_key']
    file_name = flask.request.form['file_name']
    key_str = flask.request.form['key']

    translated = True
    if 'which_text' in flask.request.form and flask.request.form['which_text'] == "original":
        translated = False

    active_conditions = [int(s, base=16) for s in json.loads(flask.request.form['active_conditions'])]
    print(active_conditions)

    path = None
    if folder_key is None:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    key = int(key_str, base=16)

    trans = TranslationCollection.load(path)

    pages, conditions_checked = render_text_html(trans, key, translated=translated, active_conditions=active_conditions)

    return { 'pages': pages, 'conditions_checked': conditions_checked }

@app.route("/api/update_item_text", methods=['POST'])
def update_item_text():
    folder_key = flask.request.form['folder_key']
    file_name = flask.request.form['file_name']
    key_str = flask.request.form['key']

    new_text = flask.request.form['new_text']

    new_text = new_text.replace("\r\n", "\n")

    path = None
    if folder_key is None:
        path = f"yaml/{file_name}.yaml"
    else:
        path = f"yaml/{folder_key}/{file_name}.BZH.yaml"

    key = int(key_str, base=16)

    trans = TranslationCollection.load(path)

    trans[key].translated = new_text
    trans.save(path)

    return { }

'''
class Files(flask_restful.Resource):
    def get(self):
        scenario_filenames = sorted([file[:-8] for file in os.listdir("csv/Scenarios")])
        combat_filenames = sorted([file[:-8] for file in os.listdir("csv/Combats")])
        root_filenames = sorted([file[:-4] for file in os.listdir("csv") if file.endswith(".csv")])

        return [
            {'display': "Scenarios", 'folder_key': "scenarios", 'folder_items': [{'display': name} for name in scenario_filenames]},
            {'display': "Combats", 'folder_key': "combats", 'folder_items': [{'display': name} for name in combat_filenames]}
        ] + [{'display': name for name in root_filenames}]


class Translations(flask_restful.Resource):
    def get(self, folder_key, file_name):
        path = None
        if folder_key == "_":
            path = f"csv/{file_name}.csv"
        elif folder_key == "scenarios":
            path = f"csv/Scenarios/{file_name}.BZH.csv"
        elif folder_key == "combats":
            path = f"csv/Combats/{file_name}.BZH.csv"

        if path is None:
            flask_restful.abort(404, message="Folder not found")

        csv_data = load_csv(path)
        if len(csv_data) == 0:
            flask_restful.abort(404, message="File not found")

        items = []
        for key, data in csv_data.items():
            items.append({'key': f"{key:04x}", 'original': data.original, 'translated': data.translated})

        return items


api.add_resource(Files, "/")
api.add_resource(Translations, "/<string:folder_key>/<string:file_name>")


if __name__ == '__main__':
    app.run(debug=True)
'''