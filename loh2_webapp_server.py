import flask
import flask_restful
import markupsafe
import os

from csv_util import *

app = flask.Flask(__name__)
api = flask_restful.Api(app)


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