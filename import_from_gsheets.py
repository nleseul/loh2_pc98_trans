import argparse
import configparser
import gspread
import os
import time
import tqdm

from trans_util import *

def main():
    parser = argparse.ArgumentParser("import_from_gsheets", description="Import a translation from Google Sheets")
    parser.add_argument("--file", type=str)
    args = parser.parse_args()

    if args.file is None:
        yaml_paths = []
        for path, dirs, files in os.walk("yaml"):
            for file in files:
                yaml_paths.append(os.path.join(path, file))
        yaml_paths = sorted(yaml_paths)
    else:
        yaml_paths = [args.file]

    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")

    config = configfile["GSheets"]

    account = gspread.service_account(filename=config["CredentialsFile"])
    sheet = account.open_by_key(config["SpreadsheetKey"])

    notes = {}
    try:
        index_worksheet = sheet.worksheet("Index")
        index_data = index_worksheet.get_all_values()

        for row in index_data:
            if len(row) > 1:
                notes[row[0]] = row[1]
    except gspread.WorksheetNotFound:
        pass

    progress = tqdm.tqdm(yaml_paths)
    for path in progress:
        trans = TranslationCollection.load(path)

        worksheet_name = path[5:-5]
        if worksheet_name.endswith(".BZH"):
            worksheet_name = worksheet_name[:-4]

        progress.set_description(worksheet_name)
        progress.update()

        if worksheet_name in notes:
            trans.note = notes[worksheet_name]

        try:
            worksheet = sheet.worksheet(worksheet_name)
        except gspread.WorksheetNotFound:
            continue

        worksheet_data = worksheet.get_all_values()

        for key in trans.keys:
            key_str = f"{key:04x}"
            for i, row in enumerate(worksheet_data):
                if len(row) > 0 and row[0] == key_str:
                    if len(row) > 2 and len(row[2]) > 0:
                        trans[key].translated = row[2]
                    break

        trans.save(path)

        # Throttle to avoid triggering gsheets rate limits
        time.sleep(3)

if __name__ == '__main__':
    main()