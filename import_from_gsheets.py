import configparser
import gspread
import os
import time
import tqdm

from trans_util import *

if __name__ == '__main__':
    yaml_paths = []
    for path, dirs, files in os.walk("yaml"):
        for file in files:
            yaml_paths.append(os.path.join(path, file))
    yaml_paths = sorted(yaml_paths)

    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")

    config = configfile["GSheets"]

    account = gspread.service_account(filename=config["CredentialsFile"])
    sheet = account.open_by_key(config["SpreadsheetKey"])

    progress = tqdm.tqdm(yaml_paths)
    for path in progress:
        trans = TranslationCollection.load(path)

        worksheet_name = path[5:-5]
        if worksheet_name.endswith(".BZH"):
            worksheet_name = worksheet_name[:-4]

        progress.set_description(worksheet_name)
        progress.update()

        try:
            worksheet = sheet.worksheet(worksheet_name)
        except gspread.WorksheetNotFound:
            continue

        worksheet_data = worksheet.get_all_values()

        for key in trans.keys:
            key_str = f"{key:04x}"

            for i, row in enumerate(worksheet_data):
                if len(row) > 2 and row[0] == key_str and len(row[2]) > 0:
                    trans[key].translated = row[2]

        trans.save(path)

        # Throttle to avoid triggering gsheets rate limits
        time.sleep(3)
