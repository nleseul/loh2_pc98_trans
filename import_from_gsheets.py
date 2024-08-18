import configparser
import gspread
import os
import time
import tqdm

from csv_util import *

if __name__ == '__main__':
    csv_paths = []
    for path, dirs, files in os.walk("csv"):
        for file in files:
            csv_paths.append(os.path.join(path, file))
    csv_paths = sorted(csv_paths)

    configfile = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    configfile.read("loh2_patch.conf")

    config = configfile["GSheets"]

    account = gspread.service_account(filename=config["CredentialsFile"])
    sheet = account.open_by_key(config["SpreadsheetKey"])

    progress = tqdm.tqdm(csv_paths)
    for path in progress:
        csv_data = load_csv(path)

        worksheet_name = path[4:-4]
        if worksheet_name.endswith(".BZH"):
            worksheet_name = worksheet_name[:-4]

        progress.set_description(worksheet_name)
        progress.update()

        try:
            worksheet = sheet.worksheet(worksheet_name)
        except gspread.WorksheetNotFound:
            continue

        worksheet_data = worksheet.get_all_values()

        for addr, data in csv_data.items():
            key = f"{addr:04x}"

            for i, row in enumerate(worksheet_data):
                if len(row) > 2 and row[0] == key and len(row[2]) > 0:
                    data.translated = row[2]

        save_csv(path, csv_data)

        # Throttle to avoid triggering gsheets rate limits
        time.sleep(3)
