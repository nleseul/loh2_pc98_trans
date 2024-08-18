import configparser
import gspread
import gspread_formatting
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
            worksheet = sheet.add_worksheet(worksheet_name, 0, 3)
            gspread_formatting.set_column_widths(worksheet, [ ('A', 50), ('B:C', 280) ] )
            gspread_formatting.format_cell_range(worksheet, 'A:C', gspread_formatting.CellFormat(textFormat=gspread_formatting.TextFormat(fontFamily="Roboto Mono")))

        worksheet_data = worksheet.get_all_values()

        for addr, data in csv_data.items():
            key = f"{addr:04x}"
            row_index = None

            for i, row in enumerate(worksheet_data):
                if len(row) > 0 and row[0] == key:
                    row_index = i
                    break

            if row_index is None:
                for i, row in enumerate(worksheet_data):
                    if len(row) == 0:
                        row += [key,'','']
                        row_index = i
                        break
                    elif row[0] == '' and row.count('') == len(row):
                        row[0] = key
                        row_index = i
                        break

            if row_index is None:
                row_index = len(worksheet_data)
                worksheet_data.append([key,'',''])

            while len(worksheet_data[row_index]) < 3:
                worksheet_data[row_index].append('')

            worksheet_data[row_index][1] = data.original
            worksheet_data[row_index][2] = data.translated

        worksheet.update(worksheet_data)



        # Throttle to avoid triggering gsheets rate limits
        time.sleep(4)
