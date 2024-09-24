import configparser
import gspread
import gspread_formatting
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

    worksheet_list = []

    progress = tqdm.tqdm(yaml_paths)
    for path in progress:
        trans = TranslationCollection.load(path)

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

        worksheet_list.append((worksheet_name, worksheet.id))

        worksheet_data = worksheet.get_all_values()

        for key in trans.keys:
            key_str = f"{key:04x}"
            row_index = None

            for i, row in enumerate(worksheet_data):
                if len(row) > 0 and row[0] == key_str:
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

            worksheet_data[row_index][1] = trans[key].original
            worksheet_data[row_index][2] = trans[key].translated

        worksheet.update(worksheet_data)

        # Throttle to avoid triggering gsheets rate limits
        time.sleep(4)

    try:
        index_worksheet = sheet.worksheet("Index")
    except gspread.WorksheetNotFound:
        index_worksheet = sheet.add_worksheet("Index", 0, 5, index=0)
        gspread_formatting.format_cell_range(index_worksheet, 'E:E', gspread_formatting.CellFormat(numberFormat=gspread_formatting.NumberFormat(type='PERCENT', pattern="0.0%")))

    index_data = index_worksheet.get_all_values()
    index_data = []


    for row_index, (worksheet_name, worksheet_id) in enumerate(worksheet_list):

        link_text = f"=HYPERLINK(\"https://docs.google.com/spreadsheets/d/{config['SpreadsheetKey']}/edit#gid={worksheet_id}\", \"{worksheet_name}\")"

        index_data.append([link_text,'',f"=SUMPRODUCT(--(len('{worksheet_name}'!B:B)>0))", f"=SUMPRODUCT(--(len('{worksheet_name}'!C:C)>0))", f"=D{row_index+1}/C{row_index+1}"])

    index_worksheet.update(index_data, value_input_option="USER_ENTERED")
