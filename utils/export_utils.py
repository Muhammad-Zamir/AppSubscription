import io

import xlwt
from django.http import FileResponse


class ExportUtility:

    def export_user_data(self, serialized_asset, columns, export_name):
        try:
            buffer = io.BytesIO()
            wb = xlwt.Workbook(encoding="utf-8")
            ws = wb.add_sheet(export_name)
            # Sheet header, first row
            font_style = xlwt.XFStyle()
            font_style.font.bold = True
            row_num = 0
            for col_num in range(len(columns)):
                row_num += 1
                ws.write(0, col_num, columns[col_num], font_style)
                # Sheet body, remaining rows
            count = 0
            font_style = xlwt.XFStyle()
            y = 1
            for row in serialized_asset.data:
                ws.write(
                    count + y,
                    0,
                    str(
                        row["first_name"]
                        if not None
                        else "" + " " + row["last_name"]
                        if not None
                        else ""
                    ),
                    font_style,
                )
                ws.write(count + y, 1, str(row["username"]), font_style)
                ws.write(count + y, 2, str(row["email"]), font_style)
                ws.write(count + y, 3, str(row["created_at"]), font_style)
                ws.write(count + y, 4, str(row["is_active"]), font_style)

                y = y + 1
            count += 1
            wb.save(buffer)
            buffer.seek(0)
            return FileResponse(
                buffer, as_attachment=True, filename=export_name + ".xls"
            )
        except Exception as e:
            print("USER EXCEL EXPORT EXCEPTION", e)

    def export_role_data(self, serialized_asset, columns, export_name):
        try:
            buffer = io.BytesIO()
            wb = xlwt.Workbook(encoding="utf-8")
            ws = wb.add_sheet(export_name)
            # Sheet header, first row
            font_style = xlwt.XFStyle()
            font_style.font.bold = True
            row_num = 0
            for col_num in range(len(columns)):
                row_num += 1
                ws.write(0, col_num, columns[col_num], font_style)
                # Sheet body, remaining rows
            count = 0
            font_style = xlwt.XFStyle()
            y = 1
            for row in serialized_asset.data:
                permitted_features = [r["feature"]["name"] for r in row["features_list"]]
                ws.write(count + y, 0, str(row["name"]), font_style)
                ws.write(count + y, 1, str(permitted_features), font_style)
                ws.write(count + y, 2, str((row["is_active"])), font_style)
                y = y + 1
            count += 1
            wb.save(buffer)
            buffer.seek(0)
            return FileResponse(
                buffer, as_attachment=True, filename=export_name + ".xls"
            )
        except Exception as e:
            print("ROLE EXCEL EXPORT EXCEPTION", e)

    def export_notification_data(self, serialized_asset, columns, export_name):
        try:
            buffer = io.BytesIO()
            wb = xlwt.Workbook(encoding="utf-8")
            ws = wb.add_sheet(export_name)
            # Sheet header, first row
            font_style = xlwt.XFStyle()
            font_style.font.bold = True
            row_num = 0
            for col_num in range(len(columns)):
                row_num += 1
                ws.write(0, col_num, columns[col_num], font_style)
                # Sheet body, remaining rows
            count = 0
            font_style = xlwt.XFStyle()
            y = 1
            for row in serialized_asset.data:
                ws.write(count + y, 0, str(row["name"]), font_style)
                ws.write(count + y, 1, str(row["subject"]), font_style)
                ws.write(count + y, 2, str(row["body"]), font_style)
                ws.write(count + y, 3, str(row["is_published"]), font_style)
                ws.write(count + y, 4, str(row["recipient_list"]), font_style)
                ws.write(count + y, 5, str(row["recipient_roles"]), font_style)
                ws.write(count + y, 6, str(row["recipient_group"]), font_style)

                # ws.write(count + y, 2, str(row["country"]['name']), font_style)
                y = y + 1
            count += 1
            wb.save(buffer)
            buffer.seek(0)
            return FileResponse(
                buffer, as_attachment=True, filename=export_name + ".xls"
            )
        except Exception as e:
            print("NOTIFICATION EXCEL EXPORT EXCEPTION", e)
