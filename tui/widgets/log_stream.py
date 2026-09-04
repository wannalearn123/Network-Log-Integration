# Live scrolling log stream DataTable.

from textual.widgets import DataTable


    # Live log stream table showing recent parsed logs.
class LogStream(DataTable):

    def on_mount(self):
        self.add_columns(
            "Time", "Device", "Type", "Event",
            "Src IP", "Dst IP", "Proto", "Port",
        )
        self.cursor_type = "row"

        # Replace all rows with new data from query results.
    def populate(self, rows: list):
        self.clear()
        for row in rows:
            ts = row[0].strftime("%H:%M:%S") if row[0] else ""
            hostname = row[1] or ""
            device = row[2] or ""
            event = row[3] or ""
            src_ip = str(row[4]) if row[4] else ""
            dst_ip = str(row[5]) if row[5] else ""
            proto = row[6] or ""
            port = str(row[7]) if row[7] else ""
            self.add_row(ts, hostname, device, event, src_ip, dst_ip, proto, port)
