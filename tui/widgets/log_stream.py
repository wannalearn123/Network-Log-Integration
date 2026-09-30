# Live scrolling log stream DataTable.

from textual.widgets import DataTable


    # Live log stream table showing recent parsed logs.
class LogStream(DataTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rows: list[dict] = []

    def on_mount(self):
        self.add_columns(
            "Time", "Device", "Type", "Event",
            "Src IP", "Entity", "Proto", "Port",
        )
        self.cursor_type = "row"

        # Replace all rows with new data from query results.
    def populate(self, rows: list):
        self.clear()
        self._rows.clear()
        for i, row in enumerate(rows):
            ts = row[0].strftime("%H:%M:%S") if row[0] else ""
            hostname = row[1] or ""
            device = row[2] or ""
            event = row[3] or ""
            src_ip = str(row[4]) if row[4] else ""
            entity = str(row[8]) if len(row) > 8 and row[8] else src_ip
            proto = row[6] or ""
            port = str(row[7]) if row[7] else ""
            self.add_row(ts, hostname, device, event, src_ip, entity, proto, port,
                         key=f"log-{i}")
            detail = {
                "time": row[0].strftime("%Y-%m-%d %H:%M:%S") if row[0] else "",
                "device": hostname,
                "type": device,
                "event": event,
                "src_ip": src_ip,
                "dst_ip": str(row[5]) if row[5] else "",
                "proto": proto,
                "port": port,
                "entity": entity,
            }
            # v2 detail fields (indices 9..27 of SQL_LOGS); stored for the modal.
            v2_keys = (
                "src_port", "action", "mac", "vlan_id",
                "ifname", "peer_ifname", "stp_root", "client_mac", "ssid",
                "radio", "reason", "signal_dbm", "tx_rate_mbps",
                "eap_status", "ospf_nbr", "gateway", "route_dst",
                "dhcp_mac", "conntrack_count",
            )
            for j, key in enumerate(v2_keys):
                idx = 9 + j
                if idx < len(row) and row[idx] is not None:
                    detail[key] = str(row[idx])
            self._rows.append(detail)
