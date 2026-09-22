#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>

/* Sentinel for unset optional numeric fields (json_out omits them). */
#define UNSET_INT (-999999)

typedef struct {
    char timestamp[64];
    char hostname[64];
    char facility[16];
    char severity[16];
    char device_type[32];
    char event[64];
    char src_ip[46];
    char dst_ip[46];
    char proto[8];
    int  dst_port;

    int  src_port;          /* SPT= / spt= */
    char action[16];        /* allow|drop|deny|reject|close|accept */
    char tcp_flags[16];     /* SYN|ACK|FIN|RST|URG */
    char mac[24];           /* switch: flapping/learned MAC */
    int  vlan_id;           /* switch: vlan N */
    char ifname[40];        /* interface (Gi1/0/3, GigabitEthernet0/0, eth0, wlan0) */
    char peer_ifname[40];   /* switch: second port in "between port A and port B" */
    char stp_root[40];      /* switch: STP "new root Gi0/5" */
    char client_mac[24];    /* ap: station MAC */
    char ssid[32];          /* ap: SSID */
    char radio[16];         /* ap: wlan0/wlan1 */
    int  reason;            /* ap: reason=N */
    int  signal_dbm;        /* ap: signal=N dBm */
    int  tx_rate_mbps;      /* ap: tx_rate=NMbps */
    char eap_status[16];    /* ap: success|failed */
    char ospf_nbr[46];      /* router: OSPF neighbor IP */
    char gateway[46];       /* router: gateway= */
    char route_dst[46];     /* router: dst-address= */
    char dhcp_mac[24];      /* router: DHCPACK client MAC */
    int  conntrack_count;   /* router/firewall: connection tracking entries */

    char *raw_line; /* heap-allocated full line, never truncated (1MB cap in collector) */
} log_entry_t;

#include "syslog.h"
#include "devices.h"

// Parse a raw syslog line into a log_entry_t.
log_entry_t* parse_syslog_line(const char* line);

// Free a log_entry_t.
void free_entry(log_entry_t* entry);

#endif
