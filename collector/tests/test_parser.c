#include "../src/parser.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

void test_parse_iso_syslog(void) {
    TEST("Parse ISO timestamp syslog");
    const char* line = "2026-08-31T04:44:43+00:00 ap.docker_building-lan hostapd: wlan0: AP-STA-CONNECTED aa:bb:cc:7c:ee:e6 172.20.100.4 printer-04";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->hostname, "ap.docker_building-lan") != 0)
        { FAIL("hostname mismatch"); free_entry(entry); return; }
    if (strcmp(entry->device_type, "ap") != 0)
        { FAIL("device_type should be ap"); free_entry(entry); return; }
    if (strcmp(entry->event, "client_connect") != 0)
        { FAIL("event should be client_connect"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_firewall_log(void) {
    TEST("Parse firewall log with IP fields");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan fwdaemon: [FW DROP] UDP 172.20.100.1 -> 172.20.0.4:80";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->device_type, "firewall") != 0)
        { FAIL("device_type should be firewall"); free_entry(entry); return; }
    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_switch_log(void) {
    TEST("Parse switch MAC learning event");
    const char* line = "2026-08-31T08:16:05+00:00 switch.docker_building-lan switchd: [MAC LEARN] learned 02:00:00:9e:8f:7b on br0 port 1";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->device_type, "switch") != 0)
        { FAIL("device_type should be switch"); free_entry(entry); return; }
    if (strcmp(entry->event, "mac_learn") != 0)
        { FAIL("event should be mac_learn"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_router_dhcp(void) {
    TEST("Parse router DHCP ack");
    const char* line = "2026-08-31T08:16:17+00:00 router.docker_building-lan dhcpd: DHCPACK on 172.20.100.1 to aa:bb:cc:0a:b4:1d";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->device_type, "router") != 0)
        { FAIL("device_type should be router"); free_entry(entry); return; }
    if (strcmp(entry->event, "dhcp_ack") != 0)
        { FAIL("event should be dhcp_ack"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.100.1") != 0)
        { FAIL("dst_ip should be 172.20.100.1"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_scan_detected(void) {
    TEST("Parse firewall scan detection");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan fwdaemon: [SCAN DETECTED] Port scan from 172.20.0.50 - 12 ports in 5s";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->event, "scan_detected") != 0)
        { FAIL("event should be scan_detected"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_empty_line(void) {
    TEST("Empty line returns NULL");
    log_entry_t* entry = parse_syslog_line("");
    if (entry != NULL) { FAIL("should be NULL"); free_entry(entry); return; }

    entry = parse_syslog_line(NULL);
    if (entry != NULL) { FAIL("NULL input should return NULL"); free_entry(entry); return; }

    PASS();
}

void test_to_json(void) {
    TEST("to_json produces valid JSON");
    const char* line = "2026-08-31T04:44:43+00:00 ap.docker_building-lan hostapd: wlan0: AP-STA-CONNECTED aa:bb:cc 172.20.100.4 printer-04";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("parse returned NULL"); return; }

    char* json = to_json(entry);
    if (!json) { FAIL("to_json returned NULL"); free_entry(entry); return; }

    if (json[0] != '{') { FAIL("JSON should start with {"); free(json); free_entry(entry); return; }

    int len = strlen(json);
    if (json[len-1] != '\n' || json[len-2] != '}') {
        if (json[len-1] != '}') { FAIL("JSON should end with }"); free(json); free_entry(entry); return; }
    }

    if (!strstr(json, "ap.docker_building-lan")) {
        FAIL("JSON should contain hostname");
        free(json);
        free_entry(entry);
        return;
    }

    free(json);
    free_entry(entry);
    PASS();
}

// Hostile hostname must be escaped so output stays valid JSON.
void test_to_json_escaping(void) {
    TEST("to_json escapes hostname");
    log_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.timestamp, sizeof(entry.timestamp), "2026-08-31T04:44:43+00:00");
    snprintf(entry.hostname, sizeof(entry.hostname), "ho\"st\\test");
    snprintf(entry.facility, sizeof(entry.facility), "user");
    snprintf(entry.severity, sizeof(entry.severity), "info");
    snprintf(entry.device_type, sizeof(entry.device_type), "other");
    snprintf(entry.event, sizeof(entry.event), "unknown");
    entry.dst_port = -1;
    entry.raw_line = "raw";

    char* json = to_json(&entry);
    if (!json) { FAIL("to_json returned NULL"); return; }
    if (!strstr(json, "ho\\\"st\\\\test")) {
        FAIL("hostname not escaped");
        free(json);
        return;
    }
    if (strstr(json, "\"hostname\":\"ho\"")) {
        FAIL("raw quote leaked into JSON");
        free(json);
        return;
    }
    free(json);
    PASS();
}

void test_malformed_line(void) {
    TEST("Malformed syslog line parses without crash");
    const char* line = "this is not syslog at all";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (entry->facility[0] == '\0') { FAIL("facility should have default"); free_entry(entry); return; }
    if (entry->severity[0] == '\0') { FAIL("severity should have default"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_iptables_kernel(void) {
    TEST("Parse real iptables kernel log");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan kernel: [FW DENY INPUT] IN=eth0 OUT= SRC=172.20.0.50 DST=172.20.0.4 PROTO=TCP SPT=4444 DPT=22";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "172.20.0.50") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.0.4") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->proto, "TCP") != 0)
        { FAIL("proto should be TCP"); free_entry(entry); return; }
    if (entry->dst_port != 22)
        { FAIL("dst_port should be 22"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_arrow_form(void) {
    TEST("Parse arrow firewall form with fields");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan fwdaemon: [FW ALLOW] TCP 172.20.100.5 -> 172.20.0.4:53";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->event, "fw_allow") != 0)
        { FAIL("event should be fw_allow"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "172.20.100.5") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.0.4") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (entry->dst_port != 53)
        { FAIL("dst_port should be 53"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_cisco_flap(void) {
    TEST("Parse Cisco MAC flap format");
    const char* line = "2026-08-31T08:16:26+00:00 switch.docker_building-lan %SW_MATM-4-MACFLAP_NOTIF: Host 0200.000a.02b2 in vlan 10 is flapping between port Gi1/0/1 and port Gi1/0/2";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->event, "mac_flap") != 0)
        { FAIL("event should be mac_flap"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_hostapd_real(void) {
    TEST("Parse real hostapd associated line");
    const char* line = "2026-08-31T08:16:26+00:00 ap.docker_building-lan hostapd: wlan0: STA aa:bb:cc:11:22:33 IEEE 802.11: associated";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->event, "client_connect") != 0)
        { FAIL("event should be client_connect"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_parse_unknown_host(void) {
    TEST("Unknown hostname still extracts firewall fields");
    const char* line = "2026-08-31T08:16:26+00:00 ids-01.example kernel: SRC=10.0.0.5 DST=10.0.0.4 PROTO=TCP DPT=443 DROP packet";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    if (strcmp(entry->device_type, "other") != 0)
        { FAIL("device_type should be other"); free_entry(entry); return; }
    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "10.0.0.5") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (entry->dst_port != 443)
        { FAIL("dst_port should be 443"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

void test_brand_cisco_router(void) {
    TEST("Brand Cisco router lineproto");
    const char* line = "2026-08-31T08:16:26+00:00 router.docker_building-lan ios: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "interface_status") != 0)
        { FAIL("event should be interface_status"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_mikrotik_dhcp(void) {
    TEST("Brand MikroTik dhcp assigned");
    const char* line = "2026-08-31T08:16:26+00:00 router.docker_building-lan dhcp: dhcp,info dhcp1 assigned 172.20.100.7 to AA:BB:CC:11:22:33";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "dhcp_ack") != 0)
        { FAIL("event should be dhcp_ack"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.100.7") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_cisco_learn(void) {
    TEST("Brand Cisco switch learn");
    const char* line = "2026-08-31T08:16:26+00:00 switch.docker_building-lan ios: %MATM-5-LEARN: Host 0200.000a.02b2 learned on Gi1/0/1 vlan 10";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "mac_learn") != 0)
        { FAIL("event should be mac_learn"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_ruijie_flap(void) {
    TEST("Brand Ruijie switch flap");
    const char* line = "2026-08-31T08:16:26+00:00 switch.docker_building-lan rgos: %MACFLAP-4-FLAP_DETECTED: Mac 0200.000a.02b2 flap between Gi0/1 and Gi0/2 in VLAN 10";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "mac_flap") != 0)
        { FAIL("event should be mac_flap"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_ruijie_ap(void) {
    TEST("Brand Ruijie AP assoc");
    const char* line = "2026-08-31T08:16:26+00:00 ap.docker_building-lan DOT11: DOT11-6-ASSOC: Station 0200.000a.02b2 associated to WLAN wlan1 (SSID Campus)";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "client_connect") != 0)
        { FAIL("event should be client_connect"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_ruijie_auth(void) {
    TEST("Brand Ruijie AP auth success");
    const char* line = "2026-08-31T08:16:26+00:00 ap.docker_building-lan DOT11: STA 0200.000a.02b2 authentication success";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "client_connect") != 0)
        { FAIL("event should be client_connect"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_fortigate(void) {
    TEST("Brand FortiGate deny (simplified)");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan fortigate: date=2026-09-08 devname=FG100F action=deny srcip=172.20.0.50 dstip=172.20.0.4 proto=6 dstport=22 policyid=1";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "172.20.0.50") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.0.4") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->proto, "TCP") != 0)
        { FAIL("proto should be TCP"); free_entry(entry); return; }
    if (entry->dst_port != 22)
        { FAIL("dst_port should be 22"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_fortigate_cef_close(void) {
    TEST("FortiGate CEF act=close");
    const char* line = "2026-09-08T11:07:55+00:00 FGT-A-LOG fortigate: CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward close|3|deviceExternalId=FGT100F0000000001 FTNTFGTlogid=0001000013 cat=traffic:forward src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 proto=6 act=close";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "fw_allow") != 0)
        { FAIL("event should be fw_allow"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "10.1.100.11") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "52.53.140.235") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->proto, "TCP") != 0)
        { FAIL("proto should be TCP"); free_entry(entry); return; }
    if (entry->dst_port != 443)
        { FAIL("dst_port should be 443"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_fortigate_cef_deny(void) {
    TEST("FortiGate CEF act=deny");
    const char* line = "2026-09-08T11:07:55+00:00 FGT-A-LOG fortigate: CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward deny|3|deviceExternalId=FGT100F0000000001 FTNTFGTlogid=0001000013 cat=traffic:forward src=172.20.0.50 dst=172.20.0.4 spt=4444 dpt=22 proto=6 act=deny";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }
    if (strcmp(entry->src_ip, "172.20.0.50") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.0.4") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->proto, "TCP") != 0)
        { FAIL("proto should be TCP"); free_entry(entry); return; }
    if (entry->dst_port != 22)
        { FAIL("dst_port should be 22"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_fortigate_cef_drop(void) {
    TEST("FortiGate CEF act=drop");
    const char* line = "2026-09-08T11:07:55+00:00 FGT-A-LOG fortigate: CEF: 0|Fortinet|FortiGate|v7.0.0|00013|traffic:forward deny|3|deviceExternalId=FGT100F0000000013 FTNTFGTlogid=0000000013 cat=traffic:forward src=192.168.1.100 dst=8.8.8.8 spt=12345 dpt=53 proto=17 act=drop";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->event, "fw_block") != 0)
        { FAIL("event should be fw_block"); free_entry(entry); return; }
    if (strcmp(entry->proto, "UDP") != 0)
        { FAIL("proto should be UDP"); free_entry(entry); return; }
    if (entry->dst_port != 53)
        { FAIL("dst_port should be 53"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_brand_mikrotik_fw(void) {
    TEST("Brand MikroTik forward");
    const char* line = "2026-08-31T08:16:26+00:00 firewall.docker_building-lan firewall: firewall,info forward: in:ether1 out:ether2 src-address=172.20.100.5 dst-address=172.20.0.4 proto=TCP dst-port=80";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->src_ip, "172.20.100.5") != 0)
        { FAIL("src_ip mismatch"); free_entry(entry); return; }
    if (strcmp(entry->dst_ip, "172.20.0.4") != 0)
        { FAIL("dst_ip mismatch"); free_entry(entry); return; }
    if (entry->dst_port != 80)
        { FAIL("dst_port should be 80"); free_entry(entry); return; }
    free_entry(entry);
    PASS();
}

void test_traditional_timestamp(void) {
    TEST("Traditional timestamp to ISO");
    const char* line = "Aug 31 10:23:01 myhost tag: DROP packet SRC=10.0.0.5 DST=10.0.0.4";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (!strstr(entry->timestamp, "-08-31T10:23:01")) {
        FAIL("timestamp should contain -08-31T10:23:01");
        free_entry(entry);
        return;
    }
    if (strcmp(entry->hostname, "myhost") != 0) {
        FAIL("hostname mismatch after traditional ts");
        free_entry(entry);
        return;
    }
    free_entry(entry);
    PASS();
}

void test_traditional_single_day(void) {
    TEST("Traditional single-digit day");
    const char* line = "Aug  5 09:01:02 myhost tag: DROP packet";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (!strstr(entry->timestamp, "-08-05T09:01:02")) {
        FAIL("timestamp should contain -08-05T09:01:02");
        free_entry(entry);
        return;
    }
    free_entry(entry);
    PASS();
}

void test_bad_timestamp_fallback(void) {
    TEST("Bad timestamp falls back");
    const char* line = "Aug xx 99:99:99 myhost tag: hello";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (entry->timestamp[0] == '\0') {
        FAIL("fallback timestamp should not be empty");
        free_entry(entry);
        return;
    }
    free_entry(entry);
    PASS();
}

// "lap-01" must not classify as ap (substring guard).
void test_lap_not_ap(void) {
    TEST("lap-01 is not ap");
    const char* line = "2026-08-31T08:16:26+00:00 lap-01 kernel: SRC=10.0.0.5 DST=10.0.0.4 PROTO=TCP DPT=443 DROP packet";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->device_type, "ap") == 0) {
        FAIL("lap-01 misclassified as ap");
        free_entry(entry);
        return;
    }
    if (strcmp(entry->event, "fw_block") != 0) {
        FAIL("event should still be fw_block");
        free_entry(entry);
        return;
    }
    free_entry(entry);
    PASS();
}

// "ap01" token still classifies as ap.
void test_ap01_is_ap(void) {
    TEST("ap01 is ap");
    const char* line = "2026-08-31T08:16:26+00:00 ap01 hostapd: wlan0: STA aa:bb:cc:11:22:33 IEEE 802.11: associated";
    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }
    if (strcmp(entry->device_type, "ap") != 0) {
        FAIL("device_type should be ap");
        free_entry(entry);
        return;
    }
    free_entry(entry);
    PASS();
}

int main(void) {
    printf("=== Log Collector Unit Tests ===\n\n");

    test_parse_iso_syslog();
    test_parse_firewall_log();
    test_parse_switch_log();
    test_parse_router_dhcp();
    test_parse_scan_detected();
    test_parse_iptables_kernel();
    test_parse_arrow_form();
    test_parse_cisco_flap();
    test_parse_hostapd_real();
    test_parse_unknown_host();
    test_brand_cisco_router();
    test_brand_mikrotik_dhcp();
    test_brand_cisco_learn();
    test_brand_ruijie_flap();
    test_brand_ruijie_ap();
    test_brand_ruijie_auth();
    test_brand_fortigate();
    test_fortigate_cef_close();
    test_fortigate_cef_deny();
    test_fortigate_cef_drop();
    test_brand_mikrotik_fw();
    test_empty_line();
    test_to_json();
    test_to_json_escaping();
    test_malformed_line();
    test_traditional_timestamp();
    test_traditional_single_day();
    test_bad_timestamp_fallback();
    test_lap_not_ap();
    test_ap01_is_ap();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
