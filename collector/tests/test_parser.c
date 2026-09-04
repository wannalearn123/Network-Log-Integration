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

// ============================================================
// Test: Parse rsyslog ISO format
// ============================================================
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

// ============================================================
// Test: Parse firewall log with SRC/DST
// ============================================================
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

// ============================================================
// Test: Parse switch MAC learning
// ============================================================
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

// ============================================================
// Test: Parse router DHCP
// ============================================================
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

// ============================================================
// Test: Parse scan detection
// ============================================================
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

// ============================================================
// Test: Empty line returns NULL
// ============================================================
void test_empty_line(void) {
    TEST("Empty line returns NULL");
    log_entry_t* entry = parse_syslog_line("");
    if (entry != NULL) { FAIL("should be NULL"); free_entry(entry); return; }

    entry = parse_syslog_line(NULL);
    if (entry != NULL) { FAIL("NULL input should return NULL"); free_entry(entry); return; }

    PASS();
}

// ============================================================
// Test: to_json output
// ============================================================
void test_to_json(void) {
    TEST("to_json produces valid JSON");
    const char* line = "2026-08-31T04:44:43+00:00 ap.docker_building-lan hostapd: wlan0: AP-STA-CONNECTED aa:bb:cc 172.20.100.4 printer-04";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("parse returned NULL"); return; }

    char* json = to_json(entry);
    if (!json) { FAIL("to_json returned NULL"); free_entry(entry); return; }

    // Check it starts with { and ends with }
    if (json[0] != '{') { FAIL("JSON should start with {"); free(json); free_entry(entry); return; }

    int len = strlen(json);
    if (json[len-1] != '\n' || json[len-2] != '}') {
        // Check last non-newline char
        if (json[len-1] != '}') { FAIL("JSON should end with }"); free(json); free_entry(entry); return; }
    }

    // Check it contains hostname
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

// ============================================================
// Test: Malformed syslog line
// ============================================================
void test_malformed_line(void) {
    TEST("Malformed syslog line parses without crash");
    const char* line = "this is not syslog at all";

    log_entry_t* entry = parse_syslog_line(line);
    if (!entry) { FAIL("returned NULL"); return; }

    // Should have some defaults
    if (entry->facility[0] == '\0') { FAIL("facility should have default"); free_entry(entry); return; }
    if (entry->severity[0] == '\0') { FAIL("severity should have default"); free_entry(entry); return; }

    free_entry(entry);
    PASS();
}

// ============================================================
// Main
// ============================================================
int main(void) {
    printf("=== Log Collector Unit Tests ===\n\n");

    test_parse_iso_syslog();
    test_parse_firewall_log();
    test_parse_switch_log();
    test_parse_router_dhcp();
    test_parse_scan_detected();
    test_empty_line();
    test_to_json();
    test_malformed_line();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
