// Tested on FreeBSD 15 only; structure definitions may need adjustment for other versions of FreeBSD. I've only implemented this specifically for version 15 

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define IPFW_CFG_GET_STATIC     0x01
#define IPFW_CFG_GET_STATES     0x02
#define IPFW_CFG_GET_COUNTERS   0x04

static void hex_dump(const unsigned char *data, size_t len, size_t max_dump) {
    size_t dump_len = len < max_dump ? len : max_dump;
    for (size_t i = 0; i < dump_len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (dump_len % 16 != 0) printf("\n");
    if (len > max_dump) {
        printf("--- (total %zu bytes, showing first %zu) ---\n", len, max_dump);
    }
}

int main(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    ipfw_cfg_lheader probe = {0};
    socklen_t probe_len = sizeof(probe);

    probe.opheader.opcode  = 97;
    probe.opheader.version = IP_FW3_OPVER;
    probe.set_mask         = 0xFFFFFFFFU;
    probe.spare            = 0;
    probe.flags            = IPFW_CFG_GET_STATIC |
                             IPFW_CFG_GET_STATES  |
                             IPFW_CFG_GET_COUNTERS;
    probe.start_rule       = 0;
    probe.end_rule         = 0xFFFFFFFFU;

    printf("Probing required size (small hdr)...\n");
    if (getsockopt(s, IPPROTO_IP, IP_FW3, &probe, &probe_len) < 0) {
        if (errno == ENOMEM) {
            printf("\tENOMEM received (normal for size probe)\n");
        } else {
            perror("probe failed");
            close(s);
            return 1;
        }
    } else {
        printf("\tProbe succeeded without ENOMEM\n");
    }

    uint32_t needed = probe.size;
    printf("Kernel reports needed buffer size: %u bytes\n", needed);

    if (needed == 0) {
        printf("Kernel reported 0 bytes, no config or invalid flags\n");
        close(s);
        return 1;
    }

    if (needed > 2 * 1024 * 1024) {
        printf("Too large the size is: %u aborting\n", needed);
        close(s);
        return 1;
    }

    char *full_buf = calloc(1, needed);
    if (!full_buf) {
        perror("calloc full buffer");
        close(s);
        return 1;
    }

    ipfw_cfg_lheader *req = (ipfw_cfg_lheader *)full_buf;
    *req = probe;
    req->opheader.opcode  = 97;
    req->opheader.version = IP_FW3_OPVER;

    socklen_t fetch_len = needed;

    printf("Fetching full configuration (%u bytes)\n", needed);
    if (getsockopt(s, IPPROTO_IP, IP_FW3, full_buf, &fetch_len) < 0) {
        perror("fetch failed");
        free(full_buf);
        close(s);
        return 1;
    }

    printf("Success! Kernel returned %u bytes\n", fetch_len);
    printf("\nFirst 256 bytes:\n");
    hex_dump((const unsigned char *)full_buf, fetch_len, 256);

    FILE *f = fopen("ipfw_config.bin", "wb");
    if (!f) {
        perror("fopen ipfw_config.bin");
    } else {
        size_t written = fwrite(full_buf, 1, fetch_len, f);
        fclose(f);
        if (written == fetch_len) {
            printf("Full %u bytes saved to ipfw_config.bin\n", fetch_len);
        } else {
            printf("Warning: wrote only %zu of %u bytes\n", written, fetch_len);
        }
    }

    free(full_buf);
    close(s);

    printf("\nDone. Check: ipfw_config.bin\n");

    return 0;
}
