#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "algo-ac.h"

#define MAX_PATTERNS 4096
#define MAX_LINE_LEN 1024

static void free_patterns(void **patterns, int *sizes, int count) {
    for (int i = 0; i < count; i++) {
        free(patterns[i]);
    }

    free(patterns);
    free(sizes);
}

static int load_patterns(const char *filename, void ***patterns_out,
                         int **sizes_out) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    void **patterns = malloc(sizeof(void *) * MAX_PATTERNS);
    int *sizes = malloc(sizeof(int) * MAX_PATTERNS);

    if (!patterns || !sizes) {
        perror("malloc");
        fclose(fp);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {

        size_t len = strlen(line);

        /* remove newline */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0)
            continue;

        unsigned char *p = malloc(len + 1);

        if (!p) {
            perror("malloc");
            fclose(fp);
            free_patterns(patterns, sizes, count);
            return -1;
        }

        memcpy(p, line, len);
        p[len] = '\0';

        patterns[count] = p;
        sizes[count] = (int)len;

        count++;

        if (count >= MAX_PATTERNS) {
            fprintf(stderr, "Troppi pattern\n");
            break;
        }
    }

    fclose(fp);

    *patterns_out = patterns;
    *sizes_out = sizes;

    return count;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <trace.pcap> <patterns.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *pcap_file = argv[1];
    const char *pattern_file = argv[2];

    void **patterns = NULL;
    int *pattern_sizes = NULL;

    int pattern_count = load_patterns(pattern_file, &patterns, &pattern_sizes);

    if (pattern_count <= 0) {
        fprintf(stderr, "Errore caricamento pattern\n");
        return EXIT_FAILURE;
    }

    printf("[+] Loaded %d patterns\n", pattern_count);

    /*
     *      * Build DFA
     *           */
    DFA_struct *dfa =
        DFA_build((const void **)patterns, pattern_count, pattern_sizes, 0);

    if (!dfa) {
        fprintf(stderr, "Errore DFA_build\n");
        free_patterns(patterns, pattern_sizes, pattern_count);
        return EXIT_FAILURE;
    }

    /*
     *      * Open pcap
     *           */
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

    if (!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);

        DFA_free(dfa);
        free_patterns(patterns, pattern_sizes, pattern_count);

        return EXIT_FAILURE;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;

    int ret;
    int pkt_count = 0;

    /*
     *      * Scan packets
     *           */
    while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (ret == 0)
            continue;

        pkt_count++;

        int *matches = NULL;

        DFA_exec_chunk(dfa->root, packet, (int)header->caplen, &matches, NULL);

        if (matches)
            free(matches);
    }

    printf("[+] Processed packets: %d\n", pkt_count);

    /*
     *      * Print DFA statistics / hot states
     *           */
    DFA_debug(dfa->root);

    /*
     *      * Cleanup
     *           */
    pcap_close(handle);

    DFA_free(dfa);

    free_patterns(patterns, pattern_sizes, pattern_count);

    return EXIT_SUCCESS;
}
