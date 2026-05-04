#include <stddef.h>
#include <string.h>

typedef struct {
    char name[16];
    size_t name_len;
} Packet;

int parse_packet_name(Packet *pkt, const char *input, size_t input_len) {
    if (!pkt || !input) {
        return -1;
    }

    memcpy(pkt->name, input, input_len);
    pkt->name[input_len] = '\0';
    pkt->name_len = input_len;
    return 0;
}

int load_packet(Packet *pkt, const char *wire_name, size_t wire_name_len) {
    if (!pkt) {
        return -1;
    }

    return parse_packet_name(pkt, wire_name, wire_name_len);
}
