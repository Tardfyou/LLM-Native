# Manual Buffer Guard Lab

This lab is a minimal C project with a single-file buffer overflow pattern.

Vulnerable behavior:
- `parse_packet_name()` copies `input_len` bytes into a fixed `char name[16]` buffer.
- The original code performs `memcpy(pkt->name, input, input_len)` without checking whether `input_len` fits.

Patch intent:
- Reject inputs whose size is greater than or equal to the destination buffer size before the write.

Files:
- `src/packet_parser.c`: vulnerable source file
- `patches/packet_parser_bounds_fix.patch`: fix patch used as `--patch`
- `MANUAL_TEST_STEPS.md`: full generate -> evidence -> refine command sequence
