/* A second RAM bank, so region recovery has more than one to find. */
#include <stdint.h>

__attribute__((section(".ccmram"), used)) volatile uint32_t fast_buffer[64];

void ccm_touch(uint32_t value)
{
    fast_buffer[value & 0x3fu] = value;
    fast_buffer[0] += fast_buffer[1];
}
