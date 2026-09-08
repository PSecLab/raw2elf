/* Test firmware for raw2elf.
 *
 * Deliberately built to exercise recovery rather than to do anything useful:
 * a conventional Cortex-M vector table, a GCC-shaped .data copy and .bss
 * clear in the reset handler, real STM32F4 peripheral registers, a constant
 * table in .rodata and a handful of function pointers so that absolute code
 * references exist to recover.
 */
#include <stdint.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;

#define RCC_BASE     0x40023800u
#define GPIOA_BASE   0x40020000u
#define GPIOD_BASE   0x40020C00u
#define USART1_BASE  0x40011000u
#define TIM2_BASE    0x40000000u
#define PWR_BASE     0x40007000u
#define SYSTICK_BASE 0xE000E010u

#define REG(a) (*(volatile uint32_t *)(a))

volatile uint32_t counter = 0x12345678u;
volatile uint32_t scale = 3u;
volatile uint32_t sink[48];
static volatile uint32_t shadow[24];

static const uint32_t weights[24] = {
    0x0000000fu, 0x0000001eu, 0x0000002du, 0x0000003cu, 0x0000004bu, 0x0000005au,
    0x00000069u, 0x00000078u, 0x00000087u, 0x00000096u, 0x000000a5u, 0x000000b4u,
    0x000000c3u, 0x000000d2u, 0x000000e1u, 0x000000f0u, 0x000000ffu, 0x0000010eu,
    0x0000011du, 0x0000012cu, 0x0000013bu, 0x0000014au, 0x00000159u, 0x00000168u,
};
static const char banner[] = "raw2elf fixture firmware";

static void clock_setup(void)
{
    REG(RCC_BASE + 0x00) |= 0x00010000u;   /* RCC_CR: HSEON */
    REG(RCC_BASE + 0x08) = 0x00009400u;    /* RCC_CFGR */
    REG(RCC_BASE + 0x30) |= 0x00000009u;   /* RCC_AHB1ENR: GPIOA, GPIOD */
    REG(RCC_BASE + 0x40) |= 0x00000010u;   /* RCC_APB2ENR: USART1 */
    REG(RCC_BASE + 0x44) |= 0x00000001u;   /* RCC_APB1ENR: TIM2 */
    REG(PWR_BASE + 0x00) = 0x0000c000u;    /* PWR_CR */
}

static void gpio_setup(void)
{
    REG(GPIOA_BASE + 0x00) = 0x000000a0u;  /* GPIOA_MODER */
    REG(GPIOA_BASE + 0x08) = 0x000000f0u;  /* GPIOA_OSPEEDR */
    REG(GPIOA_BASE + 0x20) = 0x00000770u;  /* GPIOA_AFRL */
    REG(GPIOD_BASE + 0x00) = 0x55000000u;  /* GPIOD_MODER */
    REG(GPIOD_BASE + 0x18) = 0x00001000u;  /* GPIOD_BSRR */
}

static void uart_setup(void)
{
    REG(USART1_BASE + 0x08) = 0x00000341u; /* USART1_BRR */
    REG(USART1_BASE + 0x0c) = 0x0000200cu; /* USART1_CR1 */
}

static void timer_setup(void)
{
    REG(TIM2_BASE + 0x28) = 0x0000a410u;   /* TIM2_PSC */
    REG(TIM2_BASE + 0x2c) = 0x000003e8u;   /* TIM2_ARR */
    REG(TIM2_BASE + 0x00) = 0x00000001u;   /* TIM2_CR1 */
}

static void systick_setup(void)
{
    REG(SYSTICK_BASE + 0x04) = 0x00002710u;
    REG(SYSTICK_BASE + 0x00) = 0x00000007u;
}

static uint32_t mix(uint32_t value)
{
    return (value ^ (value >> 13)) * 0x9e3779b9u;
}

static uint32_t accumulate(uint32_t seed)
{
    uint32_t total = seed;
    for (unsigned index = 0; index < 24; index++) {
        shadow[index] = mix(weights[index] + total);
        total += shadow[index];
    }
    return total;
}

static void emit(uint32_t value)
{
    while ((REG(USART1_BASE + 0x00) & 0x80u) == 0u) {
    }
    REG(USART1_BASE + 0x04) = value & 0xffu;
}

typedef uint32_t (*stage_t)(uint32_t);

static uint32_t stage_a(uint32_t value) { return value + counter; }
static uint32_t stage_b(uint32_t value) { return value * scale; }
static uint32_t stage_c(uint32_t value) { return mix(value); }

/* A function pointer table gives base recovery absolute code pointers to
 * cross-check against the call targets a sweep finds. */
static stage_t const stages[3] = { stage_a, stage_b, stage_c };

int main(void)
{
    clock_setup();
    gpio_setup();
    uart_setup();
    timer_setup();
    systick_setup();

    uint32_t value = counter;
    for (unsigned round = 0; round < 3; round++) {
        value = stages[round](value);
        sink[round] = value;
    }
    value = accumulate(value);
#if defined(HAVE_SECOND_RAM_BANK)
    extern void ccm_touch(uint32_t value);
    ccm_touch(value);
#endif
    for (unsigned index = 0; index < sizeof(banner) - 1; index++) {
        emit((uint32_t)banner[index]);
    }
    for (;;) {
        sink[3] = value;
        REG(GPIOD_BASE + 0x14) ^= 0x00001000u;
    }
}

void Default_Handler(void)
{
    for (;;) {
    }
}

void Reset_Handler(void)
{
    uint32_t *source = &_sidata;
    uint32_t *destination = &_sdata;

    while (destination < &_edata) {
        *destination++ = *source++;
    }
    for (destination = &_sbss; destination < &_ebss;) {
        *destination++ = 0u;
    }
    main();
    for (;;) {
    }
}

void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));

void SysTick_Handler(void)
{
    counter += 1u;
    sink[4] = counter;
}

void USART1_IRQHandler(void)
{
    sink[5] = REG(USART1_BASE + 0x04);
}

void TIM2_IRQHandler(void)
{
    REG(TIM2_BASE + 0x10) = 0u;
    sink[6] += 1u;
}

#define IRQ(n) Default_Handler
__attribute__((section(".isr_vector"), used))
void (*const vector_table[])(void) = {
    (void (*)(void))&_estack,
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    0, 0, 0, 0,
    SVC_Handler,
    DebugMon_Handler,
    0,
    PendSV_Handler,
    SysTick_Handler,
    /* device interrupts 0.. */
    IRQ(0), IRQ(1), IRQ(2), IRQ(3), IRQ(4), IRQ(5), IRQ(6), IRQ(7),
    IRQ(8), IRQ(9), IRQ(10), IRQ(11), IRQ(12), IRQ(13), IRQ(14), IRQ(15),
    IRQ(16), IRQ(17), IRQ(18), IRQ(19), IRQ(20), IRQ(21), IRQ(22), IRQ(23),
    IRQ(24), IRQ(25), IRQ(26), IRQ(27),
    TIM2_IRQHandler,                    /* IRQ 28 on STM32F4 */
    IRQ(29), IRQ(30), IRQ(31), IRQ(32), IRQ(33), IRQ(34), IRQ(35), IRQ(36),
    USART1_IRQHandler,                  /* IRQ 37 on STM32F4 */
    IRQ(38), IRQ(39), IRQ(40), IRQ(41), IRQ(42), IRQ(43),
    IRQ(44), IRQ(45), IRQ(46), IRQ(47), IRQ(48), IRQ(49), IRQ(50), IRQ(51),
    IRQ(52), IRQ(53), IRQ(54), IRQ(55), IRQ(56), IRQ(57), IRQ(58), IRQ(59),
    IRQ(60), IRQ(61), IRQ(62), IRQ(63), IRQ(64), IRQ(65), IRQ(66), IRQ(67),
    IRQ(68), IRQ(69), IRQ(70), IRQ(71), IRQ(72), IRQ(73), IRQ(74), IRQ(75),
    IRQ(76), IRQ(77), IRQ(78), IRQ(79), IRQ(80), IRQ(81),
};
