/* usermode.c - Standalone Ring 3 hello-world application.
 *
 * This file hosts simple user-mode applications and is not owinit. The kernel
 * boot path launches the real Essentials owinit.owx process separately; this
 * application is available to an explicit application-launch path only.
 *
 * Host builds keep the launcher as a no-op because they do not establish a
 * real CPL3 address space. */
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_usermode.h"
#include <stdint.h>

#ifdef OW_HOST_HAL

void OwUmLaunchHello(void) {}

#else

#define OW_USER_HELLO_BASE      0x4000000ULL
#define OW_USER_HELLO_CODE      OW_USER_HELLO_BASE
#define OW_USER_HELLO_DATA      (OW_USER_HELLO_BASE + 0x20000ULL)
#define OW_USER_HELLO_STACK_TOP (OW_USER_HELLO_BASE + 0x1FF000ULL)

static const char s_hello[] = "Hello from Ring 3!\r\n";

static const uint8_t s_hello_payload[] = {
    /* mov eax, OW_SYS_UART_WRITE; mov rcx, OW_USER_HELLO_DATA; int 0x80 */
    0xB8, 0x1B, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC1, 0x00, 0x00, 0x02, 0x04,
    0xCD, 0x80,
    /* mov eax, OW_SYS_PS_SLEEP; mov rcx, 8; int 0x80 */
    0xB8, 0x18, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    /* mov eax, OW_SYS_PS_EXIT_THREAD; int 0x80; cli; hlt; loop */
    0xB8, 0x0E, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xFA, 0xF4, 0xEB, 0xFE
};

void OwUmLaunchHello(void) {
    OW_PROCESS_OBJECT *process;
    uint32_t length = 0;

    OwHalMemSetUserAccessible(OW_USER_HELLO_BASE);
    ow_memcpy((void *)(uintptr_t)OW_USER_HELLO_CODE,
              s_hello_payload, sizeof(s_hello_payload));

    while (s_hello[length]) length++;
    ow_memcpy((void *)(uintptr_t)OW_USER_HELLO_DATA, s_hello, length + 1U);

    process = OwPsCreateProcess("user-hello", 0);
    if (!process) {
        ow_kprintf("[USER] hello process creation FAILED\r\n");
        return;
    }
    if (!OwPsCreateUserThread(process, OW_USER_HELLO_CODE,
                              OW_USER_HELLO_STACK_TOP)) {
        ow_kprintf("[USER] hello thread creation FAILED\r\n");
        return;
    }
    ow_kprintf("[USER] standalone Ring 3 hello application queued\r\n");
}

#endif /* OW_HOST_HAL */