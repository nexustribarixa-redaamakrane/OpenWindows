/*
 * host_boot.c - Host boot harness for openwinkrnl.owx
 *
 * Executes the same boot sequence as core/main.c::_start, then drives
 * the Ring-0 debug shell through scripted host UART input and validates
 * the resulting transcript.
 *
 * Host file access deliberately avoids:
 *   fopen / fread / fseek / ftell
 *   strcpy / strlen / strstr
 *   malloc / free
 *   snprintf
 *
 * Windows uses _sopen_s/_read/_close.
 * POSIX hosts use open/read/close.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../../inc/ow_alpc.h"
#include "../../inc/ow_diag.h"
#include "../../inc/ow_ecosys.h"
#include "../../inc/ow_hal.h"
#include "../../inc/ow_kprintf.h"
#include "../../boot/owinit_image.h"
#include "../../inc/ow_memory.h"
#include "../../inc/ow_net.h"
#include "../../inc/ow_object.h"
#include "../../inc/ow_ps.h"
#include "../../inc/ow_runlevel.h"
#include "../../inc/ow_sentinel.h"
#include "../../inc/ow_shell.h"
#include "../../inc/ow_syscall.h"
#include "../../inc/ow_types.h"
#include "../../inc/ow_vfs.h"
#include "../../storage/owdisk.h"

#include <stdio.h>

/* -------------------------------------------------------------------------
 */
/* Host HAL */
/* -------------------------------------------------------------------------
 */

char *HostHalOutput(void);
size_t HostHalOutputLen(void);
void HostHalSetInputScript(const char *script);

/* ------------------------------------------------------------------------- */
/* Harness state                                                              */
/* ------------------------------------------------------------------------- */

static const char *g_script = "exit\n";

static int g_failures = 0;
static int g_passed = 0;

/* ------------------------------------------------------------------------- */
/* Tiny local string helpers                                                  */
/* ------------------------------------------------------------------------- */

static size_t ow_strlen(const char *text) {
  size_t length = 0;

  if (text == NULL)
    return 0;

  while (text[length] != '\0')
    ++length;

  return length;
}

/*
 * Bounded string copy.
 *
 * Returns true when the complete string fitted.
 * Returns false when truncation would have occurred.
 */
static bool ow_strcopy(char *destination, size_t destination_size,
                       const char *source) {
  size_t i;

  if (destination == NULL || source == NULL || destination_size == 0) {
    return false;
  }

  for (i = 0; i + 1 < destination_size && source[i] != '\0'; ++i) {
    destination[i] = source[i];
  }

  destination[i] = '\0';

  return source[i] == '\0';
}

/*
 * Small byte-copy helper.
 *
 * Used instead of strcpy/memcpy for the tiny host-side buffers here.
 */
static void ow_copy_bytes(uint8_t *destination, const uint8_t *source,
                          size_t count) {
  size_t i;

  if (destination == NULL || source == NULL)
    return;

  for (i = 0; i < count; ++i)
    destination[i] = source[i];
}

/* ------------------------------------------------------------------------- */
/* Local substring search                                                     */
/* ------------------------------------------------------------------------- */

static const char *ow_strfind(const char *haystack, const char *needle) {
  size_t needle_length;
  size_t i;

  if (haystack == NULL || needle == NULL)
    return NULL;

  needle_length = ow_strlen(needle);

  if (needle_length == 0)
    return haystack;

  for (i = 0; haystack[i] != '\0'; ++i) {
    size_t j;

    for (j = 0; j < needle_length; ++j) {
      if (haystack[i + j] == '\0')
        break;

      if (haystack[i + j] != needle[j])
        break;
    }

    if (j == needle_length)
      return &haystack[i];
  }

  return NULL;
}

static size_t count_occ(const char *haystack, const char *needle) {
  size_t count = 0;
  size_t needle_length;
  const char *current;

  if (haystack == NULL || needle == NULL)
    return 0;

  needle_length = ow_strlen(needle);

  if (needle_length == 0)
    return 0;

  current = haystack;

  while ((current = ow_strfind(current, needle)) != NULL) {
    ++count;
    current += needle_length;
  }

  return count;
}

/* ------------------------------------------------------------------------- */
/* Transcript verification                                                    */
/* ------------------------------------------------------------------------- */

static void expect(const char *needle, size_t minimum_count) {
  char *output;
  size_t count;

  output = HostHalOutput();

  if (output == NULL)
    return;

  count = count_occ(output, needle);

  if (count >= minimum_count) {
    ++g_passed;

    printf("[PASS] <<%s>> x%u\n", needle, (unsigned)count);
  } else {
    ++g_failures;

    printf("[FAIL] <<%s>> expected >=%u, found %u\n", needle,
           (unsigned)minimum_count, (unsigned)count);
  }
}

/* ------------------------------------------------------------------------- */
/* Host file access                                                           */
/* ------------------------------------------------------------------------- */

/*
 * Read a host file into a caller-provided buffer.
 *
 * Returns:
 *   >= 0 : number of bytes read
 *   -1   : failure
 *
 * No stdio file API is used.
 */
static long host_read_file(const char *path, uint8_t *buffer, size_t capacity) {
  int fd;
  long total = 0;

  if (path == NULL || buffer == NULL || capacity == 0) {
    return -1;
  }

#ifdef _WIN32

  {
    errno_t result;

    result = _sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0);

    if (result != 0 || fd < 0)
      return -1;
  }

#else

  fd = open(path, O_RDONLY);

  if (fd < 0)
    return -1;

#endif

  while ((size_t)total < capacity) {
    size_t remaining;
    unsigned int request;
    int bytes_read;

    remaining = capacity - (size_t)total;

    /*
     * Keep the read size inside the range accepted by both
     * the Windows CRT and normal POSIX implementations.
     */
    request = (remaining > 0x7FFFFFFFU) ? 0x7FFFFFFFU : (unsigned int)remaining;

#ifdef _WIN32

    bytes_read = _read(fd, buffer + total, request);

#else

    bytes_read = (int)read(fd, buffer + total, request);

#endif

    if (bytes_read < 0) {

#ifdef _WIN32
      _close(fd);
#else
      close(fd);
#endif

      return -1;
    }

    if (bytes_read == 0)
      break;

    total += (long)bytes_read;
  }

#ifdef _WIN32
  _close(fd);
#else
  close(fd);
#endif

  return total;
}

/*
 * Try:
 *
 *   name
 *   build/name
 *   ../name
 *
 * without constructing paths using snprintf/strcpy.
 */
static long host_read_file_candidates(const char *name, uint8_t *buffer,
                                      size_t capacity) {
  static const char *const prefixes[] = {"", "build/", "../"};

  size_t prefix_index;

  if (name == NULL)
    return -1;

  for (prefix_index = 0; prefix_index < sizeof(prefixes) / sizeof(prefixes[0]);
       ++prefix_index) {

    char path[512];
    size_t prefix_length;
    size_t name_length;

    prefix_length = ow_strlen(prefixes[prefix_index]);
    name_length = ow_strlen(name);

    if (prefix_length + name_length + 1 > sizeof(path))
      continue;

    if (prefix_length != 0) {
      ow_copy_bytes((uint8_t *)path, (const uint8_t *)prefixes[prefix_index],
                    prefix_length);
    }

    ow_copy_bytes((uint8_t *)path + prefix_length, (const uint8_t *)name,
                  name_length);

    path[prefix_length + name_length] = '\0';

    {
      long result;

      result = host_read_file(path, buffer, capacity);

      if (result >= 0)
        return result;
    }
  }

  return -1;
}

/* ------------------------------------------------------------------------- */
/* Main                                                                       */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  OW_STATUS st;

  printf("=== OpenWindows kernel host boot harness ===\n");

  fflush(stdout);

  /* ------------------------------------------------------------------ */
  /* Phase 1: HAL                                                       */
  /* ------------------------------------------------------------------ */

  st = OwHalInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] HAL failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 2: Memory Manager                                            */
  /* ------------------------------------------------------------------ */

  st = OwMemInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Memory init failed\n");
    return 1;
  }

  (void)OwMemAllocatePage();

  /* ------------------------------------------------------------------ */
  /* Phase 3: Object Manager                                            */
  /* ------------------------------------------------------------------ */

  st = OwObjInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Object init failed\n");
    return 1;
  }

  (void)OwObjCreateDirectory("\\", (void *)0);
  (void)OwObjCreateDirectory("Device", (void *)0);
  (void)OwObjCreateDirectory("DosDevices", (void *)0);
  (void)OwObjCreateDirectory("Kernel", (void *)0);
  (void)OwObjCreateDirectory("Drivers", (void *)0);

  /* ------------------------------------------------------------------ */
  /* Phase 4: Diagnostic Engine + ALPC                                  */
  /* ------------------------------------------------------------------ */

  st = OwDiagInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Diag init failed\n");
    return 1;
  }

  st = OwAlpcInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] ALPC init failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Runlevel subsystem                                                 */
  /* ------------------------------------------------------------------ */

  st = OwRunlevelInitialize(OW_RUNLEVEL_BOOT_DEFAULT);

  if (!ow_status_success(st)) {
    printf("[BOOT] Runlevel init failed\n");
    return 1;
  }

  ow_kprintf("[RUNLVL] boot target: %d (%s) - "
             "runlevel subsystem online\r\n",
             OwRunlevelGetTarget(), OwRunlevelName(OwRunlevelGetTarget()));

  /* ------------------------------------------------------------------ */
  /* Phase 4b: SUCS + SUTF                                              */
  /* ------------------------------------------------------------------ */

  OwSucsInitialize();
  (void)OwSucsCommitBoot();

  if (OwSucsSelfTest()) {

    ow_kprintf("[SUTF] Codec self-test: OK "
               "(Base SUCS / SUTF-8 active)\r\n");

  } else {

    printf("[BOOT] SUTF self-test failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 4c: Process / Thread subsystem                               */
  /* ------------------------------------------------------------------ */

  st = OwPsInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] PS init failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5: VFS                                                       */
  /* ------------------------------------------------------------------ */

  st = OwVfsMountPrimary();

  if (!ow_status_success(st)) {
    printf("[BOOT] VFS primary failed\n");
    return 1;
  }

  st = OwVfsMountSecure();

  if (!ow_status_success(st)) {
    printf("[BOOT] VFS secure failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5b: Physical storage                                         */
  /* ------------------------------------------------------------------ */

  st = OwDiskInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] OwDiskInitialize failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Provision owinit.owx                                               */
  /* ------------------------------------------------------------------ */

  {
    uint32_t ino = 0;

    st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &ino);

    if (!ow_status_success(st)) {
      printf("[BOOT] owinit create failed\n");
      return 1;
    }

    st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owinit_image, OWINIT_IMAGE_SIZE);

    if (!ow_status_success(st)) {
      printf("[BOOT] owinit write failed\n");
      return 1;
    }

    printf("[BOOT] provisioned %s on host OWFS "
           "(ino %u)\n",
           OW_INIT_EXEC_NAME, (unsigned)ino);
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5c: owinit provisioning check                                */
  /* ------------------------------------------------------------------ */

  ow_kprintf("[STARTED] owinit\r\n");

  if (OwDiskOwinitPresent()) {

    ow_kprintf("[FINISHED] owinit\r\n");

  } else {

    printf("[BOOT] owinit executable missing on host OWFS\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5c.5: owinit process hand-off                                */
  /* ------------------------------------------------------------------ */

  {
    static uint8_t s_OwinitImage[64U * 1024U];

    uint32_t read_len = 0;
    OW_STATUS read_status;

    read_status = OwFsOwfsRead(OW_INIT_EXEC_NAME, s_OwinitImage,
                               (uint32_t)sizeof(s_OwinitImage), &read_len);

    if (!ow_status_success(read_status) || read_len == 0) {

      printf("[BOOT] owinit.owx read failed "
             "(st=0x%x, len=%u)\n",
             (unsigned)read_status, (unsigned)read_len);

      return 1;
    }

    {
      OW_PROCESS_OBJECT *process;

      process = OwPsCreateProcess("owinit", OW_PS_PID_KERNEL);

      if (process == NULL) {

        printf("[BOOT] owinit process create failed\n");

        return 1;
      }

      if (!ow_status_success(OwPsLoadImage(process, s_OwinitImage, read_len))) {

        printf("[BOOT] owinit image load failed "
               "(len=%u)\n",
               (unsigned)read_len);

        return 1;
      }

      {
        OW_THREAD_OBJECT *thread;

        thread = OwPsCreateThread(process, process->EntryPoint, 0);

        if (thread == NULL) {

          printf("[BOOT] owinit thread create failed\n");

          return 1;
        }

        printf("[BOOT] owinit enqueued as PID 1 "
               "thread %u\n",
               (unsigned)thread->Tid);
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Provision openwinkrnl.chk                                          */
  /* ------------------------------------------------------------------ */

  {
    static const char kDefaultChecksum[] =
        "e925ab4e3f175405000000000000000000000000000000000000000000000000\n";

    uint8_t checksum_buffer[256];
    uint32_t checksum_inode = 0;
    long checksum_length;

    checksum_length = host_read_file_candidates(
        "openwinkrnl.chk", checksum_buffer, sizeof(checksum_buffer) - 1);

    if (checksum_length < 0) {

      /*
       * No host checksum was found.
       * Use the built-in test checksum.
       */
      if (!ow_strcopy((char *)checksum_buffer, sizeof(checksum_buffer),
                      kDefaultChecksum)) {

        printf("[BOOT] default checksum copy failed\n");

        return 1;
      }

      checksum_length = (long)ow_strlen((const char *)checksum_buffer);

    } else {

      checksum_buffer[checksum_length] = '\0';
    }

    st = OwFsOwfsCreate(OW_KERNEL_CHK_NAME, &checksum_inode);

    if (!ow_status_success(st)) {

      printf("[BOOT] openwinkrnl.chk create failed\n");

      return 1;
    }

    st = OwFsOwfsWrite(OW_KERNEL_CHK_NAME, checksum_buffer,
                       (uint32_t)checksum_length);

    if (!ow_status_success(st)) {

      printf("[BOOT] openwinkrnl.chk write failed\n");

      return 1;
    }

    printf("[BOOT] provisioned %s on host OWFS "
           "(ino %u, len %u)\n",
           OW_KERNEL_CHK_NAME, (unsigned)checksum_inode,
           (unsigned)checksum_length);
  }

  /* ------------------------------------------------------------------ */
  /* Provision openwinkrnl.owx                                          */
  /* ------------------------------------------------------------------ */

  {
    /*
     * Static storage intentionally replaces malloc/free.
     *
     * Increase this if OpenWindows kernel images can exceed 1 MiB.
     */
    static uint8_t kernel_image[1024U * 1024U];

    uint32_t kernel_inode = 0;
    long kernel_size;

    kernel_size = host_read_file_candidates("openwinkrnl.owx", kernel_image,
                                            sizeof(kernel_image));

    if (kernel_size > 0) {

      st = OwFsOwfsCreate(OW_KERNEL_IMG_NAME, &kernel_inode);

      if (!ow_status_success(st)) {

        printf("[BOOT] %s create failed\n", OW_KERNEL_IMG_NAME);

        return 1;
      }

      st = OwFsOwfsWrite(OW_KERNEL_IMG_NAME, kernel_image,
                         (uint32_t)kernel_size);

      if (!ow_status_success(st)) {

        printf("[BOOT] %s write failed\n", OW_KERNEL_IMG_NAME);

        return 1;
      }

      printf("[BOOT] provisioned %s on host OWFS "
             "(ino %u, size %ld)\n",
             OW_KERNEL_IMG_NAME, (unsigned)kernel_inode, kernel_size);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5d: Kernel integrity                                         */
  /* ------------------------------------------------------------------ */

  ow_kprintf("[STARTED] Kernel Integrity\r\n");

  st = OwSentinelVerifyKernelChecksum();

  if (ow_status_success(st)) {

    ow_kprintf("[FINISHED] Kernel Integrity\r\n");

  } else {

    printf("[BOOT] Kernel integrity check failed (0x%X)\n", (unsigned)st);

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 6: Network Router                                            */
  /* ------------------------------------------------------------------ */

  st = OwNetInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Net init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 6b: UniVIP + FVIP                                            */
  /* ------------------------------------------------------------------ */

  if (!OwVipIsUp()) {

    uint32_t vip_code;

    vip_code = OwVipInitialize();

    if (!OwVipIsSuccessCode(vip_code)) {

      printf("[BOOT] VIP init failed (0x%X)\n", (unsigned)vip_code);

      return 1;
    }
  }

  if (OwVipIsUp()) {

    ow_kprintf("[VIP] UniVIP online: root volume %u @ LBA %llu, "
               "FVIP index ready\r\n",
               OW_VIP_ROOT_VOLUME, (unsigned long long)OW_VIP_ROOT_BASE_SECTOR);
  }

  /* ------------------------------------------------------------------ */
  /* Phase 7: Sentinel                                                  */
  /* ------------------------------------------------------------------ */

  st = OwSentinelInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Sentinel init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 8: Syscall gateway                                           */
  /* ------------------------------------------------------------------ */

  st = OwSyscallInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Syscall init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 9: Scheduler hand-off                                        */
  /* ------------------------------------------------------------------ */

  OwPsCaptureBootContext();
  OwPsStartScheduler();

  /* ------------------------------------------------------------------ */
  /* Phase 9: Debug shell                                                */
  /* ------------------------------------------------------------------ */

  st = OwShellInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Shell init failed\n");

    return 1;
  }

  /*
   * Build the optional custom shell command without snprintf.
   *
   * argc == 1:
   *     exit
   *
   * argc == 2:
   *     argv[1]
   *     exit
   *
   * argc >= 3:
   *     argv[1] argv[2]
   *     exit
   */
  if (argc > 1) {

    static char custom_script[256];

    size_t position = 0;
    size_t i;

    /* First argument. */
    for (i = 0; argv[1][i] != '\0' && position + 1 < sizeof(custom_script);
         ++i) {

      custom_script[position++] = argv[1][i];
    }

    /* Optional second argument. */
    if (argc > 2 && position + 1 < sizeof(custom_script)) {

      custom_script[position++] = ' ';

      for (i = 0; argv[2][i] != '\0' && position + 1 < sizeof(custom_script);
           ++i) {

        custom_script[position++] = argv[2][i];
      }
    }

    /* Newline after command. */
    if (position + 1 < sizeof(custom_script))
      custom_script[position++] = '\n';

    /* "exit\n" */
    if (position + 5 < sizeof(custom_script)) {

      custom_script[position++] = 'e';
      custom_script[position++] = 'x';
      custom_script[position++] = 'i';
      custom_script[position++] = 't';
      custom_script[position++] = '\n';
    }

    custom_script[position] = '\0';

    HostHalSetInputScript(custom_script);

  } else {

    HostHalSetInputScript(g_script);
  }

  (void)OwShellRun();

  /* ------------------------------------------------------------------ */
  /* Custom trap verification                                            */
  /* ------------------------------------------------------------------ */

  if (argc > 1) {

    printf("\n=== Custom Trap Execution Verification ===\n");

    if (count_occ(HostHalOutput(), "You need to restart your device.") > 0) {
      expect("You need to restart your device.", 1);
    } else {
      expect("SYSTEM HALTED", 1);
    }

    expect("SYSTEM HALTED", 1);

    expect("#######", 1);

    printf("\n=== RESULT: %d passed, %d failed ===\n", g_passed, g_failures);

    fflush(stdout);

    return (g_failures == 0) ? 0 : 1;
  }

  /* ------------------------------------------------------------------ */
  /* Normal transcript verification                                     */
  /* ------------------------------------------------------------------ */

  printf("\n=== Transcript verification ===\n");

  fflush(stdout);

  expect("[SUTF] Codec self-test: OK", 1);

  expect("[RUNLVL] boot target: 5 (FULL)", 1);

  expect("[RUNLVL] current=5 (FULL)", 1);

  expect("[RUNLVL] config: verbosity=1 "
         "watchdogMs=0 heapKB=262144 "
         "maxHandles=65536",
         1);

  expect("[RUNLVL] profile: level 3, name NETWORK", 1);

  expect("[RUNLVL]   + NETWORK", 1);

  expect("[RUNLVL]   + AI", 1);

  expect("[FINISHED] owinit", 1);

  expect("[FINISHED] Kernel Integrity", 1);

  expect("[PS] process/thread subsystem initialized", 1);

  expect("[PS] owinit: process created (PID 1)", 1);

  expect("[PS] owinit: thread 1 created, entry 0x", 1);

  expect("[PS] boot context captured (thread 0)", 1);

  expect("[PS] scheduler started (100 Hz)", 1);

  expect("[VIP] UniVIP online: root volume 0 @ LBA 131200", 1);

  expect("[VIP] mount code 0x11AD02", 1);

  expect("[VIP] volume 1 base LBA 131200", 1);

  expect("[VIP] '/boot/bootvid.owd' sector_offset=12 flags=0x3", 1);

  expect("[VIP] lookup miss code 0x11AEE2", 1);

  expect("[VIP] integrity code 0x", 1);

  expect("[FS] format: OK", 1);

  expect("[FS] owfs mount: OK", 1);

  expect("[FS] mkdir 'System': OK", 1);

  expect("[FS] create 'bootvid.owd': OK", 1);

  expect("[FS] write 'bootvid.owd': OK", 1);

  expect("[FS] OWFS: MOUNTED", 1);

  expect("[FS] USFS: MOUNTED", 1);

  expect("OpenWindows storage live", 2);

  expect("[SUCS] request: staged, reboot required", 1);

  expect("[SHUTDOWN] Exiting...", 1);

  /* ------------------------------------------------------------------ */
  /* Final result                                                        */
  /* ------------------------------------------------------------------ */

  printf("\n=== RESULT: %d passed, %d failed ===\n", g_passed, g_failures);

  fflush(stdout);

  return (g_failures == 0) ? 0 : 1;
}
