// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"

size_t kdf_util_strlen(const char *s) {
  const char *sc;
  for (sc = s; *sc != '\0'; ++sc) { ; }
  return sc - s;
}

int kdf_util_strncmp(const char *cs, const char *ct, int count) {
  unsigned char c1, c2;
  while (count) {
    c1 = *cs++;
    c2 = *ct++;
    if (c1 != c2) {
      return c1 < c2 ? -1 : 1;
    }
    if (!c1) {
      break;
    }
    count--;
  }
  return 0;
}

size_t kdf_util_strlcat(char *dest, const char *src, size_t count) {
  size_t dsize = kdf_util_strlen(dest);
  size_t len = kdf_util_strlen(src);
  size_t res = dsize + len;
  BUG_ON(dsize >= count); // This would be a bug
  dest += dsize;
  count -= dsize;
  if (len >= count) { len = count-1; }
  __memcpy(dest, src, len);
  dest[len] = 0;
  return res;
}

static void kdf_util_reverse_str(char str[], int length) {
  int start = 0;
  int end = length -1;
  while (start < end) {
    char tmp = *(str+end);
    *(str+end) = *(str+start);
    *(str+start) = tmp;
    start++;
    end--;
  }
}

char* kdf_util_itoa(long long num, char* str, int base) {
  int i = 0;
  bool is_negative = false;
  if (num == 0) {
    str[i++] = '0';
    str[i] = '\0';
    return str;
  }
  if (num < 0 && base == 10) {
    is_negative = true;
    num = -num;
  }
  while (num != 0) {
    int rem = num % base;
    str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
    num = num/base;
  }
  if (is_negative) { str[i++] = '-'; }
  str[i] = '\0';
  kdf_util_reverse_str(str, i);
  return str;
}

size_t kdf_util_strlcpy(char *dest, const char *src, size_t size) {
  size_t ret = kdf_util_strlen(src);
  if (size) {
    size_t len = (ret >= size) ? size - 1 : ret;
    __memcpy(dest, src, len);
    dest[len] = '\0';
  }
  return ret;
}

int kdf_util_memcmp(const void *cs, const void *ct, size_t count) {
  const unsigned char *su1, *su2;
  int res = 0;
  for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
  if ((res = *su1 - *su2) != 0)
    break;
  return res;
}

int kdf_util_strcmp(const char *cs, const char *ct) {
  unsigned char c1, c2;
  while (1) {
    c1 = *cs++;
    c2 = *ct++;
    if (c1 != c2)
      return c1 < c2 ? -1 : 1;
    if (!c1)
      break;
  }
  return 0;
}

char *kdf_util_strpbrk(const char *cs, const char *ct) {
  const char *sc1, *sc2;

  for (sc1 = cs; *sc1 != '\0'; ++sc1) {
    for (sc2 = ct; *sc2 != '\0'; ++sc2) {
      if (*sc1 == *sc2)
        return (char *)sc1;
      }
    }
  return NULL;
}

/* We could add a skipnr arg to kdf_util_bt_handle(), and pass that to arg 3 of stack_trace_save()...
 * However, that'd require maintaining different skipnr values for the store hooks, the load hooks, etc.
 * Moreover, after any changes to the KDFSAN runtime library, we'd have to check whether the skipnr values are still accurate.
 * Instead, let's just use skipnr=0, and fix this (i.e., remove the parts of the callstack in KDFSAN) when post-processing the reports. */
depot_stack_handle_t kdf_util_bt_handle(void) {
  unsigned long entries[128];
  unsigned int num_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
  return stack_depot_save(entries, num_entries, GFP_KERNEL);
}

// Returns string length
size_t kdf_util_bt_str(char * str, size_t size, depot_stack_handle_t bt_handle) {
  KDF_PANIC_ON(size < 4096, "Need a larger string for a backtrace."); // Should add better size checks
  unsigned long *entries;
  size_t len = 0;
  unsigned int num_entries = stack_depot_fetch(bt_handle, &entries);

  len += sprintf(str+len, "[");
  if (num_entries > 0) len += sprintf(str+len, "\"%pS\"", entries[0]);
  for (int i = 1; i < num_entries; i++) len += sprintf(str+len, ", \"%pS\"", entries[i]);
  len += sprintf(str+len, "]");
  return len;
}

noinline unsigned long kdf_util_syscall_get_nr(void) {
  return syscall_get_nr(current, task_pt_regs(current));
}

#define TIME_STRING_LEN 64
static char time_str[TIME_STRING_LEN];
void kdf_util_set_time_str(void) {
  struct timespec64 ts;
  struct tm tm;
  ktime_get_real_ts64(&ts); // Get the current time
  time64_to_tm(ts.tv_sec, 0, &tm); // Convert to calendar time
  snprintf(time_str, TIME_STRING_LEN, "%04ld-%02d-%02d_%02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
const char * kdf_util_get_time_str(void) { return time_str; }

static unsigned long random_number;
void kdf_util_set_rand(void) { get_random_bytes(&random_number, sizeof(random_number)); }
unsigned long kdf_util_get_rand(void) { return random_number; }

// Specific to x86-64 with 4-level page tables
bool kdf_is_kernel_ptr(u64 addr) {
  return (addr >= 0xffff888000000000ULL && addr <= 0xffffc87fffffffffULL)  /* direct map */
      || (addr >= 0xffffc90000000000ULL && addr <= 0xffffe8ffffffffffULL)  /* vmalloc */
      || (addr >= 0xffffea0000000000ULL && addr <= 0xffffeaffffffffffULL)  /* virtual map */
      || (addr >= 0xfffffe0000000000ULL && addr <= 0xfffffeffffffffffULL)  /* cpu_entry_area map */
      || (addr >= 0xffffff0000000000ULL && addr <= 0xffffff7fffffffffULL)  /* %esp fixup stacks */
      || (addr >= 0xffffffef00000000ULL && addr <= 0xfffffffeffffffffULL)  /* EFI region map */
      || (addr >= 0xffffffff80000000ULL && addr <= 0xfffffffffeffffffULL); /* kernel text map, module map */
}