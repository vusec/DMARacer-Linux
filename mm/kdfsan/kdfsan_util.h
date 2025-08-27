// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_UTIL_H
#define KDFSAN_UTIL_H

size_t kdf_util_strlen(const char *s);
int kdf_util_strncmp(const char *cs, const char *ct, int count);
size_t kdf_util_strlcat(char *dest, const char *src, size_t count);
char* kdf_util_itoa(long long num, char* str, int base);
size_t kdf_util_strlcpy(char *dest, const char *src, size_t size);
int kdf_util_memcmp (const void *cs, const void *ct, size_t count);
int kdf_util_strcmp(const char *cs, const char *ct);
char *kdf_util_strpbrk(const char *cs, const char *ct);
depot_stack_handle_t kdf_util_bt_handle(void);
size_t kdf_util_bt_str(char * str, size_t size, depot_stack_handle_t bt_handle);
unsigned long kdf_util_syscall_get_nr(void);
void kdf_util_set_time_str(void);
const char * kdf_util_get_time_str(void);
void kdf_util_set_rand(void);
unsigned long kdf_util_get_rand(void);
bool kdf_is_kernel_ptr(u64 addr);

#define CONCAT_STR(SRC,DEST,COUNT) \
  do { kdf_util_strlcat(DEST, SRC, COUNT); } while(0)
#define CONCAT_NUM(NUM,BASE,DEST,COUNT) \
  do { char __tmp_num_str[32]; \
  __memset(__tmp_num_str,0,32); \
  kdf_util_itoa(NUM, __tmp_num_str, BASE); \
  CONCAT_STR(__tmp_num_str,DEST,COUNT); } while(0)

#endif