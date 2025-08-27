// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_util.h"
#include "kdfsan_interface.h"

static void *____dfsw___memcpy(void *dest, const void *src, size_t n, dfsan_label dest_label, dfsan_label src_label, dfsan_label n_label, dfsan_label *ret_label, void * rip) {
  void * ret_val = __memcpy(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_with_rip(dest, src, n, dest_label, src_label, n_label, rip);
  return ret_val;
}
void * noinline __dfsw___memcpy(void *dest, const void *src, size_t n, dfsan_label dest_label, dfsan_label src_label, dfsan_label n_label, dfsan_label *ret_label) {
  return ____dfsw___memcpy(dest, src, n, dest_label, src_label, n_label, ret_label, __builtin_return_address(0));
}
void * noinline __dfsw_memcpy(void *dest, const void *src, size_t n, dfsan_label dest_label, dfsan_label src_label, dfsan_label n_label, dfsan_label *ret_label) {
  return ____dfsw___memcpy(dest, src, n, dest_label, src_label, n_label, ret_label, __builtin_return_address(0));
}

static void *____dfsw___memset(void *ptr, int val, size_t n, dfsan_label ptr_label, dfsan_label val_label, dfsan_label n_label, dfsan_label *ret_label, void * rip) {
  void * ret_val = __memset(ptr, val, n);
  *ret_label = ptr_label;
  dfsan_store_with_rip(val, ptr, n, val_label, ptr_label, rip);
  return ret_val;
}
void * noinline __dfsw___memset(void *ptr, int val, size_t n, dfsan_label ptr_label, dfsan_label val_label, dfsan_label n_label, dfsan_label *ret_label) {
  return ____dfsw___memset(ptr, val, n, ptr_label, val_label, n_label, ret_label, __builtin_return_address(0));
}
void * noinline __dfsw_memset(void *ptr, int val, size_t n, dfsan_label ptr_label, dfsan_label val_label, dfsan_label n_label, dfsan_label *ret_label) {
  return ____dfsw___memset(ptr, val, n, ptr_label, val_label, n_label, ret_label, __builtin_return_address(0));
}

void * noinline __dfsw_memset16(uint16_t *s, uint16_t v, size_t count, dfsan_label s_label, dfsan_label v_label, dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset16(s, v, count);
  *ret_label = s_label;
  dfsan_store_with_rip(v, s, count * sizeof(uint16_t), v_label, s_label, __builtin_return_address(0));
  return ret_val;
}

void * noinline __dfsw_memset32(uint32_t *s, uint32_t v, size_t count, dfsan_label s_label, dfsan_label v_label, dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset32(s, v, count);
  *ret_label = s_label;
  dfsan_store_with_rip(v, s, count * sizeof(uint32_t), v_label, s_label, __builtin_return_address(0));
  return ret_val;
}

void * noinline __dfsw_memset64(uint64_t *s, uint64_t v, size_t count, dfsan_label s_label, dfsan_label v_label, dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset64(s, v, count);
  *ret_label = s_label;
  dfsan_store_with_rip(v, s, count * sizeof(uint64_t), v_label, s_label, __builtin_return_address(0));
  return ret_val;
}

void * noinline __dfsw___memmove(void *dest, const void *src, size_t n, dfsan_label dest_label, dfsan_label src_label, dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = __memmove(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_with_rip(dest, src, n, dest_label, src_label, n_label, __builtin_return_address(0));
  return ret_val;
}

char * noinline __dfsw_strcpy(char *dest, const char *src, dfsan_label dest_label, dfsan_label src_label, dfsan_label *ret_label) {
  char * ret_val = strcpy(dest, src);
  *ret_label = dest_label;
  dfsan_mem_transfer_with_rip(dest, src, kdf_util_strlen(src)+1, dest_label, src_label, 0, __builtin_return_address(0));
  return ret_val;
}

size_t noinline __dfsw_strlcat(char *dest, const char *src, size_t count, dfsan_label dest_label, dfsan_label src_label, dfsan_label count_label, dfsan_label *ret_label) {
  size_t dsize = kdf_util_strlen(dest);
  size_t len = kdf_util_strlen(src);
  size_t res = dsize + len;
  *ret_label = dfsan_union(dest_label, src_label);

  /* This would be a bug */
  BUG_ON(dsize >= count);

  dest += dsize;
  count -= dsize;
  if (len >= count)
  len = count-1;
  __memcpy(dest, src, len);
  dfsan_mem_transfer_with_rip(dest, src, len, dest_label, src_label, count_label, __builtin_return_address(0));
  dest[len] = 0;
  dfsan_set_label(0, &dest[len], sizeof(char)); // Not performing store policy for NULL terminator
  return res;
}

size_t noinline __dfsw_strlcpy(char *dest, const char *src, size_t size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, dfsan_label *ret_label) {
  size_t ret = kdf_util_strlen(src);
  *ret_label = src_label;

  if (size) {
    size_t len = (ret >= size) ? size - 1 : ret;
    dfsan_label len_label = (ret >= size) ? size_label : 0;
    __memcpy(dest, src, len);
    dfsan_mem_transfer_with_rip(dest, src, len, dest_label, src_label, len_label, __builtin_return_address(0));
    dest[len] = '\0';
    dfsan_set_label(0, &dest[len], sizeof(char)); // Not performing store policy for NULL terminator
  }
  return ret;
}

char *__dfsw_strnchr(const char *s, size_t count, int c, dfsan_label s_label, dfsan_label count_label, dfsan_label c_label, dfsan_label *ret_label) {
  while (count--) {
    if (*s == (char)c) {
      *ret_label = dfsan_read_label(s, sizeof(char));
      return (char *)s;
    }
    if (*s++ == '\0') {
      break;
    }
  }
  *ret_label = 0;
  return NULL;
}

char * noinline __dfsw_strreplace(char *s, char old, char new, dfsan_label s_label, dfsan_label old_label, dfsan_label new_label, dfsan_label *ret_label) {
  for (; *s; ++s) {
    if (*s == old) {
      *s = new;
      dfsan_store_with_rip(new, s, sizeof(char), new_label, s_label, __builtin_return_address(0));
    }
  }
  *ret_label = s_label;
  return s;
}

char *__dfsw_strsep(char **s, const char *ct, dfsan_label s_label, dfsan_label ct_label, dfsan_label *ret_label) {
  char *sbegin = *s;
  char *end;

  if (sbegin == NULL) {
    *ret_label = 0;
    return NULL;
  }

  end = kdf_util_strpbrk(sbegin, ct);
  if (end) {
    *end = '\0';
    dfsan_set_label(0, end, sizeof(char)); // Not performing store policy for NULL terminator
    end++;
  }
  *s = end;
  *ret_label = s_label;
  return sbegin;
}

char *__dfsw_strstr(const char *s1, const char *s2, dfsan_label s1_label, dfsan_label s2_label, dfsan_label *ret_label) {
  char * ret_val = strstr(s1, s2);
  if (ret_val == NULL) {
    *ret_label = 0;
  } else {
    *ret_label = s1_label;
  }
  return ret_val;
}
