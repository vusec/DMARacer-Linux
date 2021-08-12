// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_WHITELIST_H
#define KDFSAN_WHITELIST_H

typedef enum {
  KDFSAN_WHITELIST_DISABLED = 'd',
  KDFSAN_WHITELIST_TASKNAME = 't',
  KDFSAN_WHITELIST_SYSCALLNR = 's'
} kdfsan_whitelist_type_t;

bool kdf_is_a_whitelist_type(char w);
bool kdfsan_is_whitelist_task(void);

#endif
