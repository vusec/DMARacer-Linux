// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_INTERFACE_H
#define KDFSAN_INTERFACE_H

void kdf_enable(void);
bool kdf_enabled(void);
void kdf_kill(void);
struct kdfsan_ctx *kdfsan_get_context(void);
void dfsan_store_with_rip(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip);

#endif // KDFSAN_INTERFACE_H
