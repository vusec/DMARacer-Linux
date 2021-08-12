// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_INTERNAL_H
#define KDFSAN_INTERNAL_H

#include "kdfsan_types.h"
#include "kdfsan_whitelist.h"
#include "kdfsan_interface.h"

void kdf_memtransfer(void *dst, const void *src, uptr count, dfsan_label dst_label, dfsan_label src_label, void * rip, bool perform_policies);
void kdf_set_label(dfsan_label label, void *addr, uptr size);
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2);
dfsan_label kdf_union_read_label(const void *addr, uptr n);
void kdf_add_label(dfsan_label label_src, void *addr, uptr size);
dfsan_label kdf_create_label(const char *desc); // userdata decprecated
int kdf_has_label(dfsan_label label, dfsan_label elem);
dfsan_label kdf_has_label_with_desc(dfsan_label label, const char *desc);
dfsan_label kdf_get_label_with_desc(const char *desc);
size_t kdf_get_label_descs(dfsan_label label, char descs_arr[][KDF_DESC_LEN], size_t descs_arr_size);
dfsan_label kdf_read_label(const void *addr, uptr size);
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2);
void kdf_print_label_info(dfsan_label lbl, const bool line_cont);
void kdf_copy_label_info(dfsan_label label, char * dest, size_t count);
void kdf_init_internal_data(void);
void kdf_internal_task_create(struct task_struct *task);

/*
 * KDFSAN performs a lot of consistency checks that are currently enabled by
 * default. BUG_ON is normally discouraged in the kernel, unless used for
 * debugging, but KMSAN itself is a debugging tool, so it makes little sense to
 * recover if something goes wrong.
 */
#define KDFSAN_WARN_ON(cond)                                          \
	({                                                            \
		const bool __cond = WARN_ON(cond);                    \
		if (unlikely(__cond)) {                               \
			kdf_kill();                                   \
			if (true) {                                   \
				/* Can't call panic() here because */ \
				/* of uaccess checks. */              \
				BUG();                                \
			}                                             \
		}                                                     \
		__cond;                                               \
	})

#endif // KDFSAN_INTERNAL_H
