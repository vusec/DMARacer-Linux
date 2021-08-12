// SPDX-License-Identifier: GPL-2.0

#ifndef LINUX_KDFSAN_TYPES_H
#define LINUX_KDFSAN_TYPES_H

#include <linux/kdfsan.h>
#include <linux/maple_tree.h>

static const uptr INTERNAL_LABEL_LOG_BIT_WIDTH = 3; // {0,1,2,3,4} <--- CHANGE THIS TO ADJUST SHADOW MEM SIZE
static const uptr INTERNAL_LABEL_BIT_WIDTH = (1 << INTERNAL_LABEL_LOG_BIT_WIDTH); // {1,2,4,8,16}
static const uptr NUM_LABELS = (1 << INTERNAL_LABEL_BIT_WIDTH); // {0x2,0x4,0x10,0x100,0x10000}
static const uptr INTERNAL_LABEL_ADDR_MASK = (INTERNAL_LABEL_LOG_BIT_WIDTH < 4) ? (1<<(3-INTERNAL_LABEL_LOG_BIT_WIDTH))-1 : 0; // {0x7,0x3,0x1,0x0,0x0}
static const uptr INTERNAL_LABEL_MASK = (NUM_LABELS - 1); // {0x1,0x3,0xf,0xff,0xffff}

// TODO: Set these based on the policy specified by the KDFSAN pass. For now, just use the default settings.
static const bool PROPAGATE_STORE_PTR = false;
static const bool PROPAGATE_LOAD_PTR = true;

/* KDFSAN argument and retval context structs. */
#define KDFSAN_PARAM_SIZE 64

struct kdfsan_context_state {
  dfsan_label __dfsan_retval_tls;
  dfsan_label __dfsan_arg_tls[KDFSAN_PARAM_SIZE];
};

static const uptr MAX_TOTAL_REPORTS = NUM_LABELS * 32; // This is arbitrary...
struct kdfsan_policies_state {
  bool initialized;
  struct maple_tree fetches;
  struct maple_tree fetch_ptrs; // Janky way of tracking pointers in the fetches tree, so we can just free all of them when exiting the domain
  bool reports_covered[MAX_TOTAL_REPORTS];
};

struct kdfsan_ctx {
  struct kdfsan_context_state cstate;
  int kdfsan_in_runtime;
  bool allow_reporting; // TODO for future use
  struct kdfsan_policies_state pstate;
};

#endif /* LINUX_KDFSAN_TYPES_H */
