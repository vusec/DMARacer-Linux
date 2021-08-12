# SPDX-License-Identifier: GPL-2.0
obj-y := kdfsan_custom.o kdfsan_init.o kdfsan_interface.o kdfsan_internal.o kdfsan_mm.o kdfsan_shadow.o kdfsan_policies.o kdfsan_util.o kdfsan_whitelist.o

KASAN_SANITIZE := n
KMSAN_SANITIZE := n
KDFSAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n

# Disable instrumentation of KDFSAN runtime with other tools.
CC_FLAGS_KDFSAN_RUNTIME := -fno-stack-protector
CC_FLAGS_KDFSAN_RUNTIME += $(call cc-option,-fno-conserve-stack)
CC_FLAGS_KDFSAN_RUNTIME += -DDISABLE_BRANCH_PROFILING

# Disable ftrace to avoid recursion.
CFLAGS_REMOVE_kdfsan_custom.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_init.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_interface.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_internal.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_mm.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_policies.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_shadow.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_util.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kdfsan_whitelist.o = $(CC_FLAGS_FTRACE)

CFLAGS_kdfsan_custom.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_init.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_interface.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_internal.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_mm.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_policies.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_shadow.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_util.o := $(CC_FLAGS_KDFSAN_RUNTIME)
CFLAGS_kdfsan_whitelist.o := $(CC_FLAGS_KDFSAN_RUNTIME)

# TODO: Remove these
CFLAGS_REMOVE_kdfsan_internal.o += -Werror
CFLAGS_REMOVE_kdfsan_shadow.o += -Werror
CFLAGS_REMOVE_kdfsan_interface.o += -Werror
CFLAGS_REMOVE_kdfsan_policies.o += -Werror
