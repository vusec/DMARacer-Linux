/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SHARED_IO_H
#define _ASM_X86_SHARED_IO_H

#include <linux/types.h>
#include <linux/kdfsan.h>

#define BUILDIO(bwl, bw, type)						\
static __always_inline void __out##bwl(type value, u16 port)		\
{									\
	asm volatile("out" #bwl " %" #bw "0, %w1"			\
		     : : "a"(value), "Nd"(port));			\
	kdfsan_pmio_out(&value, port, sizeof(type), dfsan_get_label(value), dfsan_get_label(port), 0);	\
}									\
									\
static __always_inline void __out##bwl##_ret(type value, u16 port)	\
{									\
	asm volatile("out" #bwl " %" #bw "0, %w1"			\
		     : : "a"(value), "Nd"(port));			\
	kdfsan_pmio_out_with_rip(&value, port, sizeof(type), dfsan_get_label(value), dfsan_get_label(port), 0, __builtin_return_address(0));	\
}									\
									\
static __always_inline type __in##bwl(u16 port)				\
{									\
	type value;							\
	asm volatile("in" #bwl " %w1, %" #bw "0"			\
		     : "=a"(value) : "Nd"(port));			\
	kdfsan_pmio_in(port, sizeof(type), &value, dfsan_get_label(port), 0, 0);	\
	return value;							\
}									\
									\
static __always_inline type __in##bwl##_ret(u16 port)			\
{									\
	type value;							\
	asm volatile("in" #bwl " %w1, %" #bw "0"			\
		     : "=a"(value) : "Nd"(port));			\
	kdfsan_pmio_in_with_rip(port, sizeof(type), &value, dfsan_get_label(port), 0, 0, __builtin_return_address(0));	\
	return value;							\
}

BUILDIO(b, b, u8)
BUILDIO(w, w, u16)
BUILDIO(l,  , u32)
#undef BUILDIO

#define inb __inb
#define inw __inw
#define inl __inl
#define outb __outb
#define outw __outw
#define outl __outl

#endif
