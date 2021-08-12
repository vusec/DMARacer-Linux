// SPDX-License-Identifier: GPL-2.0

#ifndef LINUX_KDFSAN_H
#define LINUX_KDFSAN_H

#include <linux/types.h>
#include <linux/init.h>

struct page;
typedef unsigned long uptr;
typedef u16 dfsan_label;
struct device;
struct scatterlist;
struct task_struct;
#define KDF_DESC_LEN 150

#if !defined(KDFSAN_NO_RUNTIME) && defined(CONFIG_KDFSAN)
int kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t flags, int node);
void kdfsan_free_page(struct page *page, unsigned int order);
void kdfsan_split_page(struct page *page, unsigned int order);
void kdfsan_copy_page_shadow(struct page *dst, struct page *src);
void __init kdfsan_init_shadow(void);
void __init kdfsan_init_runtime(void);
void kdfsan_task_create(struct task_struct *task);
void __dfsan_mem_transfer(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label);
void __dfsan_mem_transfer_with_rip(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip);
void dfsan_set_label(dfsan_label label, void *addr, uptr size);
void dfsan_add_label(dfsan_label label_src, void *addr, uptr size);
dfsan_label dfsan_create_label(const char *desc, void *userdata);
int dfsan_has_label(dfsan_label label, dfsan_label elem);
dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc);
dfsan_label dfsan_get_label_with_desc(const char *desc);
size_t dfsan_get_label_descs(dfsan_label label, char descs_arr[][KDF_DESC_LEN], size_t descs_arr_size);
dfsan_label dfsan_get_label_count(void);
dfsan_label dfsan_read_label(const void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
dfsan_label dfsan_get_label(long data);
void kdfsan_syscall_arg(void * arg, size_t s, int arg_num);
void kdfsan_domain_enter(void);
void kdfsan_domain_exit(void);
#else
static inline int kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t flags, int node) { return 0; }
static inline void kdfsan_free_page(struct page *page, unsigned int order) { }
static inline void kdfsan_split_page(struct page *page, unsigned int order) { }
static inline void kdfsan_copy_page_shadow(struct page *dst, struct page *src) { }
static inline void __init kdfsan_init_shadow(void) { }
static inline void __init kdfsan_init_runtime(void) {}
static inline void kdfsan_task_create(struct task_struct *task) {}
static inline void __dfsan_mem_transfer(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label) { }
static inline void __dfsan_mem_transfer_with_rip(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip) { }
static inline void dfsan_set_label(dfsan_label label, void *addr, uptr size) { }
static inline void dfsan_add_label(dfsan_label label_src, void *addr, uptr size) { }
static inline dfsan_label dfsan_create_label(const char *desc, void *userdata) { return 0; }
static inline int dfsan_has_label(dfsan_label label, dfsan_label elem) { return 0; }
static inline dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc) { return 0; }
static inline dfsan_label dfsan_get_label_with_desc(const char *desc) { return 0; }
static inline size_t dfsan_get_label_descs(dfsan_label label, char descs_arr[][KDF_DESC_LEN], size_t descs_arr_size) { return 0; }
static inline dfsan_label dfsan_get_label_count(void) { return 0; }
static inline dfsan_label dfsan_read_label(const void *addr, uptr size) { return 0; }
static inline dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2) { return 0; }
static inline dfsan_label dfsan_get_label(long data) { return 0; }
static inline void kdfsan_syscall_arg(void * arg, size_t s, int arg_num) { }
static inline void kdfsan_domain_enter(void) { }
static inline void kdfsan_domain_exit(void) { }
#endif

#ifdef KDFSAN_CLEARTAINT
static __always_inline void dfsan_mem_transfer(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label) { dfsan_set_label(0, dest, size); }
static __always_inline void dfsan_mem_transfer_with_rip(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip) { dfsan_set_label(0, dest, size); }
#else
static __always_inline void dfsan_mem_transfer(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label) { __dfsan_mem_transfer(dest, src, size, dest_label, src_label, size_label); }
static __always_inline void dfsan_mem_transfer_with_rip(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip) { __dfsan_mem_transfer_with_rip(dest, src, size, dest_label, src_label, size_label, rip); }
#endif

#if !defined(KDFSAN_NO_RUNTIME) && defined(CONFIG_KDFSAN_DOUBLEFETCH_POLICIES)
void kdfsan_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma);
void kdfsan_dma_free(struct device *dev, dma_addr_t bus_addr);
void kdfsan_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents);
void kdfsan_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents);
void kdfsan_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu);
void kdfsan_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu);
void kdfsan_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size);
void kdfsan_iounmap(void __iomem *cpu_addr);
void kdfsan_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label);
void kdfsan_pmio_out_with_rip(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * caller_rip);
void kdfsan_pmio_in(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label);
void kdfsan_pmio_in_with_rip(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * caller_rip);
void kdfsan_bugon(dfsan_label label);
#else
static inline void kdfsan_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma) { }
static inline void kdfsan_dma_free(struct device *dev, dma_addr_t bus_addr) { }
static inline void kdfsan_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents) { }
static inline void kdfsan_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents) { }
static inline void kdfsan_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu) { }
static inline void kdfsan_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu) { }
static inline void kdfsan_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size) { }
static inline void kdfsan_iounmap(void __iomem *cpu_addr) { }
static inline void kdfsan_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label) { }
static inline void kdfsan_pmio_out_with_rip(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * caller_rip) { }
static inline void kdfsan_pmio_in(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label) { }
static inline void kdfsan_pmio_in_with_rip(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * caller_rip) { }
static inline void kdfsan_bugon(dfsan_label label) { }
#endif

#endif /* LINUX_KDFSAN_H */
