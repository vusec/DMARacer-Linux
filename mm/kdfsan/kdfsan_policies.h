// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_POLICIES_H
#define KDFSAN_POLICIES_H

#include "kdfsan_types.h"

/******************************************************************************/

#if defined(CONFIG_KDFSAN_USERSPACE_POLICIES)
#define KDFSAN_POLICY_SYSCALL_ARG 1
#define KDFSAN_POLICY_IO 0
#define KDFSAN_POLICY_LOAD 1
#define KDFSAN_POLICY_STORE 0
#define KDFSAN_POLICY_COND_FWD 0
#define KDFSAN_POLICY_COND_BKWD 0
#define KDFSAN_POLICY_AND 0
#define KDFSAN_POLICY_BUGON 0
#define KDFSAN_POLICY_PER_DOMAIN 0
dfsan_label kdfsan_policies_get_getuser_label(void);
#elif defined(CONFIG_KDFSAN_DOUBLEFETCH_POLICIES)
#define KDFSAN_POLICY_SYSCALL_ARG 0
#define KDFSAN_POLICY_IO 1
#define KDFSAN_POLICY_LOAD 1
#define KDFSAN_POLICY_STORE 1
#define KDFSAN_POLICY_COND_FWD 0
#define KDFSAN_POLICY_COND_BKWD 1
#define KDFSAN_POLICY_AND 0
#define KDFSAN_POLICY_BUGON 1
#define KDFSAN_POLICY_PER_DOMAIN 1
bool kdfsan_policies_is_df_label(dfsan_label lbl);
#define KDF_DOUBLEFETCH_DMA_COHERENT 1
#define KDF_DOUBLEFETCH_DMA_STREAMING 1
#define KDF_DOUBLEFETCH_MMIO 0
#define KDF_DOUBLEFETCH_PMIO 0
#define KDF_DOUBLEFETCH_USER 0
#else
#define KDFSAN_POLICY_SYSCALL_ARG 0
#define KDFSAN_POLICY_IO 0
#define KDFSAN_POLICY_LOAD 0
#define KDFSAN_POLICY_STORE 0
#define KDFSAN_POLICY_COND_FWD 0
#define KDFSAN_POLICY_COND_BKWD 0
#define KDFSAN_POLICY_AND 0
#define KDFSAN_POLICY_BUGON 0
#define KDFSAN_POLICY_PER_DOMAIN 0
#endif

/******************************************************************************/

#if KDFSAN_POLICY_SYSCALL_ARG==1
void kdf_policies_syscall_arg(void * arg, size_t s, int arg_num);
#else
static inline void kdf_policies_syscall_arg(void * arg, size_t s, int arg_num) { }
#endif

#if KDFSAN_POLICY_IO==1
void kdf_policies_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma, void * rip);
void kdf_policies_dma_free(struct device *dev, dma_addr_t bus_addr);
void kdf_policies_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents, void * rip);
void kdf_policies_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents);
void kdf_policies_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu, void * rip);
void kdf_policies_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu, void * rip);
void kdf_policies_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size, void * rip);
void kdf_policies_iounmap(void __iomem *cpu_addr);
void kdf_policies_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * rip);
void kdf_policies_pmio_in(u16 port, size_t size, void * dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * rip);
#else
static inline void kdf_policies_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma, void * rip) { }
static inline void kdf_policies_dma_free(struct device *dev, dma_addr_t bus_addr) { }
static inline void kdf_policies_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents, void * rip) { }
static inline void kdf_policies_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents) { }
static inline void kdf_policies_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu, void * rip) { }
static inline void kdf_policies_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu, void * rip) { }
static inline void kdf_policies_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size, void * rip) { }
static inline void kdf_policies_iounmap(void __iomem *cpu_addr) { }
static inline void kdf_policies_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * rip) { }
static inline void kdf_policies_pmio_in(u16 port, size_t size, void * dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * rip) { }
#endif

#if KDFSAN_POLICY_LOAD==1
dfsan_label kdf_policies_load(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip);
#else
static inline dfsan_label kdf_policies_load(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) { return data_label; }
#endif

#if KDFSAN_POLICY_STORE==1
void kdf_policies_store(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip);
#else
static inline void kdf_policies_store(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) { }
#endif

#if KDFSAN_POLICY_COND_FWD==1
void kdf_policies_cond_fwd(dfsan_label label, void * rip);
#else
static inline void kdf_policies_cond_fwd(dfsan_label label, void * rip) { }
#endif

#if KDFSAN_POLICY_COND_BKWD==1
void kdf_policies_cond_bkwd(dfsan_label label, void * rip);
#else
static inline void kdf_policies_cond_bkwd(dfsan_label label, void * rip) { }
#endif

#if KDFSAN_POLICY_AND==1
void kdf_policies_and(dfsan_label l1, dfsan_label l2, void * rip);
#else
static inline void kdf_policies_and(dfsan_label l1, dfsan_label l2, void * rip) { }
#endif

#if KDFSAN_POLICY_BUGON==1
void kdf_policies_bugon(dfsan_label label, void * rip);
#else
static inline void kdf_policies_bugon(dfsan_label label, void * rip) { }
#endif

#if KDFSAN_POLICY_PER_DOMAIN==1
void kdf_policies_domain_enter(void);
void kdf_policies_domain_exit(void);
#else
static inline void kdf_policies_domain_enter(void) { }
static inline void kdf_policies_domain_exit(void) { }
#endif

void kdf_policies_init(void);
void kdf_policies_post_boot(void);

#endif // KDFSAN_POLICIES_H
