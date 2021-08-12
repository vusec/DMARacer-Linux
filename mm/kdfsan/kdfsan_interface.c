// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_mm.h"
#include "kdfsan_policies.h"
#include "kdfsan_whitelist.h"

/************************************************************/
/********************** Interface data **********************/

DEFINE_PER_CPU(struct kdfsan_ctx, kdfsan_percpu_ctx);

// NOTE: Need __read_mostly or else this will land in .bss!
static bool __read_mostly kdfsan_enabled = false;

/***********************************************************/
/********* Enter/leave guards for run-time library *********/

void kdf_enable(void) { kdfsan_enabled = true; }
bool kdf_enabled(void) { return kdfsan_enabled; }
void kdf_kill(void) { kdfsan_enabled = false; }

struct kdfsan_ctx *kdfsan_get_context(void) {
  return in_task() ? &current->kdfsan_ctx : raw_cpu_ptr(&kdfsan_percpu_ctx);
}

static bool kdfsan_in_runtime(void) {
  if ((hardirq_count() >> HARDIRQ_SHIFT) > 1) return true;
  if (in_nmi()) return true;
  return kdfsan_get_context()->kdfsan_in_runtime;
}

static void kdfsan_enter_runtime(void) {
  struct kdfsan_ctx *ctx;
  ctx = kdfsan_get_context();
  KDFSAN_WARN_ON(ctx->kdfsan_in_runtime < 0);
  ctx->kdfsan_in_runtime++;
}

static void kdfsan_leave_runtime(void) {
  struct kdfsan_ctx *ctx = kdfsan_get_context();
  KDFSAN_WARN_ON(ctx->kdfsan_in_runtime < 0);
  ctx->kdfsan_in_runtime--;
}

/***********************************************************/
/*************** Interfaces inserted by pass ***************/

dfsan_label noinline __dfsan_read_label(const void *addr, uptr size) {
  if (size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  dfsan_label ret = kdf_read_label(addr,size);
  KDF_CHECK_LABEL(ret);
  kdfsan_leave_runtime();
  return ret;
}

void noinline __dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  if (size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  kdf_set_label(label,addr,size);
  kdfsan_leave_runtime();
}

dfsan_label noinline __dfsan_union(dfsan_label l1, dfsan_label l2) {
  if (l1 == 0) return l2;
  if (l2 == 0) return l1;
  if (l1 == l2) return l1;
  if (!kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(l1); KDF_CHECK_LABEL(l2);
  dfsan_label ret = kdf_union(l1,l2);
  KDF_CHECK_LABEL(ret);
  kdfsan_leave_runtime();
  return ret;
}

void noinline __dfsan_vararg_wrapper(const char *fname) {
  if (!kdfsan_enabled || kdfsan_in_runtime()) return;
  kdfsan_enter_runtime();
  printk("KDFSan ERROR: unsupported indirect call to vararg\n");
  kdfsan_leave_runtime();
}

/********************************************************************/
/*************** Callback interfaces inserted by pass ***************/

/* TODO: The KDFSAN pass _might_ need to be picky about which loads/stores to
 * check, similar to how KASAN only instruments "interesting" loads/stores. At
 * least for Kasper (where the KDFSAN pass runs after the KASAN pass), we only
 * inserted load/store callbacks for the accesses which were hooked by KASAN.
 * Otherwise, KDFSAN would instrument too many accesses, and result in a crash.
 */

// NOTE: Performs policies but NOT shadow operation or pointer propagation
dfsan_label noinline __dfsan_load_callback(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label) {
  if (size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return 0;
  if (!KDFSAN_POLICY_LOAD || !kdfsan_is_whitelist_task()) return data_label;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(data_label); KDF_CHECK_LABEL(ptr_label);
  dfsan_label ret = kdf_policies_load(addr, size, data_label, ptr_label, __builtin_return_address(0));
  kdfsan_leave_runtime();
  return ret;
}

// NOTE: Performs policies but NOT shadow operation or pointer propagation
void noinline __dfsan_store_callback(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label) {
  if (!KDFSAN_POLICY_STORE || size == 0 || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(data_label); KDF_CHECK_LABEL(ptr_label);
  kdf_policies_store(data, addr, size, data_label, ptr_label, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
// NOTE: Performs policies, shadow operation, and pointer propagation
void noinline dfsan_store_with_rip(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) {
  if (size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(data_label); KDF_CHECK_LABEL(ptr_label);
  if (kdfsan_is_whitelist_task()) kdf_policies_store(data, addr, size, data_label, ptr_label, __builtin_return_address(0)); // 1. Store policy
  data_label = PROPAGATE_STORE_PTR ? kdf_union(data_label, ptr_label) : data_label;                                         // 2. Store pointer propagation
  kdf_set_label(data_label, addr, size);                                                                                    // 3. Perform shadow store
  kdfsan_leave_runtime();
}

void noinline __dfsan_conditional_fwd_callback(dfsan_label label) {
  if (!KDFSAN_POLICY_COND_FWD || label == 0 || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  kdf_policies_cond_fwd(label, __builtin_return_address(0));
  kdfsan_leave_runtime();
}

void noinline __dfsan_conditional_bkwd_callback(dfsan_label label) {
  if (!KDFSAN_POLICY_COND_BKWD || label == 0 || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  kdf_policies_cond_bkwd(label, __builtin_return_address(0));
  kdfsan_leave_runtime();
}

// NOTE: Performs policies, shadow operation, and pointer propagation
static void dfsan_mem_transfer_internal(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip) {
  if (size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return;
  bool perform_policies = kdfsan_is_whitelist_task();
  kdfsan_enter_runtime();
  // NOTE: kdf_memtransfer() performs: (i) the shadow memtransfer; (ii) if perform_policies is set, the associated load/store policies; AND (iii) pointer propagation
  kdf_memtransfer(dest, src, size, dest_label, src_label, rip, perform_policies);
  kdfsan_leave_runtime();
}
void noinline __dfsan_mem_transfer_callback(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label) {
  dfsan_mem_transfer_internal(dest, src, size, dest_label, src_label, size_label, __builtin_return_address(0));
}

/* Add noinline function attribute if/when this callback does something interesting */
void __dfsan_cmp_callback(dfsan_label combined_label) { }

/* Add noinline function attribute if/when this callback does something interesting */
void __dfsan_conditional_callback(dfsan_label label) { }

dfsan_label noinline __dfsan_and_callback(dfsan_label l1, dfsan_label l2) {
  return 0; // Let's clear taint on 'and' instructions
}

/***************************************************************/
/*************** Interfaces not inserted by pass ***************/

void noinline dfsan_add_label(dfsan_label label_src, void *addr, uptr size) {
  if (size == 0 || label_src == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label_src);
  kdf_add_label(label_src,addr,size);
  kdfsan_leave_runtime();
}

// TODO: userdata unused; remove
dfsan_label noinline dfsan_create_label(const char *desc, void *userdata) {
  if (!kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  dfsan_label ret = kdf_create_label(desc);
  KDF_CHECK_LABEL(ret);
  kdfsan_leave_runtime();
  return ret;
}

int noinline dfsan_has_label(dfsan_label label, dfsan_label elem) {
  if (label == elem) return true;
  if (!kdfsan_enabled || kdfsan_in_runtime()) return false;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label); KDF_CHECK_LABEL(elem);
  int ret = kdf_has_label(label,elem);
  kdfsan_leave_runtime();
  return ret;
}

dfsan_label noinline dfsan_has_label_with_desc(dfsan_label label, const char *desc) {
  if (desc == NULL || !kdfsan_enabled || kdfsan_in_runtime()) return false;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  dfsan_label ret = kdf_has_label_with_desc(label,desc);
  KDF_CHECK_LABEL(ret);
  kdfsan_leave_runtime();
  return ret;
}

dfsan_label dfsan_get_label_with_desc(const char *desc) {
  if (desc == NULL || !kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  dfsan_label ret = kdf_get_label_with_desc(desc);
  KDF_CHECK_LABEL(ret);
  kdfsan_leave_runtime();
  return ret;
}

size_t dfsan_get_label_descs(dfsan_label label, char descs_arr[][KDF_DESC_LEN], size_t descs_arr_size) {
  if (label == 0 || descs_arr == NULL || descs_arr_size == 0 || !kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  size_t ret = kdf_get_label_descs(label, descs_arr, descs_arr_size);
  kdfsan_leave_runtime();
  return ret;
}

dfsan_label noinline dfsan_get_label_count(void) {
  if (!kdfsan_enabled || kdfsan_in_runtime()) return 0;
  kdfsan_enter_runtime();
  dfsan_label ret = kdf_get_label_count();
  kdfsan_leave_runtime();
  return ret;
}

dfsan_label noinline dfsan_read_label(const void *addr, uptr size) {
  return __dfsan_read_label(addr, size);
}

void noinline dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

dfsan_label noinline dfsan_union(dfsan_label l1, dfsan_label l2) {
  return __dfsan_union(l1,l2);
}

dfsan_label noinline __dfsw_dfsan_get_label(long data, dfsan_label data_label, dfsan_label *ret_label) {
  if (!kdfsan_enabled || kdfsan_in_runtime()) return 0;
  *ret_label = 0;
  return data_label;
}

// TODO: Improve KDFSAN instrumentation coverage so that this can be removed.
dfsan_label noinline dfsan_get_label(long data) { return 0; }

void noinline __dfsan_mem_transfer(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label) {
  dfsan_mem_transfer_internal(dest, src, size, dest_label, src_label, size_label, __builtin_return_address(0));
}
void noinline __dfsan_mem_transfer_with_rip(void *dest, const void *src, uptr size, dfsan_label dest_label, dfsan_label src_label, dfsan_label size_label, void * rip) {
  dfsan_mem_transfer_internal(dest, src, size, dest_label, src_label, size_label, rip);
}

/************************************************************/
/*************** Memory management interfaces ***************/

int noinline kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t orig_flags, int node) {
  int ret = kdf_alloc_page(page, order, orig_flags, node);
  return ret;
}

void noinline kdfsan_free_page(struct page *page, unsigned int order) {
  kdf_free_page(page, order);
}

void noinline kdfsan_split_page(struct page *page, unsigned int order) {
  kdf_split_page(page, order);
}

void noinline kdfsan_copy_page_shadow(struct page *dst, struct page *src) {
  kdf_copy_page_shadow(dst, src);
}

/********************************************************/
/*************** Miscellaneous interfaces ***************/

void noinline dfsan_copy_label_info(dfsan_label label, char * dest, size_t count) {
  if (!kdfsan_enabled || kdfsan_in_runtime()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  kdf_copy_label_info(label, dest, count);
  kdfsan_leave_runtime();
}

void noinline kdfsan_syscall_arg(void * arg, size_t s, int arg_num) {
  if (!KDFSAN_POLICY_SYSCALL_ARG || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  kdf_policies_syscall_arg(arg, s, arg_num);
  kdfsan_leave_runtime();
}

void kdfsan_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma) {
  kdfsan_enter_runtime();
  kdf_policies_dma_alloc(dev, bus_addr, cpu_addr, s, is_streaming_dma, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
void kdfsan_dma_free(struct device *dev, dma_addr_t bus_addr) {
  kdfsan_enter_runtime();
  kdf_policies_dma_free(dev, bus_addr);
  kdfsan_leave_runtime();
}
void kdfsan_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents) {
  kdfsan_enter_runtime();
  kdf_policies_dma_alloc_sg(dev, sg, ents, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
void kdfsan_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents) {
  kdfsan_enter_runtime();
  kdf_policies_dma_free_sg(dev, sg, nents);
  kdfsan_leave_runtime();
}
void kdfsan_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu) {
  kdfsan_enter_runtime();
  kdf_policies_dma_sync(dev, addr, size, is_for_cpu, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
void kdfsan_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu) {
  kdfsan_enter_runtime();
  kdf_policies_dma_sync_sg(dev, sg, nelems, is_for_cpu, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
void kdfsan_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size) {
  kdfsan_enter_runtime();
  kdf_policies_ioremap(bus_addr, cpu_addr, size, __builtin_return_address(0));
  kdfsan_leave_runtime();
}
void kdfsan_iounmap(void __iomem *cpu_addr) {
  kdfsan_enter_runtime();
  kdf_policies_iounmap(cpu_addr);
  kdfsan_leave_runtime();
}

void kdfsan_pmio_out_with_rip(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * caller_rip) {
  if (!KDFSAN_POLICY_IO || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  kdf_policies_pmio_out(src, port, size, src_label, port_label, size_label, caller_rip);
  kdfsan_leave_runtime();
}
void kdfsan_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label) {
  kdfsan_pmio_out_with_rip(src, port, size, src_label, port_label, size_label, __builtin_return_address(0));
}

void kdfsan_pmio_in_with_rip(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * caller_rip) {
  if (!KDFSAN_POLICY_IO || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  kdf_policies_pmio_in(port, size, dest, port_label, size_label, dest_label, caller_rip);
  kdfsan_leave_runtime();
}
void kdfsan_pmio_in(u16 port, size_t size, void *dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label) {
  kdfsan_pmio_in_with_rip(port, size, dest, port_label, size_label, dest_label, __builtin_return_address(0));
}

void kdfsan_bugon(dfsan_label label) {
  if (!KDFSAN_POLICY_BUGON || label == 0 || !kdfsan_enabled || kdfsan_in_runtime() || !kdfsan_is_whitelist_task()) return;
  kdfsan_enter_runtime();
  KDF_CHECK_LABEL(label);
  kdf_policies_bugon(label, __builtin_return_address(0));
  kdfsan_leave_runtime();
}

void kdfsan_domain_enter(void) {
  kdfsan_enter_runtime();
  kdf_policies_domain_enter();
  kdfsan_leave_runtime();
}

void kdfsan_domain_exit(void) {
  kdfsan_enter_runtime();
  kdf_policies_domain_exit();
  kdfsan_leave_runtime();
}

struct kdfsan_context_state *__dfsan_get_context_state(void) {
  return &kdfsan_get_context()->cstate;
}
EXPORT_SYMBOL(__dfsan_get_context_state);

void kdfsan_task_create(struct task_struct *task) {
  kdfsan_enter_runtime();
  kdf_internal_task_create(task);
  kdfsan_leave_runtime();
}
