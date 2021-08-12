// SPDX-License-Identifier: GPL-2.0
// Shadow memory initialization based on KMSAN's

#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_shadow.h"
#include "kdfsan_policies.h"
#include "kdfsan_interface.h"
#include "kdfsan_whitelist.h"

#include <asm/sections.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/debugfs.h>

/*********************************************************************/
/************************** Early-boot shadow init *******************/

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
  void *start, *end;
};

static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
static int future_index __initdata;

/*
 * Record a range of memory for which the metadata pages will be created once
 * the page allocator becomes available.
 */
static void __init kdf_record_future_shadow_range(void *start, void *end) {
	u64 nstart = (u64)start, nend = (u64)end, cstart, cend;
	bool merged = false;

	KDF_PANIC_ON(future_index == NUM_FUTURE_RANGES, "KDFSan init error: check 1 in kdf_record_future_shadow_range failed");
	KDF_PANIC_ON((nstart >= nend) || !nstart || !nend, "KDFSan init error: check 2 in kdf_record_future_shadow_range failed");
	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
	nend = ALIGN(nend, PAGE_SIZE);

	/*
	 * Scan the existing ranges to see if any of them overlaps with
	 * [start, end). In that case, merge the two ranges instead of
	 * creating a new one.
	 * The number of ranges is less than 20, so there is no need to organize
	 * them into a more intelligent data structure.
	 */
	for (int i = 0; i < future_index; i++) {
		cstart = (u64)start_end_pairs[i].start;
		cend = (u64)start_end_pairs[i].end;
		if ((cstart < nstart && cend < nstart) ||
		    (cstart > nend && cend > nend))
			/* ranges are disjoint - do not merge */
			continue;
		start_end_pairs[i].start = (void *)min(nstart, cstart);
		start_end_pairs[i].end = (void *)max(nend, cend);
		merged = true;
		break;
	}
	if (merged)
		return;
        printk("%s: recording region %px-%px\n", __func__, start, end);
	start_end_pairs[future_index].start = (void *)nstart;
	start_end_pairs[future_index].end = (void *)nend;
	future_index++;
}

/* Allocate metadata for pages allocated at boot time. */
static void __init kdf_init_alloc_meta_for_range(void *start, void *end) {
  u64 addr, size;
  struct page *page;
  void *shadow;
  struct page *shadow_p;
  printk("%s: Initializing region %px-%px\n",__func__,start,end);
  // FIXME: Potential bug -- If a range is in the same region as another range, then it will have >1 shadow page allocated for it
  printk("Initializing shadow for region at %px-%px\n", start, end);
  start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
  size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
  shadow = memblock_alloc(size, PAGE_SIZE);
  for (addr = 0; addr < size; addr += PAGE_SIZE) {
    page = kdf_virt_to_page_or_null((char *)start + addr);
    if (page == NULL) { panic("Cannot get page struct for memory at %px.\n", (char *)start + addr); }
    shadow_p = kdf_virt_to_page_or_null((char *)shadow + addr);
    if (shadow_p == NULL) { panic("Cannot get page struct for shadow memory at %px...\n", (char *)shadow + addr); }
    shadow_p->shadow = NULL;
    page->shadow = shadow_p;
  }
}

/*
 * Initialize the shadow for existing mappings during kernel initialization.
 * These include kernel text/data sections, NODE_DATA and future ranges
 * registered while creating other data (e.g. percpu).
 *
 * Allocations via memblock can be only done before slab is initialized.
 */
void __init kdfsan_init_shadow(void) {
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	phys_addr_t p_start, p_end;
	u64 loop;
	int nid;

        printk("KDFSan: Initializing shadow...\n");

        printk("%s: recording all reserved memblock regions...\n",__func__);
	for_each_reserved_mem_range(loop, &p_start, &p_end)
		kdf_record_future_shadow_range(phys_to_virt(p_start),
						 phys_to_virt(p_end));

        printk("%s: recording .data region...\n",__func__);
	/* Allocate shadow for .data */
	kdf_record_future_shadow_range(_sdata, _edata);

        printk("%s: recording all online nodes regions...\n",__func__);
	for_each_online_node(nid)
		kdf_record_future_shadow_range(
			NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);

        printk("%s: allocating %d ranges...\n",__func__,future_index);
	for (int i = 0; i < future_index; i++)
		kdf_init_alloc_meta_for_range(
			(void *)start_end_pairs[i].start,
			(void *)start_end_pairs[i].end);
        printk("KDFSan: Shadow initialized.\n");
}

/********************************************************************/
/************************** Kernel parameters ***********************/

// NOTE: Need __read_mostly or else these will land in .bss!
bool __read_mostly kdf_param_run_tests = false;
bool __read_mostly kdf_param_early_enable = false;
bool __read_mostly kdf_param_generic_syscall_label = false;
kdfsan_whitelist_type_t __read_mostly kdf_param_whitelist = KDFSAN_WHITELIST_TASKNAME;

static int __init kdf_param_run_tests_handler(char *str) { kdf_param_run_tests = simple_strtol(str, NULL, 0); return 1; }
static int __init kdf_param_early_enable_handler(char *str) { kdf_param_early_enable = simple_strtol(str, NULL, 0); return 1; }
static int __init kdf_param_generic_syscall_label_handler(char *str) { kdf_param_generic_syscall_label = simple_strtol(str, NULL, 0); return 1; }
static int __init kdf_param_whitelist_handler(char *str) {
  KDF_PANIC_ON(strlen(str) != 1, "KDFSan error: kdf_param_whitelist should be a single character");
  char w = str[0];
  KDF_PANIC_ON(!kdf_is_a_whitelist_type(w), "KDFSan error: Unsupported kdf_param_whitelist type");
  kdf_param_whitelist = w;
  return 1;
}

__setup("kdf_param_run_tests=", kdf_param_run_tests_handler);
__setup("kdf_param_early_enable=", kdf_param_early_enable_handler);
__setup("kdf_param_generic_syscall_label=", kdf_param_generic_syscall_label_handler);
__setup("kdf_param_whitelist=", kdf_param_whitelist_handler);

/**********************************************************************/
/************************** Enable and tests **************************/

void kdfsan_run_base_tests(void);
void kdfsan_run_policies_tests(void);

// Warning: SUPER janky code to get the tests to work with task whitelisting
#define SET_WHITELIST_TASK() \
  char _saved_str[TASK_COMM_LEN]; \
  if (kdf_param_whitelist == KDFSAN_WHITELIST_TASKNAME) { \
    kdf_util_strlcpy(_saved_str, current->comm, TASK_COMM_LEN); \
    kdf_util_strlcpy(current->comm, "kdfsan_task", TASK_COMM_LEN); \
  }
#define RESET_TASK() \
  if (kdf_param_whitelist == KDFSAN_WHITELIST_TASKNAME) kdf_util_strlcpy(current->comm, _saved_str, TASK_COMM_LEN);

static void kdfsan_base_tests(void) {
  if (kdf_param_run_tests) {
    unsigned long ini = 0, end = 0;
    printk("KDFSan: Running KDFSan base tests...\n");
    ini=get_cycles(); kdfsan_run_base_tests(); end=get_cycles();
    printk("KDFSan: KDFSan base tests complete (%liM cycles elapsed)", (end-ini)/1000000);
  }
}

static void kdfsan_policies_tests(void) {
  if (kdf_param_run_tests) {
    unsigned long ini = 0, end = 0;
    SET_WHITELIST_TASK();
    printk("KDFSan: Running KDFSan policies tests...\n");
    ini=get_cycles(); kdfsan_run_policies_tests(); end=get_cycles();
    printk("KDFSan: KDFSan policies tests complete (%liM cycles elapsed)", (end-ini)/1000000);
    RESET_TASK();
  }
}

static void kdfsan_enable(void) {
  printk("KDFSan: Enabling...\n");
  kdf_enable();
}

/********************************************************************/
/************************** Early-boot runtime init *****************/

void __init kdfsan_init_runtime(void) {
  printk("KDFSan: Initializing internal data...\n");
  kdf_internal_task_create(current);
  kdf_init_internal_data();

  printk("KDFSan: Initializing custom tainting policies...\n");
  kdf_policies_init();

  printk("KDFSan: Initialization done.\n");
  kdfsan_domain_enter();
  if (kdf_param_early_enable) {
    kdfsan_enable();
    kdfsan_base_tests();
    // Not running the policies tests because userspace/drivers/etc. haven't been initialized yet.
  }
}

/********************************************************************/
/************************** Late-boot debugfs init ******************/

static int kdfsan_post_boot(void *data, u64 *val);
DEFINE_DEBUGFS_ATTRIBUTE(kdfsan_post_boot_fops, kdfsan_post_boot, NULL, "%lld\n");

int __init kdfsan_init_late(void) {
  printk("KDFSan: Initializing debugfs...\n");
  struct dentry *kdfsan_dir  = debugfs_create_dir("kdfsan", NULL);
  debugfs_create_file("post_boot", 0444, kdfsan_dir, NULL, &kdfsan_post_boot_fops);
  printk("KDFSan: Late initialization done.\n");
  return 0;
}
postcore_initcall(kdfsan_init_late);

/**********************************************************************/
/************************** Post-boot *********************************/

static int kdfsan_post_boot(void *data, u64 *val) {
  printk("KDFSan: Post boot...\n");
  kdf_policies_post_boot();
  if (!kdf_enabled()) {
    kdfsan_enable();
    kdfsan_base_tests();
    kdfsan_policies_tests();
  }
  printk("KDFSan: Post boot done.\n");
  return 0;
}
