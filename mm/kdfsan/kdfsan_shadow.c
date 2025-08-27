// SPDX-License-Identifier: GPL-2.0
// Shadow memory hooks based on KMSAN's

#include "kdfsan_types.h"

/*************************************************************************/
/********************** Valid virtual address check **********************/

#if defined(CONFIG_X86)

static inline int kdf_phys_addr_valid(resource_size_t addr) {
#ifdef CONFIG_PHYS_ADDR_T_64BIT
  return !(addr >> boot_cpu_data.x86_phys_bits);
#else
  return 1;
#endif
}

/*
 * Dummy load and store pages to be used when the real metadata is unavailable.
 * There are separate pages for loads and stores, so that every load returns a
 * zero, and every store doesn't affect other loads.
 */
static char dummy_load_page[PAGE_SIZE] __aligned(PAGE_SIZE);
static char dummy_store_page[PAGE_SIZE] __aligned(PAGE_SIZE);

static inline bool kdfsan_internal_is_module_addr(void *vaddr)
{
	return ((u64)vaddr >= MODULES_VADDR) && ((u64)vaddr < MODULES_END);
}

static inline bool kdfsan_internal_is_vmalloc_addr(void *addr)
{
	return ((u64)addr >= VMALLOC_START) && ((u64)addr < VMALLOC_END);
}

static bool kdf_virt_addr_valid(void *addr) {
  unsigned long x = (unsigned long)addr;
  unsigned long y = x - __START_KERNEL_map;

  if (unlikely(x > y)) {
    x = y + phys_base;
    if (y >= KERNEL_IMAGE_SIZE) return false;
  }
  else {
    x = y + (__START_KERNEL_map - PAGE_OFFSET);
    if ((x > y) || !kdf_phys_addr_valid(x)) return false;
  }

  return pfn_valid(x >> PAGE_SHIFT);
}

#elif defined(CONFIG_ARM64)

static bool kdf_virt_addr_valid(void *addr) {
  return virt_addr_valid(addr);
}

#endif

struct page *kdf_virt_to_page_or_null(void *vaddr) {
  if (vaddr < PAGE_OFFSET) return NULL;
  if (kdf_virt_addr_valid(vaddr)) return virt_to_page(vaddr);
  if (kdf_virt_addr_valid(__va(__pa(vaddr)))) return virt_to_page(__va(__pa(vaddr)));
  else return NULL;
}

/*****************************************************************************/
/************************** Shadow accessor helpers **************************/

dfsan_label *get_shadow_addr(const u8 *ptr) {
  uptr addr = (uptr) ptr;
  struct page *page = NULL;
  //uptr aligned_addr = 0;
  uptr shadow_offset = 0;
  void *shadow_base = NULL;
  dfsan_label *shadow_addr = NULL;

  if (kdfsan_internal_is_vmalloc_addr((void*)ptr) ||
	kdfsan_internal_is_module_addr((void*)ptr))
		return (void *)NULL;

  page = kdf_virt_to_page_or_null((void*)ptr);
  if (page == NULL) {
    //printk("get_shadow_addr: NO PAGE EXISTS FOR VADDR %px\n",ptr);
    return NULL;
  }
  if (page->shadow == NULL) {
    //printk("get_shadow_addr: NO SHADOW EXISTS FOR PAGE AT %px (VADDR: %px)\n",page,ptr);
    return NULL;
  }

  shadow_offset = (addr % PAGE_SIZE);
  shadow_base = page_address(page->shadow);
  shadow_addr = shadow_base + shadow_offset;
  return shadow_addr;
}

static uptr get_internal_label_offset(const u8 *ptr) {
  return (((uptr) ptr) & INTERNAL_LABEL_ADDR_MASK) * INTERNAL_LABEL_BIT_WIDTH;
}

/**********************************************************************/
/************************** Shadow accessors **************************/

dfsan_label kdf_get_shadow(const u8 *ptr) {
  dfsan_label mem_labels = 0, ret = 0, *sptr = NULL;
  sptr = get_shadow_addr(ptr);
  if(sptr == NULL) return 0;
  mem_labels = *sptr;
  ret = (dfsan_label) ((mem_labels >> get_internal_label_offset(ptr)) & INTERNAL_LABEL_MASK);
  //printk("----get_shadow: getting *shadow_of(%p) = *(%p) --> %04x (label in mem)     --> %x (single label)\n",ptr,sptr,mem_labels,ret);
  KDF_CHECK_LABEL(ret);
  return ret;
}

void kdf_set_shadow(const u8 *ptr, dfsan_label label) {
  KDF_CHECK_LABEL(label);
  dfsan_label old_labels = 0, new_label = 0, *sptr = NULL;
  sptr = get_shadow_addr(ptr);
  if(sptr == NULL) return;
  old_labels = *sptr;
  new_label = (old_labels & ~(INTERNAL_LABEL_MASK << get_internal_label_offset(ptr))) | ((label & INTERNAL_LABEL_MASK) << get_internal_label_offset(ptr));
  //printk("----set_shadow: setting *shadow_of(%p) = *(%p) <-- %04x (new label in mem) <-- %x (single label); was %04x\n",ptr,sptr,new_label,label,old_labels);
  *sptr = new_label;
}
