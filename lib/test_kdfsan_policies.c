// SPDX-License-Identifier: GPL-2.0

#include <linux/kdfsan.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/skbuff.h>
#include "../mm/kdfsan/kdfsan_policies.h"

/******************************************************************************/
/* Test helpers */
/******************************************************************************/

static bool kdf_tests_fail = false;

#define TEST_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)

#define ASSERT(x) \
do {    if (x) break; \
        printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n", \
               __FILE__, __func__, __LINE__, #x); \
        kdf_tests_fail = true;  \
} while (0)

/******************************************************************************/
/* Userspace tests */
/******************************************************************************/

#ifdef CONFIG_KDFSAN_USERSPACE_POLICIES

/************************************/
/* Helpers */

static bool check_mem(char * arr, size_t size, char x) {
  for(int i = 0; i < size; i++) {
    if(arr[i] != x)
      return false;
  }
  return true;
}

static void clear_mem(char * arr, size_t size) {
  memset(arr, 0, size);
  dfsan_set_label(0, arr, size);
  ASSERT(check_mem(arr, size, 0));
  ASSERT(dfsan_read_label(arr, size) == 0);
}

static bool check_labels(char * arr, size_t size, dfsan_label expected_label) {
  dfsan_label this_label;
  for(int i = 0; i < size; i++) {
    this_label = dfsan_get_label(arr[i]);
    if(this_label != expected_label) {
      printk("    KDFSan test ERROR: label of arr[%d] is %d but expected %d; quitting test...\n", i, this_label, expected_label);
      return false;
    }
  }
  return true;
}

/************************************/
/* Tests */

static void testpolicies_getuser_run(char *kmem, char __user *usermem, size_t size, char data, dfsan_label expected_label) {
  // Test copy_from_user
  clear_mem(kmem, size);
  TEST_PANIC_ON(copy_from_user(kmem, usermem, size), "KDFSan test error: copy_from_user failed");
  ASSERT(check_labels(kmem, size, expected_label));
  ASSERT(check_mem(kmem, size, data));

  // Test get_user
  clear_mem(kmem, size);
  TEST_PANIC_ON(get_user(kmem[0], usermem), "KDFSan test error: get_user failed");
  ASSERT(check_labels(&kmem[0], 1, expected_label) && check_labels(&kmem[1], size - 1, 0));
  ASSERT(check_mem(&kmem[0], 1, data) && check_mem(&kmem[1], size - 1, 0));

  // Test strncpy_from_user
  clear_mem(kmem, size);
  put_user(0, &usermem[size - 1]); // NULL-terminates string
  TEST_PANIC_ON(strncpy_from_user(kmem, usermem, size) != size - 1, "KDFSan test error: strncpy_from_user failed"); // returns length of string on success
  ASSERT(check_labels(kmem, size, expected_label));
  ASSERT(check_mem(kmem, size - 1, data) && check_mem(&kmem[size - 1], 1, 0));

  // Test strnlen_user
  clear_mem(kmem, size);
  put_user(0, &usermem[size - 2]); // NULL-terminates string 1 byte early
  size_t user_len = strnlen_user(usermem, size); // returns the string length *including* the NULL terminator
  ASSERT(dfsan_get_label(user_len) == expected_label);
  ASSERT(user_len == size - 1);
}

static void testpolicies_getuser(void) {
  printk("    KDFSan: Setting up user copy tests... (This should only run once task whitelisting is enabled, otherwise getuser taint will not be applied)\n");

  char *kmem;
  char __user *usermem;
  unsigned long user_addr;
  size_t size = 10;
  char data = 34;
  dfsan_label attacker_label = dfsan_create_label("test-a11", 0);
  dfsan_label getuser_label = kdfsan_policies_get_getuser_label();
  dfsan_label unioned_label = dfsan_union(attacker_label, getuser_label);
  //printk("    KDFSan getuser test: attacker_label = %d, getuser_label = %d, unioned_label = %d\n", attacker_label, getuser_label, unioned_label);

  // Allocate mem
  kmem = kzalloc(size, GFP_KERNEL);
	TEST_PANIC_ON(!kmem, "KDFSan test error: Failed to allocate kernel memory");
	user_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0);
  TEST_PANIC_ON(user_addr >= (unsigned long)(TASK_SIZE), "KDFSan test error: Failed to allocate user memory");
	usermem = (char __user *)user_addr;

  // Initialize usermem and check that parameters are untainted
  printk("    KDFSan: Running user copy tests with untainted user pointer...\n");
  memset(kmem, data, size);
  TEST_PANIC_ON(copy_to_user(usermem, kmem, size), "KDFSan test error: copy_to_user failed");
  ASSERT(dfsan_read_label(&kmem, sizeof(kmem)) == 0);
  ASSERT(dfsan_read_label(&usermem, sizeof(usermem)) == 0);
  ASSERT(dfsan_get_label(size) == 0 && dfsan_get_label(data) == 0);
  testpolicies_getuser_run(kmem, usermem, size, data, getuser_label); // getuser output should only have the getuser label

  // Re-initialize usermem and taint user pointer (tests should function the same regardless of taint)
  printk("    KDFSan: Running user copy tests with tainted user pointer...\n");
  memset(kmem, data, size);
  TEST_PANIC_ON(copy_to_user(usermem, kmem, size), "KDFSan test error: copy_to_user failed");
  dfsan_set_label(attacker_label, &usermem, sizeof(usermem));
  ASSERT(dfsan_read_label(&kmem, sizeof(kmem)) == 0);
  ASSERT(dfsan_read_label(&usermem, sizeof(usermem)) != 0); // usermem pointer is tainted
  ASSERT(dfsan_get_label(size) == 0 && dfsan_get_label(data) == 0);
  testpolicies_getuser_run(kmem, usermem, size, data, unioned_label); // getuser output should have both the getuser label and the attacker label

  // Cleanup
  printk("    KDFSan: Cleaning up user copy tests...\n");
  vm_munmap(user_addr, size);
  kfree(kmem);
}

void kdfsan_run_policies_tests(void) {
  testpolicies_getuser();
  TEST_PANIC_ON(kdf_tests_fail, "KDFSan error: one or more tests failed");
}

#endif

/******************************************************************************/
/* Double-fetch tests */
/******************************************************************************/

#ifdef CONFIG_KDFSAN_DOUBLEFETCH_POLICIES

static void __no_opt testpolicies_df_userspace(void) {
  if (!KDF_DOUBLEFETCH_USER) return;

  printk("    KDFSan: Setting up userspace double-fetch test...\n");
  unsigned char __user *usermem;
  unsigned long user_addr;
  size_t size = 10;
  unsigned char x, y[0xff], z[2];

  user_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0); // Allocate user mem
  TEST_PANIC_ON(user_addr >= (unsigned long)(TASK_SIZE), "KDFSan test error: Failed to allocate user memory");
  usermem = (char __user *)user_addr;

  printk("    KDFSan: Running userspace double-fetch test with an initial *GETUSER*. (SHOULD PRINT REPORTS: 1 USER_1F, 2 USER_2F, 1 VULN_STORE)...\n");
  barrier(); x = 0; z[0] = 0; z[1] = 0; // Just to be safe
  TEST_PANIC_ON(copy_from_user(&x, &usermem[0], 1), "KDFSan test error: copy_from_user failed"); ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted       -- USER_1F (load)
  TEST_PANIC_ON(get_user(x, &usermem[2]), "KDFSan test error: get_user failed"); ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted
  TEST_PANIC_ON(copy_from_user(z, &usermem[0], 2), "KDFSan test error: copy_from_user failed"); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(z[0]))); ASSERT(dfsan_get_label(z[1]) == 0); // Double-fetch is tainted (although usermem[1] is not double-fetched) -- USER_2F
  TEST_PANIC_ON(get_user(x, &usermem[3]), "KDFSan test error: get_user failed"); ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted
  TEST_PANIC_ON(__get_user(x, &size),     "KDFSan test error: __get_user failed"); ASSERT(dfsan_get_label(x) == 0); // Single-fetch FROM KERNELSPACE is untainted
  TEST_PANIC_ON(__get_user(x, &size),     "KDFSan test error: __get_user failed"); ASSERT(dfsan_get_label(x) == 0); // Double-fetch FROM KERNELSPACE is untainted
  TEST_PANIC_ON(get_user(x, &usermem[0]), "KDFSan test error: get_user failed"); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // N-fetch is tainted      -- USER_2F
  y[x] = 34; //                                                                                                                                                      -- VULN_STORE

  printk("    KDFSan: Running userspace double-fetch test with an initial *PUTUSER* (put_user). (SHOULD PRINT REPORTS: 1 USER_1F, 1 USER_2F, 1 VULN_COND)...\n");
  barrier(); x = 0; // Just to be safe
  TEST_PANIC_ON(put_user(34, &usermem[4]), "KDFSan test error: put_user failed"); // Single-fetch                                                                    -- USER_1F (store)
  TEST_PANIC_ON(get_user(x, &usermem[4]), "KDFSan test error: get_user failed"); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Double-fetch is tainted -- USER_2F
  for (int i = 0; i < x; i++) { barrier(); } // Vulnerable branch via a tainted condition.                                                                           -- VULN_COND

  printk("    KDFSan: Running userspace double-fetch test with an initial *PUTUSER* (copy_to_user). (SHOULD PRINT REPORTS: 1 USER_1F, 1 USER_2F)...\n");
  barrier(); x = 0; // Just to be safe
  TEST_PANIC_ON(copy_to_user(&usermem[5], &x, 1), "KDFSan test error: copy_to_user failed"); // Single-fetch                                                         -- USER_1F (store)
  TEST_PANIC_ON(get_user(x, &usermem[5]), "KDFSan test error: get_user failed"); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Double-fetch is tainted -- USER_2F

  printk("    KDFSan: Running userspace double-fetch test with an initial *PUTUSER* (__put_user). (SHOULD PRINT REPORTS: 1 USER_1F, 1 USER_2F)...\n");
  barrier(); x = 0; // Just to be safe
  TEST_PANIC_ON(__put_user(34, &usermem[7]), "KDFSan test error: __put_user failed"); // Single-fetch                                                                -- USER_1F (store)
  TEST_PANIC_ON(get_user(x, &usermem[7]), "KDFSan test error: get_user failed"); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Double-fetch is tainted -- USER_2F

  // Cleanup
  vm_munmap(user_addr, size);
}

static char __no_opt helper_load(char * ptr) { return *ptr; }
static void __no_opt helper_store(char * ptr, char x) { *ptr = x; }
static void helper_loop(char * ptr) { for (int i = 0; *ptr == 123 || i < 4; i++) { barrier(); } } // NOTE: This function should not be optimized, because otherwise the loop branch is not a backward branch, and then we don't identify it as a VULN_COND
static void __no_opt testpolicies_df_dma_coherent(void) {
  if (!KDF_DOUBLEFETCH_DMA_COHERENT) return;

  struct pci_dev * pdev = NULL;
  char * buf = NULL;
  dma_addr_t dma_handle;
  size_t size = 20;
  unsigned char x, y[0xff];

  printk("    KDFSan: Setting up coherent DMA test...\n");
  pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, NULL); // Get any available device struct
  ASSERT(pdev != NULL);
  buf = dma_alloc_coherent(&(pdev)->dev, size, &dma_handle, GFP_DMA); // Allocate on behalf of the device
  ASSERT(buf != NULL);
  printk("    KDFSan: Set up coherent DMA buffer with dev_drv=%s, dev_name=%s\n", dev_driver_string(&(pdev)->dev), pci_name(pdev));

  printk("    KDFSan: Running coherent DMA test with an initial *STORE*. (SHOULD PRINT REPORTS: 1 DMA_1F, 3 DMA_2F, 2 VULN_COND, 1 DMA_1F, 1 DMA_2F, 1 VULN_COND, (Domain change), 1 DMA_2F, 1 VULN_COND)...\n");
  barrier(); x = 0; // Just to be safe
  helper_store(&buf[0], 34); // Single-fetch                                                      -- DMA_1F (store)
  x = buf[1]; ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted
  __builtin_memmove(&x, &buf[0], sizeof(x)); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // DMA_2F
  __memcpy(&x, &buf[0], sizeof(x)); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); //   -- DMA_2F
  x = buf[2]; ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted
  x = helper_load(&buf[0]); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // N-fetch is tainted -- DMA_2F
  for (int i = 0; i < x; i++) { barrier(); } // Vulnerable branch via a tainted condition.        -- VULN_COND
  BUG_ON(x == 11111111); //                                                                       -- VULN_COND
  //if (x == 22222222) BUG(); //                                                                    -- VULN_COND
  //if (x == 33333333) panic("Here's a panic!\n"); //                                               -- VULN_COND
  helper_loop(&buf[3]); //                                                                        -- DMA_1F:LOAD, DMA_2F:LOAD, VULN_COND
  kdfsan_domain_exit(); printk("    KDFSan: ---- (Domain change) ----\n"); kdfsan_domain_enter(); // Contrived domain change to test report clearing
  for (int i = 0; i < x; i++) { barrier(); } // x is tainted, but its DMA_2F report was cleared => no VULN_COND
  x = buf[0]; ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Preceeding DMA_1F (store) persists thru domain change -- DMA_2F
  for (int i = 0; i < x; i++) { barrier(); } //                                                   -- VULN_COND

  printk("    KDFSan: Running coherent DMA test with an initial *LOAD*. (SHOULD PRINT REPORTS: 1 DMA_1F, 1 DMA_2F, 1 VULN_STORE, (Domain change), 1 DMA_1F, 1 DMA_2F, 1 VULN_STORE)...\n");
  barrier(); x = 0; // Just to be safe
  x = buf[4]; ASSERT(dfsan_get_label(x) == 0); // Single-fetch is untainted                         -- DMA_1F (load)
  for (int i = 0; i < 4; i++) {	// First set of reports should print; the other sets have duplicates
    memcpy(&x, &buf[4], sizeof(x)); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); //     -- DMA_2F
    y[x] = 34; //                                                                                   -- VULN_STORE
  }
  ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); if (x == 12345678) { barrier(); } ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Forward branch condition *does not* invalidate double-fetch taint
  kdfsan_domain_exit(); printk("    KDFSan: ---- (Domain change) ----\n"); kdfsan_domain_enter(); // Contrived domain change to test report clearing
  y[x] = 34; // x is tainted, but its DMA_2F report was cleared => no VULN_STORE
  x += buf[4]; ASSERT(dfsan_get_label(x) != 0 && !kdfsan_policies_is_df_label(dfsan_get_label(x))); // Single-fetch is tainted, but with an *invalid* double-fetch label -- DMA_1F (load)
  x += buf[4]; ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // Double-fetch is tainted  -- DMA_2F: prev_reports should include only the immediately preceeding DMA_1F
  y[x] = 34; //                                                                                     -- VULN_STORE: prev_reports should include only the immediately preceeding DMA_2F

  printk("    KDFSan: Running coherent DMA test with pointers written. (SHOULD PRINT REPORTS: 4 DMA_1F)...\n");
  u64 * dma_ptr = (u64*)(&buf[10]);
  const u64 * local_ptr = (u64*)&size;
  memset(y, 0, sizeof(y)); memcpy(&y[2], &local_ptr, sizeof(u64*)); // y[2]--y[9] has a pointer
  *dma_ptr = (u64)local_ptr;                           // DMA_1F (store)
  memcpy(dma_ptr, &local_ptr, sizeof(u64));            // DMA_1F (store)
  __memcpy(dma_ptr, &y[0], 10);                        // DMA_1F (store)
  __memcpy(dma_ptr, &y[3], 10);                        // None -- doesn't include the part of the pointer in y[2]
  __memcpy(dma_ptr, &y[0], 9);                         // None -- doesn't include the part of the pointer in y[9]
  __builtin_memmove(dma_ptr, &local_ptr, sizeof(u64)); // DMA_1F (store)

  // Cleanup
  printk("    KDFSan: Cleaning up coherent DMA test...\n");
  dma_free_coherent(&(pdev)->dev, size, buf, dma_handle);
  pci_dev_put(pdev);

  // Cleanup sanity checks
  x = buf[0]; ASSERT(dfsan_get_label(x) == 0); // buf is no longer a DMA region, so this shouldn't generate a report. (Yes, this is a use-after-free...)
  x = buf[0]; ASSERT(dfsan_get_label(x) == 0); // buf is no longer a DMA region, so this shouldn't generate a report. (Yes, this is a use-after-free...)
  ASSERT(dfsan_read_label(buf, size) == 0); // buf should be untainted
}

static int match_any_device(struct device *dev, const void *data) { return 1; } // Always match
static struct device *get_any_device(void) { return bus_find_device(&platform_bus_type, NULL, NULL, match_any_device); }
static void __no_opt testpolicies_df_vulns_dmapool(void) {
  if (!KDF_DOUBLEFETCH_DMA_COHERENT) return;

  struct device *dev;
  struct dma_pool *pool;
  char *buf1, *buf2;
  dma_addr_t handle1, handle2;

  printk("    KDFSan: Setting up DMA pool test...\n");
  dev = get_any_device();
  ASSERT(dev != NULL);
  pool = dma_pool_create("my-test-pool", dev, 1024, 64, 0);
  buf1 = dma_pool_zalloc(pool, GFP_KERNEL, &handle1);
  buf2 = dma_pool_zalloc(pool, GFP_KERNEL, &handle2);

  ASSERT(!kdfsan_policies_is_df_label(dfsan_get_label((long)buf2))); // Assert fails if DMA pool *is* vulnerable
  buf2[20] = 0x34; //					-- VULN_STORE if DMA pool is vulnerable (buf2 tainted because of the DMA_1F/2F in dma_pool_zalloc()...)

  printk("    KDFSan: Cleaning up DMA pool test...\n");
  dma_pool_free(pool, buf1, handle1);
  dma_pool_free(pool, buf2, handle2);
  dma_pool_destroy(pool);
  put_device(dev);
}

static int match_e100_device(struct device *dev, const void *data) {
    if (to_pci_dev(dev) && dev->driver && !strcmp(dev->driver->name, "e100")) return 1;
    return 0;
}
static struct device *get_e100_device(void) { return bus_find_device(&pci_bus_type, NULL, NULL, match_e100_device); }
static void __no_opt testpolicies_df_vulns_swiotlb(void) {
  if (!KDF_DOUBLEFETCH_DMA_COHERENT) return;

  struct device *dev;
  dma_addr_t handle_coherent, handle_streaming;
  char *buf_coherent;
  size_t size = 64;

  // Get a handle to the E100 dev, because it exhibits the vuln.
  printk("    KDFSan: Setting up swiotlb test...\n");
  dev = get_e100_device();
  if (!dev) { ASSERT(false); return; }
  printk("Device info: driver=%s, name=%s, bus_id=%s\n", dev_driver_string(dev), dev_name(dev), dev_bus_name(dev));

  // Setup coherent DMA region
  buf_coherent = dma_alloc_coherent(dev, size, &handle_coherent, GFP_DMA);
  ASSERT(buf_coherent != NULL);

  // Get an sk_buff (because it causes dma_map_single() to give us a swiotlb buffer)
  struct sk_buff *skb;
  if (!(skb = netdev_alloc_skb(NULL, 1500))) {
    ASSERT(false);
    return;
  }
  skb_put(skb, 1500);
  memset(skb->data, 0xFF, 1500);

  // Map the sk_buff into streaming DMA
  handle_streaming = dma_map_single(dev, skb->data, size, DMA_TO_DEVICE);
  ASSERT(!dma_mapping_error(dev, handle_streaming));

  // Cover TOITOU vuln.
  *(dma_addr_t*)buf_coherent = handle_streaming;  // DMA_1F:STORE -- Initialize buf_coherent with the streaming region's DMA handle
  dma_addr_t dma_arg = *(dma_addr_t*)buf_coherent;// DMA_2F:LOAD
  dma_unmap_single(dev, dma_arg, size, DMA_TO_DEVICE); // --> VULN_COND

  printk("    KDFSan: Cleaning up swiotlb test...\n");
  dev_kfree_skb(skb);
  dma_free_coherent(dev, size, buf_coherent, handle_coherent);
  put_device(dev);
}

static void testpolicies_df_vulns(void) {
  // Let's not run these tests by default. E.g., because the dmapool test is designed to fail an assertion if the vuln. is unmitigated.
  if (0) testpolicies_df_vulns_dmapool();
  if (0) testpolicies_df_vulns_swiotlb();
}

static void __no_opt testpolicies_df_dma_streaming() {
  if (!KDF_DOUBLEFETCH_DMA_STREAMING) return;

  struct pci_dev * pdev;
  dma_addr_t dma_handle;
  char * buf = NULL;
  size_t size = 10;
  char x;

  printk("    KDFSan: Setting up streaming DMA test...\n");
  pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, NULL); // Get any available device struct
  ASSERT(pdev != NULL);
  buf = kzalloc(size, GFP_DMA);
  ASSERT(buf != NULL);
  dma_handle = dma_map_single(&(pdev)->dev, buf, size, DMA_FROM_DEVICE);
  ASSERT(!dma_mapping_error(&(pdev)->dev, dma_handle));
  printk("    KDFSan: Set up streaming DMA buffer with dev_drv=%s, dev_name=%s\n", dev_driver_string(&(pdev)->dev), pci_name(pdev));

  printk("    KDFSan: Running streaming DMA test. (SHOULD PRINT REPORTS: 4 DMA_INV)...\n");
  x = buf[0]; // DMA_INV
  __builtin_memmove(&x, &buf[0], sizeof(x)); // DMA_INV
  ASSERT(dfsan_get_label(x) == 0);
  dma_sync_single_for_cpu(&(pdev)->dev, dma_handle, size, DMA_FROM_DEVICE);
  x = buf[0]; // (Valid access)
  ASSERT(dfsan_get_label(x) == 0);
  dma_sync_single_for_device(&(pdev)->dev, dma_handle, size, DMA_FROM_DEVICE);
  for (int i = 0; i < 10; i++) x = buf[0]; // DMA_INV (should only print 1 report; the other 9 are duplicates)
  memcpy(&x, &buf[0], sizeof(x)); // DMA_INV
  ASSERT(dfsan_get_label(x) == 0);

  // Cleanup
  printk("    KDFSan: Cleaning up streaming DMA test...\n");
  dma_unmap_single(&(pdev)->dev, dma_handle, size, DMA_FROM_DEVICE);
  pci_dev_put(pdev);

  // Cleanup sanity checks
  x = buf[0]; ASSERT(dfsan_get_label(x) == 0); // buf is no longer a DMA region, so this shouldn't generate a report. (Yes, this is a use-after-free...)
  ASSERT(dfsan_read_label(buf, size) == 0); // buf should be untainted
  kfree(buf);
}

static void __no_opt testpolicies_df_mmio() {
  if (!KDF_DOUBLEFETCH_MMIO) return;

  void __iomem * iomem;
  char x = 0, y = 0;

  printk("    KDFSan: Setting up MMIO test...\n");
  TEST_PANIC_ON(request_mem_region(0xA1234, 0x34, "fake-kdfsan-test-driver1") == NULL, "KDFSan test error: request_mem_region() failed");
  iomem = ioremap(0xA1234, 0x34);
  TEST_PANIC_ON(iomem == NULL, "KDFSan test error: ioremap() failed");

  printk("    KDFSan: Running MMIO test. (SHOULD PRINT REPORTS: 1 MMIO_1F, 4 MMIO_2F)...\n");
  writeb(34, iomem);  // MMIO_1F (STORE)
  x = *(char*)iomem;  // MMIO_2F
  x = ioread8(iomem); // MMIO_2F
  x = readb(iomem);   // MMIO_2F
  memcpy_fromio(&x, iomem, 1); // MMIO_2F

  ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x)));
  ASSERT(dfsan_get_label(y) == 0);
  y = x & 0xf; // 'And' operation clears label
  ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x)));
  ASSERT(dfsan_get_label(y) == 0);

  // Cleanup
  iounmap(iomem);
  release_mem_region(0xA1234, 0x34);
}

static void __no_opt testpolicies_df_pmio() {
  if (!KDF_DOUBLEFETCH_PMIO) return;

  int x;

  printk("    KDFSan: Setting up PMIO test...\n");
  TEST_PANIC_ON(request_region(1234, 34, "fake-kdfsan-test-driver2") == NULL, "KDFSan test error: request_region() failed");

  printk("    KDFSan: Running PMIO test. (SHOULD PRINT REPORTS: 1 PMIO_1F, 3 PMIO_2F, 1 PMIO_1F, 1 PMIO_2F, 1 VULN_COND)...\n");
  outb(34, 1234);                                                                                                 // PMIO_1F (STORE)
  x = inb(1234); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x)));                                         // PMIO_2F
  x = inb(1237); ASSERT(dfsan_get_label(x) == 0);                                                                 // PMIO_1F (LOAD)
  insb(1234, &x, 1); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x)));                                     // PMIO_2F
  x = ioread8((const void __iomem *)(0x10000UL | 1234)); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x))); // PMIO_2F... 0x10000UL shenanigans based on PIO_OFFSET in iomap.c
  x += inb(1237); ASSERT(kdfsan_policies_is_df_label(dfsan_get_label(x)));                                        // PMIO_2F
  for (int i = 0; i < x; i++) { barrier(); }                                                                      // VULN_COND: prev_reports should include the two preceeding PMIO_2F reports

  // Cleanup
  release_region(1234, 34);
}

static void __no_opt clear_stack_shadow() {
  char x[2048] = {0}; // Assuming we don't need to go deeper than 2048 bytes...
  dfsan_set_label(0, &x, sizeof(x));
}

void kdfsan_run_policies_tests(void) {
  printk("    KDFSan: Running double-fetch tests...\n");
  testpolicies_df_userspace();
  testpolicies_df_dma_coherent();
  testpolicies_df_vulns();
  testpolicies_df_dma_streaming();
  testpolicies_df_mmio();
  testpolicies_df_pmio();
  TEST_PANIC_ON(kdf_tests_fail, "KDFSan error: one or more tests failed");
  clear_stack_shadow();
}

#endif