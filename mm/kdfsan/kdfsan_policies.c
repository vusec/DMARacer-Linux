// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_util.h"
#include "kdfsan_internal.h"
#include "kdfsan_interface.h"
#include "kdfsan_policies.h"

/******************************************************************************/
/* Userspace policies */
/******************************************************************************/

#ifdef CONFIG_KDFSAN_USERSPACE_POLICIES

extern bool kdf_param_generic_syscall_label;

static u64 cumulative_arg_count = -1;
static dfsan_label attacker_syscall_label = -1;
static dfsan_label attacker_getuser_label = -1;

// For KDFSan tests
dfsan_label kdfsan_policies_get_getuser_label(void) { return attacker_getuser_label; }

// Taint source: syscall args
void kdf_policies_syscall_arg(void * arg, size_t s, int arg_num) {
  if (kdf_param_generic_syscall_label) {
    kdf_add_label(attacker_syscall_label, arg, s); // Not calling dfsan_add_label because we're in the run-time here
  } else {
    u16 syscall_nr = kdf_util_syscall_get_nr();

    u64 arg_val = 0;
    if(s == 1) { arg_val = (u64)(*(u8*)arg); }
    else if(s == 2) { arg_val = (u64)(*(u16*)arg); }
    else if(s == 4) { arg_val = (u64)(*(u32*)arg); }
    else if(s == 8) { arg_val = (u64)(*(u64*)arg); }
    else { } // TODO: panic?

    char desc[150] = "";
    u64 this_cumulative_arg_count = cumulative_arg_count; cumulative_arg_count++;
    CONCAT_STR("total_arg_nr: ",desc,sizeof(desc)); CONCAT_NUM(this_cumulative_arg_count,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_nr: ",desc,sizeof(desc)); CONCAT_NUM(syscall_nr,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_arg_nr: ",desc,sizeof(desc)); CONCAT_NUM(arg_num,10,desc,sizeof(desc));
    CONCAT_STR(", size: ",desc,sizeof(desc)); CONCAT_NUM(s,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_arg_val: 0x",desc,sizeof(desc)); CONCAT_NUM(arg_val,16,desc,sizeof(desc));

    dfsan_label label = kdf_create_label(desc); // Not calling dfsan_create_label because we're in the run-time here
    kdf_add_label(label, arg, s); // Not calling dfsan_add_label because we're in the run-time here
  }
}

// Taint source: usercopies
dfsan_label kdf_policies_load(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) {
  if (access_ok(addr, size)) return attacker_getuser_label;
  return 0;
}

void kdf_policies_init(void) {
  cumulative_arg_count = 0;
  // Not calling dfsan_create_label because the runtime has not been enabled yet
  attacker_getuser_label = kdf_create_label("attacker-getuser");
  if (kdf_param_generic_syscall_label) attacker_syscall_label = kdf_create_label("attacker-syscall-arg");
}

#endif

/******************************************************************************/
/* Double-fetch policies */
/******************************************************************************/

#ifdef CONFIG_KDFSAN_DOUBLEFETCH_POLICIES

/************************************************************/
/* Data, types, etc. ****************************************/

#define MAX_STR_LEN 4096 // Can probably use a smaller buffer

typedef struct {
  bool                 is_cpu_accessible;
  void *               last_sync_rip;
  depot_stack_handle_t last_sync_bt;
} kdf_streaming_dma_metadata;

// For tracking DMA and MMIO regions
typedef struct {
  u32                          dev_id;
  u64                          bus_addr;
  void *                       cpu_addr;
  size_t                       s;
  void *                       alloc_rip;
  depot_stack_handle_t         alloc_bt;
  bool                         is_dma; // False => is MMIO
  bool                         is_streaming_dma;
  kdf_streaming_dma_metadata * steaming_dma_byte; // A kdf_streaming_dma_metadata for every byte in the region
  struct maple_tree            stores;
  struct maple_tree            store_ptrs; // Janky way of tracking pointers in the stores tree, so we can just free all of them when freeing the region
  struct rcu_head              rcu;
} kdf_region;
static struct maple_tree regions_tree = MTREE_INIT(regions_tree, MT_FLAGS_USE_RCU);

// For recording fetches
typedef struct {
  int                  prev_report_id;
  char *               first_fetch_str;
  void *               first_fetch_rip;
  depot_stack_handle_t first_fetch_bt;
  kdf_region *         first_fetch_region;
} kdf_fetch_t;

// For reports
enum report_type { DMA_INV, DMA_SF, DMA_DF, MMIO_SF, MMIO_DF, PMIO_SF, PMIO_DF, USER_SF, USER_DF, VULN_STORE, VULN_COND };
enum instr_type { LOAD, STORE, IN, OUT, GETUSER, PUTUSER, COND, BUG };
#define REPORT_ID_NONE -1

/***************************************************************/
/* Per-domain report coverage tracking *************************/

static bool kdf_get_report_covered(int report_id) {
  return kdfsan_get_context()->pstate.reports_covered[report_id];
}

static void kdf_set_report_coverage(int report_id, bool is_covered) {
  kdfsan_get_context()->pstate.reports_covered[report_id] = is_covered;
}

/***************************************************************/
/* Label-to-report(s) conversion *******************************/

#define MAX_PREV_REPORTS 16 // I can't imagine we have more than 16 double-fetch taint colors unioned together

static bool label_have_reports[NUM_LABELS]                = {false};
static volatile bool label_locked_reports[NUM_LABELS]     = {false};
static int label_to_reports[NUM_LABELS][MAX_PREV_REPORTS] = {0}; // label_to_reports[label] --> [report0, report1, ...]

static bool kdf_label_have_reports(dfsan_label label) { return label_have_reports[label]; }
static size_t kdf_label_get_reports(int * prev_reports, dfsan_label label) {
  int * saved_prev_reports = label_to_reports[label];
  size_t num_reports = 0;
  for (int i = 0; i < MAX_PREV_REPORTS && saved_prev_reports[i] != 0; i++) {
    prev_reports[i] = saved_prev_reports[i];
    num_reports++;
  }
  return num_reports;
}
static void kdf_label_set_reports(int * prev_reports, size_t prev_reports_count, dfsan_label label) {
  if (label_have_reports[label] || label_locked_reports[label]) return; // Prevent two threads from writing to the same label_to_reports[label] simultaneously
  label_locked_reports[label] = true;
  int * saved_prev_reports = label_to_reports[label];
  for (int i = 0; i < MAX_PREV_REPORTS; i++) {
    if (i < prev_reports_count) saved_prev_reports[i] = prev_reports[i];
    else saved_prev_reports[i] = 0;
  }
  label_have_reports[label] = true;
  label_locked_reports[label] = false;
}

static size_t kdf_label_to_all_prev_reports(int * prev_reports, dfsan_label label) {
  if (label == 0) return 0;

  // Check whether we've already converted this label to prev_reports
  if (kdf_label_have_reports(label)) {
    return kdf_label_get_reports(prev_reports, label);
  }

  // If not, let's convert this label to prev_reports
  char descs[MAX_PREV_REPORTS][KDF_DESC_LEN];
  size_t num_reports = kdf_get_label_descs(label, descs, MAX_PREV_REPORTS);
  size_t err_count = 0;
  for (int i = 0; i < num_reports; i++) {
    // Convert descs[i] string into integer. If for some reason it cannot be converted to an integer, skip it.
    long this_report_id = REPORT_ID_NONE;
    int rc = kstrtol(descs[i], 10, &this_report_id);
    if (rc) {
      printk("%s:%d: Warning: Could not convert label '%s' to decimal\n", __FILE__, __LINE__, descs[i]);
      err_count++;
      num_reports--;
    }
    else prev_reports[i-err_count] = this_report_id;
  }

  // Let's save this label-to-prev_reports conversion
  kdf_label_set_reports(prev_reports, num_reports, label);

  return num_reports;
}
static size_t kdf_label_to_prev_reports(int * prev_reports, dfsan_label label) {
  if (label == 0) return 0;
  size_t prev_reports_count = kdf_label_to_all_prev_reports(prev_reports, label);
  size_t noncovered_count = 0;
  for (int i = 0; i < prev_reports_count; i++) {
    if (kdf_get_report_covered(prev_reports[i])) prev_reports[i-noncovered_count] = prev_reports[i];
    else noncovered_count++;
  }
  return prev_reports_count - noncovered_count;
}

static bool kdf_has_df_label(dfsan_label lbl) {
  int prev_reports[MAX_PREV_REPORTS];
  return kdf_label_to_prev_reports(prev_reports, lbl) != 0;
}
bool kdfsan_policies_is_df_label(dfsan_label lbl) { return kdf_has_df_label(lbl); }

static void kdf_invalidate_label(dfsan_label label) {
  if (label == 0) return;
  int prev_reports[MAX_PREV_REPORTS];
  size_t prev_reports_count = kdf_label_to_all_prev_reports(prev_reports, label);
  for (int i = 0; i < prev_reports_count; i++) kdf_set_report_coverage(prev_reports[i], false);
}

/************************************************************/
/* Tracking created double-fetch labels *********************/

// NOTE: This only includes *created* DF labels; not *all* (i.e., union'ed) labels
typedef struct {
  int report_id;
  dfsan_label created_label;
} kdf_report_to_label_t;
static kdf_report_to_label_t df_labels[NUM_LABELS] = {0}; // df_labels[count] --> (report_id, created_label)
static atomic_t df_label_count = ATOMIC_INIT(0);

static dfsan_label kdf_get_df_label(int report_id) {
  // Check if we already have a created_label saved for this report_id. If so, return that.
  int cnt = atomic_read(&df_label_count);
  for (int i = 0; i < cnt; i++) {
    if (df_labels[i].report_id == report_id) return df_labels[i].created_label;
  }

  // Check if a label with report_id as the desc already exists. If not, create it.
  char desc[8];
  sprintf(desc, "%d", report_id); // Use the report_id as the desc.
  dfsan_label lbl = kdf_get_label_with_desc(desc);
  if (lbl == 0) lbl = kdf_create_label(desc);

  // Next, add it to df_labels, then return it.
  int df_label_i = atomic_inc_return(&df_label_count) - 1;
  df_labels[df_label_i] = (kdf_report_to_label_t){.report_id = report_id, .created_label = lbl};
  return lbl;
}

/************************************************************/
/* Duplicate report filtering *******************************/

typedef struct {
  volatile bool ready;
  int report_id;
  enum report_type rt;
  enum instr_type it;
  depot_stack_handle_t bt;
  void * rip;
  dfsan_label data_label;
  dfsan_label ptr_label;
} kdf_dup_report_t;

// dup_reports does *not* track single-fetch reports. Those are managed by the per-domain 'fetches' tree (via domain_get_prev_fetch()), and are deduplicated based on address (not rt, it, rip, etc.).
static kdf_dup_report_t dup_reports[MAX_TOTAL_REPORTS] = {{0}};
static atomic64_t dup_report_count = ATOMIC_INIT(0);

static kdf_dup_report_t kdf_dup_new_report(enum report_type rt, enum instr_type it, depot_stack_handle_t bt, void * rip, dfsan_label data_label, dfsan_label ptr_label) {
  // To avoid over-reporting, only use data_label and ptr_label if this is a VULN_* rt.
  return (rt == VULN_STORE || rt == VULN_COND) ?
         (kdf_dup_report_t){.ready = false, .report_id = REPORT_ID_NONE, .rt = rt, .it = it, .bt = bt, .rip = rip, .data_label = data_label, .ptr_label = ptr_label} :
         (kdf_dup_report_t){.ready = false, .report_id = REPORT_ID_NONE, .rt = rt, .it = it, .bt = bt, .rip = rip, .data_label = 0, .ptr_label = 0};
}

static void kdf_dup_insert_report(kdf_dup_report_t dr) {
  size_t idx = atomic64_inc_return(&dup_report_count) - 1;
  KDF_PANIC_ON(idx >= MAX_TOTAL_REPORTS, "%s:%d: Error: Max report count (%lu) reached! Any new reports will not be filtered out as duplicates. Consider increasing MAX_TOTAL_REPORTS (or using a dynamically-sized linked list instead of a statically-sized array).\n", __FILE__, __LINE__, MAX_TOTAL_REPORTS);
  dup_reports[idx] = dr;
}

static bool kdf_dup_reports_equal(kdf_dup_report_t dr1, kdf_dup_report_t dr2) {
  return dr1.rt == dr2.rt &&
         dr1.it == dr2.it &&
         /*dr1.bt == dr2.bt &&*/
         dr1.rip == dr2.rip /*&&
         dr1.data_label == dr2.data_label &&
         dr1.ptr_label == dr2.ptr_label*/;
}

// If it's a duplicate, return the dup_report's ID. Else, create this report, and return REPORT_ID_NONE.
static int kdf_dup_check_insert(enum report_type rt, enum instr_type it, depot_stack_handle_t bt, void * rip, dfsan_label data_label, dfsan_label ptr_label) {
  // Loop through previous reports, checking each report's (rt, it, bt, data_label, ptr_label).
  kdf_dup_report_t this_dup_report = kdf_dup_new_report(rt, it, bt, rip, data_label, ptr_label);
  for (size_t i = 0; i < atomic64_read(&dup_report_count); i++) {
    if (!dup_reports[i].ready) { i--; continue; } // There's a small chance this report is current being added. In that case, spin until it's finished.
    if (kdf_dup_reports_equal(this_dup_report, dup_reports[i])) return dup_reports[i].report_id;
  }
  // If it's NOT a duplicate: Insert this report into the list of previous reports.
  kdf_dup_insert_report(this_dup_report);
  return REPORT_ID_NONE;
}

static void kdf_dup_add_id(enum report_type rt, enum instr_type it, depot_stack_handle_t bt, void * rip, dfsan_label data_label, dfsan_label ptr_label, int report_id) {
  // Loop through previous reports, checking each report's (rt, it, bt, data_label, ptr_label).
  kdf_dup_report_t this_dup_report = kdf_dup_new_report(rt, it, bt, rip, data_label, ptr_label);
  for (size_t i = 0; i < atomic64_read(&dup_report_count); i++) {
    // Don't check whether the report is ready. In fact, this report should _not_ yet be ready.
    if (kdf_dup_reports_equal(this_dup_report, dup_reports[i])) {
      dup_reports[i].report_id = report_id;
      dup_reports[i].ready = true;
      return;
    }
  }
  KDF_PANIC_ON(true, "Error: Could not find dup report from kdf_dup_add_id()\n");
}

/************************************************************/
/* Report batching ******************************************/

#define MAX_SAVED_REPORTS 8192
static bool kdf_printing_is_enabled = false;
static char* kdf_saved_reports[MAX_SAVED_REPORTS] = {NULL};
static atomic_t kdf_saved_reports_size = ATOMIC_INIT(0);

static void kdf_report_flush(void) {
  const int num_reports = atomic_xchg(&kdf_saved_reports_size, 0);
  int i = 0;
  while (i < num_reports) {
    if (i + 8 <= num_reports) {
      printk("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", kdf_saved_reports[i], kdf_saved_reports[i+1], kdf_saved_reports[i+2], kdf_saved_reports[i+3], kdf_saved_reports[i+4], kdf_saved_reports[i+5], kdf_saved_reports[i+6], kdf_saved_reports[i+7]);
      for (int j = 0; j < 8; j++) {
        kfree(kdf_saved_reports[i+j]);
        kdf_saved_reports[i+j] = NULL;
      }
      i += 8;
    }
    else if (i + 4 <= num_reports) {
      printk("%s\n%s\n%s\n%s\n", kdf_saved_reports[i], kdf_saved_reports[i+1], kdf_saved_reports[i+2], kdf_saved_reports[i+3]);
      for (int j = 0; j < 4; j++) {
        kfree(kdf_saved_reports[i+j]);
        kdf_saved_reports[i+j] = NULL;
      }
      i += 4;
    }
    else if (i + 2 <= num_reports) {
      printk("%s\n%s\n", kdf_saved_reports[i], kdf_saved_reports[i+1]);
      for (int j = 0; j < 2; j++) {
        kfree(kdf_saved_reports[i+j]);
        kdf_saved_reports[i+j] = NULL;
      }
      i += 2;
    }
    else {
      printk("%s\n", kdf_saved_reports[i]);
      kfree(kdf_saved_reports[i]);
      kdf_saved_reports[i] = NULL;
      i++;
    }
  }
}

static void kdf_report_enable(void) {
  kdf_printing_is_enabled = true;
  kdf_report_flush();
}

static void kdf_report_save(char * report_str) {
  if (atomic_read(&kdf_saved_reports_size) >= MAX_SAVED_REPORTS) kdf_report_flush(); // If saved reports buffer is full, flush it and continue
  int report_num = atomic_inc_return(&kdf_saved_reports_size) - 1;
  while (kdf_saved_reports[report_num] != NULL) ; // Spin until this slot is ready...
  kdf_saved_reports[report_num] = report_str;
}

/************************************************************/
/* Region logging *******************************************/

static struct maple_tree kdf_aff_regions = MTREE_INIT(kdf_aff_regions, MT_FLAGS_USE_RCU);
static struct maple_tree kdf_all_regions = MTREE_INIT(kdf_aff_regions, MT_FLAGS_USE_RCU);
static void kdf_region_str(const kdf_region * region, char * region_str, size_t size);

static void kdf_log_region_internal(kdf_region * region, const char * s) {
  // Log a dummy report, which logs this region. Code copied (mostly) from kdf_report_print_internal().
  char region_str[MAX_STR_LEN], * full_report_str;
  kdf_region_str(region, region_str, ARRAY_SIZE(region_str));
  full_report_str = kzalloc(MAX_STR_LEN, GFP_KERNEL);
  sprintf(full_report_str, "KDFSAN REPORT: {\"report_id\": -1, \"prev_reports\": [], \"rip\": \"%s\", \"report_type\": \"%s\", \"instr_type\": \"%s\", \"access\": {\"addr\": 0, \"size\": 0, \"data_label\": 0, \"ptr_label\": 0}, %s\"backtrace\": [\"%s\"], \"fuzzing_run\": \"%lu\"}", s, s, s, region_str, s, kdf_util_get_rand());
  if (kdf_printing_is_enabled) {
    printk("%s\n", full_report_str);
    kfree(full_report_str);
  }
  else kdf_report_save(full_report_str);
}

static void kdf_log_region(kdf_region * region, bool to_print, bool log_as_affected_region) {
  if (!region) return;
  struct maple_tree * logged_regions = log_as_affected_region ? &kdf_aff_regions : &kdf_all_regions;
  if (mtree_load(logged_regions, region->alloc_bt)) return; // If we've logged this region's alloc_backtrace before, return
  if (to_print) kdf_log_region_internal(region, log_as_affected_region ? "LOG_REGION_AFF" : "LOG_REGION_ALL"); // Log this region
  mtree_store(logged_regions, region->alloc_bt, (void*)(long)region->alloc_bt, GFP_KERNEL); // Save it to logged_regions (mtree[bt] = bt...)
}

/************************************************************/
/* Report printing ******************************************/

#define MAX_TYPE_SIZE 16
static atomic_t reports_count = ATOMIC_INIT(0); // For reports' IDs

static int kdf_report_next_id(void) { return atomic_inc_return(&reports_count) - 1; }

static void kdf_rt_str(const enum report_type rt, char * str, size_t size) {
  KDF_PANIC_ON(size < MAX_TYPE_SIZE, "Need a larger string for a report type."); // Should add better size checks
  if (rt == DMA_INV) strcpy(str, "DMA_INV");
  else if (rt == DMA_SF) strcpy(str, "DMA_1F");
  else if (rt == DMA_DF) strcpy(str, "DMA_2F");
  else if (rt == MMIO_SF) strcpy(str, "MMIO_1F");
  else if (rt == MMIO_DF) strcpy(str, "MMIO_2F");
  else if (rt == PMIO_SF) strcpy(str, "PMIO_1F");
  else if (rt == PMIO_DF) strcpy(str, "PMIO_2F");
  else if (rt == USER_SF) strcpy(str, "USER_1F");
  else if (rt == USER_DF) strcpy(str, "USER_2F");
  else if (rt == VULN_STORE) strcpy(str, "VULN_STORE");
  else if (rt == VULN_COND) strcpy(str, "VULN_COND");
  else strcpy(str, "UNKNOWN");
}

static void kdf_it_str(const enum instr_type it, char * str, size_t size) {
  KDF_PANIC_ON(size < MAX_TYPE_SIZE, "Need a larger string for a instr type."); // Should add better size checks
  if (it == LOAD) strcpy(str, "LOAD");
  else if (it == STORE) strcpy(str, "STORE");
  else if (it == IN) strcpy(str, "IN");
  else if (it == OUT) strcpy(str, "OUT");
  else if (it == GETUSER) strcpy(str, "GETUSER");
  else if (it == PUTUSER) strcpy(str, "PUTUSER");
  else if (it == COND) strcpy(str, "COND");
  else if (it == BUG) strcpy(str, "BUG");
  else strcpy(str, "UNKNOWN");
}

static void kdf_region_str(const kdf_region * region, char * region_str, size_t size) {
  KDF_PANIC_ON(size < MAX_TYPE_SIZE, "Need a larger string for a instr type."); // Should add better size checks
  if (region) {
    char bt_str[MAX_STR_LEN];
    kdf_util_bt_str(bt_str, ARRAY_SIZE(bt_str), region->alloc_bt);
    sprintf(region_str, "\"region\": {\"dev_id\": %u, \"bus_addr\": %llu, \"cpu_addr\": %llu, \"s\": %lu, \"alloc_rip\": \"%pS\", \"alloc_backtrace\": %s, \"is_dma\": %s, \"is_streaming_dma\": %s}, ", region->dev_id, region->bus_addr, region->cpu_addr, region->s, region->alloc_rip, bt_str, region->is_dma ? "true" : "false", region->is_streaming_dma ? "true" : "false");
  }
  else strcpy(region_str, "");
}

static void kdf_prev_reports_to_str(const int * prev_reports, size_t prev_report_count, char * prev_reports_str) {
  if (prev_reports == NULL || prev_report_count == 0) { sprintf(prev_reports_str, "[]"); return; }
  size_t len = sprintf(prev_reports_str, "[");
  if (prev_report_count > 0) len += sprintf(prev_reports_str+len, "%d", prev_reports[0]);
  for (int i = 1; i < prev_report_count; i++) len += sprintf(prev_reports_str+len, ", %d", prev_reports[i]);
  len += sprintf(prev_reports_str+len, "]");
}

static void kdf_report_print_internal(int report_id, int * prev_reports, size_t prev_report_count, char * partial_report_str, kdf_region * region, depot_stack_handle_t bt_handle, void * rip) {
  char bt_str[MAX_STR_LEN], prev_reports_str[MAX_STR_LEN], region_str[MAX_STR_LEN], * full_report_str;
  kdf_util_bt_str(bt_str, ARRAY_SIZE(bt_str), bt_handle);
  kdf_prev_reports_to_str(prev_reports, prev_report_count, prev_reports_str);
  kdf_region_str(region, region_str, ARRAY_SIZE(region_str));
  kdf_log_region(region, false, true);
  kdf_set_report_coverage(report_id, true);

  full_report_str = kzalloc(MAX_STR_LEN, GFP_KERNEL);
  sprintf(full_report_str, "KDFSAN REPORT: {\"report_id\": %d, \"prev_reports\": %s, \"rip\": \"%pS\", %s%s\"backtrace\": %s, \"fuzzing_run\": \"%lu\"}", report_id, prev_reports_str, rip, partial_report_str, region_str, bt_str, kdf_util_get_rand());

  if (kdf_printing_is_enabled) {
    printk("%s\n", full_report_str);
    kfree(full_report_str);
  }
  else kdf_report_save(full_report_str);
}

static int kdf_report_print_first_fetch(kdf_fetch_t * prev_fetch) {
  if (prev_fetch && prev_fetch->prev_report_id == REPORT_ID_NONE) {
    if (prev_fetch->prev_report_id == REPORT_ID_NONE) {
      // We haven't printed this single-fetch yet
      KDF_PANIC_ON(prev_fetch->first_fetch_str == NULL || prev_fetch->first_fetch_bt == 0, "Found a fetch with a first_fetch_str=%px, first_fetch_bt=%lu\n", prev_fetch->first_fetch_str, prev_fetch->first_fetch_bt);
      prev_fetch->prev_report_id = kdf_report_next_id();
      kdf_report_print_internal(prev_fetch->prev_report_id, NULL, 0, prev_fetch->first_fetch_str, prev_fetch->first_fetch_region, prev_fetch->first_fetch_bt, prev_fetch->first_fetch_rip);
    } else {
      // We've already printed this single-fetch
      kdf_set_report_coverage(prev_fetch->prev_report_id, true);
    }
  }
  return prev_fetch ? prev_fetch->prev_report_id : REPORT_ID_NONE;
}

static size_t kdf_report_fmt(char * report_str, size_t report_str_size, enum report_type rt, enum instr_type it, const void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, kdf_region * region, size_t streaming_dma_access_offset) {
  char rt_str[MAX_TYPE_SIZE], it_str[MAX_TYPE_SIZE], streaming_dma_str[MAX_STR_LEN];
  kdf_rt_str(rt, rt_str, ARRAY_SIZE(rt_str));
  kdf_it_str(it, it_str, ARRAY_SIZE(it_str));

  if (rt == DMA_INV) {
    char sync_bt_str[MAX_STR_LEN];
    kdf_util_bt_str(sync_bt_str, ARRAY_SIZE(sync_bt_str), region->steaming_dma_byte[streaming_dma_access_offset].last_sync_bt);
    snprintf(streaming_dma_str, MAX_STR_LEN, "\"streaming_dma_access\": {\"region_offset\": %lu, \"last_sync_rip\": \"%pS\", \"last_sync_backtrace\": %s}, ", streaming_dma_access_offset, region->steaming_dma_byte[streaming_dma_access_offset].last_sync_rip, sync_bt_str);
  } else streaming_dma_str[0] = '\0';

  int sz = snprintf(report_str, report_str_size, "\"report_type\": \"%s\", \"instr_type\": \"%s\", \"access\": {\"addr\": %llu, \"size\": %lu, \"data_label\": %d, \"ptr_label\": %d}, %s", rt_str, it_str, addr, size, data_label, ptr_label, streaming_dma_str);
  KDF_PANIC_ON(sz < 0 || sz > report_str_size, "Need a larger string for a report."); // Should add better size checks
  return (size_t)sz;
}

static int kdf_report_print(enum report_type rt, enum instr_type it, const void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip, kdf_region * region, kdf_fetch_t * prev_fetch, size_t streaming_dma_access_offset) {
  // First, check whether this report is a duplicate.
  depot_stack_handle_t bt = kdf_util_bt_handle();
  int dup_report_id = kdf_dup_check_insert(rt, it, bt, rip, data_label, ptr_label);
  if (dup_report_id != REPORT_ID_NONE) {
    // This report is a duplicate. Don't print it.
    kdf_set_report_coverage(dup_report_id, true);
    kdf_log_region(region, true, true);
    return dup_report_id;
  }

  // Next, get the 'previous report(s)'. I.e., for a tainted vulnerable operation, get the preceeding double-fetch(es); for a double-fetch, get the preceeding fetch.
  int prev_reports[MAX_PREV_REPORTS];
  size_t prev_report_count = 0;
  if      (rt == VULN_STORE) prev_report_count = kdf_label_to_prev_reports(prev_reports, ptr_label);
  else if (rt == VULN_COND)  prev_report_count = kdf_label_to_prev_reports(prev_reports, data_label);
  else if (rt == DMA_DF || rt == MMIO_DF || rt == PMIO_DF || rt == USER_DF) { prev_reports[0] = kdf_report_print_first_fetch(prev_fetch); prev_report_count++;}
  else if (rt == DMA_INV) ; // No previous report for DMA_INV reports
  else if (rt == DMA_SF || rt == MMIO_SF || rt == USER_SF) ; // No previous report for *_SF reports
  else KDF_PANIC_ON(true, "Error: Called kdf_report_print() with unknown report type (rt = %d)\n", rt);

  // Finally, print this report.
  char report_str[MAX_STR_LEN];
  int this_report_id = kdf_report_next_id();
  kdf_dup_add_id(rt, it, bt, rip, data_label, ptr_label, this_report_id);
  kdf_report_fmt(report_str, ARRAY_SIZE(report_str), rt, it, addr, size, data_label, ptr_label, region, streaming_dma_access_offset);
  kdf_report_print_internal(this_report_id, prev_reports, prev_report_count, report_str, region, bt, rip);
  if (prev_fetch) prev_fetch->prev_report_id = this_report_id;
  return this_report_id;
}

/************************************************************/
/* Per-domain fetch recording *******************************/

static void kdf_fetch_free(kdf_fetch_t * fetch) {
  if (fetch->first_fetch_region) kfree(fetch->first_fetch_region);
  kfree(fetch->first_fetch_str);
  kfree(fetch);
}

static kdf_fetch_t * kdf_fetch_alloc(enum report_type rt, enum instr_type it, const void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip, kdf_region * region) {
  char report_str[MAX_STR_LEN];
  depot_stack_handle_t bt = kdf_util_bt_handle();
  size_t len = kdf_report_fmt(report_str, ARRAY_SIZE(report_str), rt, it, addr, size, data_label, ptr_label, NULL, 0);

  kdf_fetch_t * fetch = kzalloc(sizeof(kdf_fetch_t), GFP_KERNEL);
  mtree_store(&kdfsan_get_context()->pstate.fetch_ptrs, (unsigned long)fetch, fetch, GFP_KERNEL); // mtree[ptr] = ptr...

  fetch->prev_report_id = REPORT_ID_NONE;
  fetch->first_fetch_rip = rip;
  fetch->first_fetch_bt = bt;

  fetch->first_fetch_str = kzalloc(len+1, GFP_KERNEL);
  strcpy(fetch->first_fetch_str, report_str);

  if (region) {
    fetch->first_fetch_region = kzalloc(sizeof(kdf_region), GFP_KERNEL);
    memcpy(fetch->first_fetch_region,region,sizeof(kdf_region));
  } else {
    fetch->first_fetch_region = NULL;
  }

  return fetch;
}

static kdf_fetch_t * kdf_fetch_copy_alloc(kdf_fetch_t * fetch, struct maple_tree * ptrs_tree) {
  kdf_fetch_t * fetch_copy = kzalloc(sizeof(kdf_fetch_t), GFP_KERNEL);
  mtree_store(ptrs_tree, (unsigned long)fetch_copy, fetch_copy, GFP_KERNEL); // mtree[ptr] = ptr...

  fetch_copy->prev_report_id = fetch->prev_report_id;
  fetch_copy->first_fetch_rip = fetch->first_fetch_rip;
  fetch_copy->first_fetch_bt = fetch->first_fetch_bt;

  fetch_copy->first_fetch_str = kzalloc(strlen(fetch->first_fetch_str), GFP_KERNEL);
  strcpy(fetch_copy->first_fetch_str, fetch->first_fetch_str);

  if (fetch->first_fetch_region) {
    fetch_copy->first_fetch_region = kzalloc(sizeof(kdf_region), GFP_KERNEL);
    memcpy(fetch_copy->first_fetch_region, fetch->first_fetch_region, sizeof(kdf_region));
  } else {
    fetch_copy->first_fetch_region = NULL;
  }

  return fetch_copy;
}

static void kdf_policies_domain_destroy(struct kdfsan_policies_state * pstate) {
  pstate->initialized = false;

  // Free each pointer in fetch_ptrs
  struct maple_tree * fetch_ptrs = &kdfsan_get_context()->pstate.fetch_ptrs;
  void *fetch_ptr = NULL;
  unsigned long index = 0;
  mt_for_each(fetch_ptrs, fetch_ptr, index, (unsigned long) ULONG_MAX) kdf_fetch_free(fetch_ptr);
  mtree_destroy(&pstate->fetch_ptrs);

  mtree_destroy(&pstate->fetches);
  memset(pstate->reports_covered, false, sizeof(pstate->reports_covered)); // Invalidate all of this domain's reports upon domain exit
}

static void kdf_policies_domain_init(struct kdfsan_policies_state * pstate) {
  mt_init(&pstate->fetches);
  mt_init(&pstate->fetch_ptrs);
  memset(pstate->reports_covered, false, sizeof(pstate->reports_covered)); // Invalidate all of this domain's reports, just to be safe
  pstate->initialized = true;
}

void kdf_policies_domain_enter(void) {
  struct kdfsan_policies_state * pstate = &kdfsan_get_context()->pstate;
  if (pstate->initialized) {
    printk("%s:%d: Warning: Entering a domain, but it seems we haven't exited it yet.\n", __FILE__, __LINE__);
    dump_stack();
    kdf_policies_domain_destroy(pstate);
  }
  kdf_policies_domain_init(pstate);
}

void kdf_policies_domain_exit(void) {
  struct kdfsan_policies_state * pstate = &kdfsan_get_context()->pstate;
  if (pstate->initialized) kdf_policies_domain_destroy(pstate);
  else { printk("%s:%d: Warning: Exiting a domain but was not in a domain in the first place.\n", __FILE__, __LINE__); dump_stack(); }
}

// Returns NULL if there was no previous access, or a pointer to the previous fetch
static kdf_fetch_t * domain_get_prev_fetch(const void * addr, uptr size, kdf_region * region) {
  // First, check if there's a matching access in the domain-local "fetches" tree
  struct kdfsan_policies_state * pstate = &kdfsan_get_context()->pstate;
  if (pstate->initialized) {
    for (int i = 0; i < size; i++) {
      // TODO: Rather than returning the first fetch we come across, return multiple fetches, in case there are different fetches to different bytes of the region
      kdf_fetch_t * fetch = mtree_load(&pstate->fetches, (unsigned long)addr+i);
      if (fetch) return fetch;
    }
  }

  // Second, check if there's a matching access in the global "stores" tree
  if (region) {
    for (int i = 0; i < size; i++) {
      // TODO: Rather than returning the first fetch we come across, return multiple fetches, in case there are different fetches to different bytes of the region
      kdf_fetch_t * store = mtree_load(&region->stores, (unsigned long)addr+i);
      if (store) return store;
    }
  }

  return NULL;
}

static void domain_fetch_addr(const void * addr, uptr size, kdf_fetch_t * fetch, bool is_store, kdf_region * region) {
  if (!fetch) return; // Print warning?
  bool is_persistent_access = is_store && region;

  if (!is_persistent_access) {
    // Save to domain-local "fetches" tree
    struct kdfsan_policies_state * pstate = &kdfsan_get_context()->pstate;
    if (!pstate->initialized) return;
    mtree_store_range(&pstate->fetches, (unsigned long)addr, (unsigned long)addr+size-1, fetch, GFP_KERNEL);
  } else {
    // Save to global "stores" tree
    kdf_fetch_t * store = kdf_fetch_copy_alloc(fetch, &region->store_ptrs);
    mtree_store_range(&region->stores, (unsigned long)addr, (unsigned long)addr+size-1, store, GFP_KERNEL);
  }
}

/************************************************************/
/* Usercopy hook ********************************************/

static dfsan_label kdf_policies_getuser(const void * src, size_t s, dfsan_label src_ptr_label, void * rip) {
  if (!KDF_DOUBLEFETCH_USER) return 0;
  kdf_fetch_t * fetch = domain_get_prev_fetch(src, s, NULL);
  dfsan_label data_label = 0;
  if (!fetch) {
    fetch = kdf_fetch_alloc(USER_SF, GETUSER, src, s, 0, src_ptr_label, rip, NULL);
  } else {
    int report_id = kdf_report_print(USER_DF, GETUSER, src, s, 0, src_ptr_label, rip, NULL, fetch, 0);
    data_label = kdf_get_df_label(report_id);
  }
  domain_fetch_addr(src, s, fetch, false, NULL);
  return data_label;
}

static void kdf_policies_putuser(void * dst, size_t s, dfsan_label data_label, dfsan_label dst_ptr_label, void * rip) {
  if (!KDF_DOUBLEFETCH_USER) return;
  kdf_fetch_t * fetch = domain_get_prev_fetch(dst, s, NULL);
  if (!fetch) {
    fetch = kdf_fetch_alloc(USER_SF, PUTUSER, dst, s, data_label, dst_ptr_label, rip, NULL);
  }
  domain_fetch_addr(dst, s, fetch, true, NULL);
}

/************************************************************/
/* Region helpers **********************************************/

static kdf_region * regions_find_by_cpuaddr(void * cpu_addr) {
  return mtree_load(&regions_tree, (unsigned long)cpu_addr);
}

static kdf_region * regions_find_by_dev(struct device *dev, u64 bus_addr) {
  kdf_region *curr = NULL;
  MA_STATE(mas, &regions_tree, 0, 0);
  rcu_read_lock();
  mas_for_each(&mas, curr, (unsigned long) ULONG_MAX) {
    if (dev->id == curr->dev_id && bus_addr >= curr->bus_addr && bus_addr < curr->bus_addr + curr->s) {
	rcu_read_unlock();
	return curr;
    }
  }
  rcu_read_unlock();
  return NULL;
}

/************************************************************/
/* Load/store hooks *************************************/

static void kdf_access_streaming(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip, bool is_store, kdf_region * region) {
  if (!KDF_DOUBLEFETCH_DMA_STREAMING) return;
  size_t load_offset_begin = addr - region->cpu_addr;
  for (size_t i = load_offset_begin; i < load_offset_begin + size; i++) {
    if (i >= region->s) {
      printk("%s:%d: Warning: Access to region goes out-of-bounds: load_offset=%d, access = {addr=0x%px, size=%lu, data_label=%d, ptr_label=%d}, region = {dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu}\n", __FILE__, __LINE__, i, addr, size, data_label, ptr_label, region->dev_id, region->bus_addr, region->cpu_addr, region->s);
      break;
    }
    if (!region->steaming_dma_byte[i].is_cpu_accessible) {
	kdf_report_print(DMA_INV, is_store ? STORE : LOAD, addr, size, data_label, ptr_label, rip, region, NULL, i);
	return;
    }
  }
}

static dfsan_label kdf_access_nonstreaming(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip, bool is_store, kdf_region * region, bool stores_kernel_virt_ptr) {
  if (region->is_dma && !KDF_DOUBLEFETCH_DMA_COHERENT) return 0;
  if (!region->is_dma && !KDF_DOUBLEFETCH_MMIO) return 0;

  if (addr + size > region->cpu_addr + region->s) {
    printk("%s:%d: Warning: Access to region goes out-of-bounds: access = {addr=0x%px, size=%lu, data_label=%d, ptr_label=%d}, region = {dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu, is_dma=%s}\n", __FILE__, __LINE__, addr, size, data_label, ptr_label, region->dev_id, region->bus_addr, region->cpu_addr, region->s, region->is_dma ? "true" : "false");
  }

  kdf_fetch_t * fetch = domain_get_prev_fetch(addr, size, region);
  if (!fetch || stores_kernel_virt_ptr) {
    fetch = kdf_fetch_alloc(region->is_dma ? DMA_SF : MMIO_SF, is_store ? STORE : LOAD, addr, size, data_label, ptr_label, rip, region);
    if (stores_kernel_virt_ptr) fetch->prev_report_id = kdf_report_print(region->is_dma ? DMA_SF : MMIO_SF, STORE, addr, size, data_label, ptr_label, rip, region, NULL, 0);
  }
  else if (!is_store) {
      int report_id = kdf_report_print(region->is_dma ? DMA_DF : MMIO_DF, LOAD, addr, size, data_label, ptr_label, rip, region, fetch, 0);
      data_label = kdf_union(data_label, kdf_get_df_label(report_id));
  }
  domain_fetch_addr(addr, size, fetch, is_store, region);
  return data_label;
}

dfsan_label kdf_policies_load(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) {
  if ((unsigned long)addr < PAGE_SIZE) {
    ; // Null-pointer load... Let's stay away...
  } else if (access_ok(addr, size)) {
    // Load from userspace
    data_label = kdf_policies_getuser(addr, size, ptr_label, rip);
  } else {
    // Potentially load from DMA/MMIO
    kdf_region * region = regions_find_by_cpuaddr(addr);
    if (region == NULL) return data_label;
    //printk("%s:%d: Loading from region: access = {addr=0x%px, size=%lu, data_label=%d, ptr_label=%d}, region = {dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu}\n", __FILE__, __LINE__, addr, size, data_label, ptr_label, region->dev_id, region->bus_addr, region->cpu_addr, region->s);

    if (region->is_streaming_dma) kdf_access_streaming(addr, size, data_label, ptr_label, rip, false, region);
    else data_label = kdf_access_nonstreaming(addr, size, data_label, ptr_label, rip, false, region, false);
  }

  return data_label;
}

void kdf_policies_store(u64 data, void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label, void * rip) {
  if (kdf_has_df_label(ptr_label)) {
    // If the ptr_label contains the "double-fetch" label: Print report
    kdf_report_print(VULN_STORE, STORE, addr, size, data_label, ptr_label, rip, NULL, NULL, 0);
  }

  if ((unsigned long)addr < PAGE_SIZE) {
    ; // Null-pointer store... Let's stay away...
  } else if (access_ok(addr, size)) {
    // Store to userspace
    kdf_policies_putuser(addr, size, data_label, ptr_label, rip);
  } else {
    // Potentially store to DMA/MMIO
    kdf_region * region = regions_find_by_cpuaddr(addr);
    if (region == NULL) return;
    //printk("%s:%d: Storing to region: access = {addr=0x%px, size=%lu, data_label=%d, ptr_label=%d}, region = {dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu}\n", __FILE__, __LINE__, addr, size, data_label, ptr_label, region->dev_id, region->bus_addr, region->cpu_addr, region->s);

    if (region->is_streaming_dma) kdf_access_streaming(addr, size, data_label, ptr_label, rip, true, region);
    else kdf_access_nonstreaming(addr, size, data_label, ptr_label, rip, true, region, kdf_is_kernel_ptr(data));
  }
}

/************************************************************/
/* Region alloc/free ****************************************/

static void kdf_policies_region_alloc(struct device *dev, u64 bus_addr, void * cpu_addr, size_t s, bool is_dma, bool is_streaming_dma, void * rip) {
  if (s == 0) return;
  // Add the region [cpu_addr,cpu_addr+s) to the list of regions
  kdf_region * region = kzalloc(sizeof(kdf_region), GFP_KERNEL);
  if (region == NULL) {
    printk("%s:%d: Error: Could not allocate memory for 'region': dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr, cpu_addr, s);
    return;
  }
  region->dev_id = dev ? dev->id : 0;
  region->bus_addr = bus_addr;
  region->cpu_addr = cpu_addr;
  region->s = s;
  region->is_dma = is_dma;
  region->is_streaming_dma = is_streaming_dma;
  region->alloc_rip = rip;
  depot_stack_handle_t bt = kdf_util_bt_handle();
  region->alloc_bt = bt;
  if (is_streaming_dma) {
    kdf_streaming_dma_metadata * steaming_dma_byte = kzalloc(sizeof(kdf_streaming_dma_metadata) * s, GFP_KERNEL);
    if (steaming_dma_byte == NULL) {
      printk("%s:%d: Error: Could not allocate memory for 'steaming_dma_byte': dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr, cpu_addr, s);
      kfree(region);
      return;
    }
    region->steaming_dma_byte = steaming_dma_byte;
    for (size_t i = 0; i < s; i++) {
	region->steaming_dma_byte[i].is_cpu_accessible = false; // Streaming DMA is _not_ CPU accessible when allocated.
	region->steaming_dma_byte[i].last_sync_rip = rip;
	region->steaming_dma_byte[i].last_sync_bt = bt;
    }
  } else {
    region->steaming_dma_byte = NULL;
  }
  mt_init(&region->stores);
  mt_init(&region->store_ptrs);
  mtree_store_range(&regions_tree, (unsigned long)cpu_addr, (unsigned long)cpu_addr+s-1, region, GFP_KERNEL);
  kdf_log_region(region, true, false);
}

static void kdf_policies_region_free_node(struct rcu_head *head) {
  kdf_region * region = container_of(head, kdf_region, rcu);
  //printk("%s:%d: Freeing resources for region: dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu\n", __FILE__, __LINE__, region->dev_id, region->bus_addr, region->cpu_addr, region->s);
  kdf_set_label(0, region->cpu_addr, region->s); // Clear taint of region just to be safe (we're not tainting the region anyway)
  if(region->steaming_dma_byte) kfree(region->steaming_dma_byte); // Only need to free if: region->is_streaming_dma == true

  // Free each pointer in store_ptrs
  struct maple_tree * store_ptrs = &region->store_ptrs;
  void *store_ptr = NULL;
  unsigned long index = 0;
  mt_for_each(store_ptrs, store_ptr, index, (unsigned long) ULONG_MAX) kdf_fetch_free(store_ptr);
  mtree_destroy(&region->store_ptrs);
  mtree_destroy(&region->stores);

  kfree(region);
}

/************************************************************/
/* DMA alloc/free/sync hooks ********************************/

void noinline kdf_policies_dma_alloc(struct device *dev, dma_addr_t bus_addr, void * cpu_addr, size_t s, bool is_streaming_dma, void * rip) {
  //printk("%s:%d: Allocating DMA region: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu, is_streaming_dma=%s\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr, cpu_addr, s, is_streaming_dma ? "true" : "false");
  kdf_policies_region_alloc(dev, bus_addr, cpu_addr, s, true, is_streaming_dma, rip);
}

void noinline kdf_policies_dma_free(struct device *dev, dma_addr_t bus_addr) {
  // Delete the DMA range corresponding to (dev, bus_addr) from the list of DMA ranges.
  //printk("%s:%d: Freeing DMA region... (dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px)\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr);
  mtree_lock(&regions_tree);
  kdf_region * region = regions_find_by_dev(dev, bus_addr);
  if (region == NULL) {
    mtree_unlock(&regions_tree);
    printk("%s:%d: Warning: Attempting to free untracked DMA region: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr);
    return;
  }
  //printk("%s:%d: Freeing DMA region: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), region->dev_id, region->bus_addr, region->cpu_addr, region->s);
  MA_STATE(mas, &regions_tree, (unsigned long)region->cpu_addr, (unsigned long)region->cpu_addr+region->s-1);
  void * ret = mas_erase(&mas);
  mtree_unlock(&regions_tree);
  if (!ret) printk("%s:%d: Warning: mas_erase() returned NULL when attempting to free DMA region: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, bus_addr);
  call_rcu(&region->rcu, kdf_policies_region_free_node);
}

void kdf_policies_dma_alloc_sg(struct device *dev, struct scatterlist *sg, int ents, void * rip) {
  int i;
  struct scatterlist *tmpsg;
  for_each_sg(sg, tmpsg, ents, i) {
    kdf_policies_dma_alloc(dev, sg_dma_address(tmpsg), sg_virt(tmpsg), sg_dma_len(tmpsg), true, rip);
  }
}

void kdf_policies_dma_free_sg(struct device *dev, struct scatterlist *sg, int nents) {
  int i;
  struct scatterlist *tmpsg;
  for_each_sg(sg, tmpsg, nents, i) {
    if (sg_dma_len(tmpsg) == 0) break; // We don't have the actual number of ents (only the passed in nents), so we'll use this to check for the end of the sglist
    kdf_policies_dma_free(dev, sg_dma_address(tmpsg));
  }
}

void kdf_policies_dma_sync(struct device *dev, dma_addr_t addr, size_t size, bool is_for_cpu, void * rip) {
  kdf_region * region = regions_find_by_dev(dev, addr);
  if (region == NULL) {
    printk("%s:%d: Warning: Attempting to sync untracked DMA region: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), dev->id, addr);
    return;
  }
  size_t sync_offset_begin = addr - region->bus_addr; // This may be a partial sync
  depot_stack_handle_t bt = kdf_util_bt_handle();
  for (size_t i = 0; i < size; i++) {
    if (sync_offset_begin + i >= region->s) {
      printk("%s:%d: Warning: DMA sync goes out-of-bounds. Either this is a bug in the driver, or a bug in the way KDFSAN models DMA regions: dev_drv=%s, dev_name=%s, dev_id=%u, bus_addr=0x%px, cpu_addr=0x%px, s=%lu\n", __FILE__, __LINE__, dev_driver_string(dev), dev_name(dev), region->dev_id, region->bus_addr, region->cpu_addr, region->s);
      return;
    }
    region->steaming_dma_byte[sync_offset_begin + i].is_cpu_accessible = is_for_cpu;
    region->steaming_dma_byte[sync_offset_begin + i].last_sync_rip = rip;
    region->steaming_dma_byte[sync_offset_begin + i].last_sync_bt = bt;
  }
}

void kdf_policies_dma_sync_sg(struct device *dev, struct scatterlist *sg, int nelems, bool is_for_cpu, void * rip) {
  int i;
  struct scatterlist *tmpsg;
  for_each_sg(sg, tmpsg, nelems, i) {
    if (sg_dma_len(tmpsg) == 0) break; // We don't have the actual number of ents (only the passed in nelems), so we'll use this to check for the end of the sglist
    kdf_policies_dma_sync(dev, sg_dma_address(tmpsg), sg_dma_len(tmpsg), is_for_cpu, rip);
  }
}

/************************************************************/
/* MMIO map/unmap hooks *************************************/

void kdf_policies_ioremap(resource_size_t bus_addr, void __iomem *cpu_addr, size_t size, void * rip) {
  if (!KDF_DOUBLEFETCH_MMIO) return;
  //printk("%s:%d: Allocating MMIO region: bus_addr=0x%px, cpu_addr=0x%px, size=%lu\n", __FILE__, __LINE__, bus_addr, cpu_addr, size);
  kdf_policies_region_alloc(NULL, bus_addr, cpu_addr, size, false, false, rip);
}

void kdf_policies_iounmap(void __iomem *cpu_addr) {
  if (!KDF_DOUBLEFETCH_MMIO) return;
  //printk("%s:%d: Freeing MMIO region... (cpu_addr=0x%px)\n", __FILE__, __LINE__, cpu_addr);
  mtree_lock(&regions_tree);
  kdf_region * region = regions_find_by_cpuaddr(cpu_addr);
  if (region == NULL) {
    mtree_unlock(&regions_tree);
    printk("%s:%d: Warning: Attempting to free untracked MMIO region: cpu_addr=0x%px\n", __FILE__, __LINE__, cpu_addr);
    return;
  }
  //printk("%s:%d: Freeing MMIO region: cpu_addr=0x%px\n", __FILE__, __LINE__, cpu_addr);
  MA_STATE(mas, &regions_tree, (unsigned long)region->cpu_addr, (unsigned long)region->cpu_addr+region->s-1);
  void * ret = mas_erase(&mas);
  mtree_unlock(&regions_tree);
  if (!ret) printk("%s:%d: Warning: mas_erase() returned NULL when attempting to free MMIO region: cpu_addr=0x%px\n", __FILE__, __LINE__, cpu_addr);
  call_rcu(&region->rcu, kdf_policies_region_free_node);
}


/************************************************************/
/* PMIO in/out hooks ****************************************/

// TODO: Add hooks for request_region() and release_region()?

void kdf_policies_pmio_out(void *src, u16 port, size_t size, dfsan_label src_label, dfsan_label port_label, dfsan_label size_label, void * rip) {
  if (!KDF_DOUBLEFETCH_PMIO) return;
  kdf_fetch_t * fetch = domain_get_prev_fetch((void*)port, size, NULL);
  if (!fetch) {
    fetch = kdf_fetch_alloc(PMIO_SF, OUT, port, size, kdf_read_label(src, size), port_label, rip, NULL);
  }
  domain_fetch_addr((void*)port, size, fetch, true, NULL);
}

void kdf_policies_pmio_in(u16 port, size_t size, void * dest, dfsan_label port_label, dfsan_label size_label, dfsan_label dest_label, void * rip) {
  if (!KDF_DOUBLEFETCH_PMIO) return;
  kdf_fetch_t * fetch = domain_get_prev_fetch((void*)port, size, NULL);
  if (!fetch) {
    fetch = kdf_fetch_alloc(PMIO_SF, IN, (void*)port, size, 0, port_label, rip, NULL);
  } else {
    int report_id = kdf_report_print(PMIO_DF, IN, (void*)port, size, 0, port_label, rip, NULL, fetch, 0);
    // TODO: Propagate the label of 'port' to the output? (Similar to load pointer propagation?)
    kdf_add_label(kdf_get_df_label(report_id), dest, size);
  }
  domain_fetch_addr((void*)port, size, fetch, false, NULL);
}

/************************************************************/
/* Label invalidation hooks *********************************/

#if 0
void kdf_policies_cond_fwd(dfsan_label label, void * rip) {
  if (label != 0) kdf_invalidate_label(label);
}
#endif

/************************************************************/
/* Vulnerable condition hooks *******************************/

static void kdf_policies_vuln_cond(dfsan_label label, void * rip, enum instr_type it) {
  if (!kdf_has_df_label(label)) return;
  kdf_report_print(VULN_COND, it, NULL, 0, label, 0, rip, NULL, NULL, 0);
}
void kdf_policies_cond_bkwd(dfsan_label label, void * rip) { kdf_policies_vuln_cond(label, rip, COND); }
void kdf_policies_bugon(dfsan_label label, void * rip) { kdf_policies_vuln_cond(label, rip, BUG); }

/************************************************************/
/* Initialization *******************************************/

void kdf_policies_init(void) {
  kdf_util_set_rand();
}

void kdf_policies_post_boot(void) {
  kdf_report_enable();
}

#endif