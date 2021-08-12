// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_shadow.h"
#include "kdfsan_internal.h"
#include "kdfsan_policies.h"

#define BITVECTOR_SIZE NUM_LABELS >> INTERNAL_LABEL_LOG_BIT_WIDTH
#define LABEL_SLOT_SIZE 8

typedef struct {
  u8 b[BITVECTOR_SIZE];
  char desc[KDF_DESC_LEN];
} dfsan_label_bitvector;

typedef struct {
  dfsan_label last_label;
  /* keep also the current color, so we keep bitvector compact in the presence of many label unions*/
  dfsan_label last_color; 
  dfsan_label_bitvector bitvectors[NUM_LABELS];
} dfsan_label_list;
static dfsan_label_list* label_list = NULL;


spinlock_t dfsan_label_lock;

// These should be active with CONFIG_SMP with nosmp these are not needed
#define kdf_enter_atomic(flags) spin_lock_irqsave(&dfsan_label_lock, flags)
#define kdf_exit_atomic(flags)  spin_unlock_irqrestore(&dfsan_label_lock, flags)
#define kdf_init_atomic() spin_lock_init(&dfsan_label_lock)
// This should be enough to guarantee atomicity of a 1-2 byte value 
#define KDF_ATOMIC_READ(value) READ_ONCE(value)


#if 0
// TODO activate this on !CONFIG_SMP
#define kdf_enter_atomic(flags) 
#define kdf_exit_atomic(flags)
#define kdf_init_atomic()
#define KDF_ATOMIC_READ(value) value
#endif

// An actual label within label_list (i.e., not just "NUM_LABELS - 1") to be returned when attempting to create a new label when no more labels are available
static dfsan_label max_label = -1;

/*************************************************************/
/************************** Helpers **************************/

static dfsan_label search_unique_color(dfsan_label start_label, dfsan_label color_slot, dfsan_label color_position){
  dfsan_label it;
  dfsan_label last_label = KDF_ATOMIC_READ(label_list->last_label);
  for (it = start_label; it <= last_label; it++){
      u8* b = label_list->bitvectors[it].b;
      if (b[color_slot] != (1 << color_position)){
          continue;
      }
      bool match = true;
      for (dfsan_label j =  0; j < BITVECTOR_SIZE; j++){
          if (j != color_slot && b[j] != 0){
             match = false;
             break;
          }
      }
      if (match)
          return it;
  }

  KDF_PANIC_ON(true, "search_unique_color error: Unreachable code");
  return 0;
}

static void kdf_print_bitvector(dfsan_label lbl) {
  KDF_CHECK_LABEL(lbl);
  char str_kdf_print_bitvector[NUM_LABELS + 1] = {0}; // +1 for all labels + NULL terminator
  dfsan_label last_label = KDF_ATOMIC_READ(label_list->last_label);

  for(dfsan_label i = 0; i <= last_label; i++) {
    u8 this_byte = label_list->bitvectors[lbl].b[i >> 3];
    u8 this_bit = (this_byte >> (i % LABEL_SLOT_SIZE)) & 1;
    str_kdf_print_bitvector[i] = this_bit ? '1' : '0';
  }
  printk("label %3d: bitvector=[%s...], desc=\"%s\"\n", lbl, str_kdf_print_bitvector, label_list->bitvectors[lbl].desc);
}

// Note: If b is NULL then a new label is created with a single unique bit set
static dfsan_label kdf_create_next_label(u8 *b, const char *desc) {
  // Check whether we can create a new label
  if(label_list->last_label + 1 >= NUM_LABELS) {
    //printk("KDFSan ERROR: out of labels; assigning 'max-label' label\n");
    return max_label;
  }
  
  //printk("KDFSan: last_label increased to %d",label_list->last_label);

  // The safest way to do it is to lock all accesses to bitvector read/writes
  // to gurantee all operations are coherent across concurrent thread. However
  // as reads might be more frequent than label creation, just lock on memory
  // writes, and only increment next_label after we insert a new label. Then
  // readers read next_label/next_color atomically. This guarantees that readers
  // have either the previous or next view on the label bitvectors. In the worst
  // case scenario we might add the same label multiple times if union creation
  // is executed concurrently from multiple threads.
  unsigned long irq_flags;

  kdf_enter_atomic(irq_flags);
  // Modify the label count after we insert the element so we don't
  // have inconsistencies with concurent readers.
  dfsan_label this_label = label_list->last_label + 1;
  dfsan_label_bitvector * this_bitvector = &label_list->bitvectors[this_label];

  if(b == NULL) {
    // If bitvector was not supplied, create one with a single unique bit set in label_list
    dfsan_label this_color = ++label_list->last_color;
    dfsan_label this_color_slot = this_color >> 3;
    this_bitvector->b[this_color_slot] = 1 << (this_color % LABEL_SLOT_SIZE);

  }
  else {
    // If bitvector was supplied, copy it into label_list
    dfsan_label this_color = label_list->last_color;
    dfsan_label this_color_size = (this_color >> 3) + 1;
    __memcpy(this_bitvector->b, b, this_color_size); // size could probably just be this_label; that'd be slightly faster
  }
   
  /* Now make all readers aware of this new label */
  label_list->last_label = this_label;
  kdf_exit_atomic(irq_flags);

  kdf_util_strlcpy(this_bitvector->desc, desc, KDF_DESC_LEN);

  return this_label;
}

void kdf_init_internal_data(void) {
  size_t size = sizeof(dfsan_label_list);
  printk("kdf_alloc_label_list: allocating label_list of size %zu\n", size);
  label_list = kzalloc(size, GFP_KERNEL);

  kdf_init_atomic();

  // Initialize 0 label: b should already be set to all 0; last_label should already by 0
  KDF_PANIC_ON(label_list->last_label != 0, "KDFSan error: the last_label should be 0 after label_list is initialized");
  kdf_util_strlcpy(label_list->bitvectors[0].desc, "no-taint", KDF_DESC_LEN);
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(0);
  #endif

  max_label = kdf_create_label("max-label");
}

/************************************************************************/
/************************** Interface handlers **************************/

#define MAX_BUF_LEN 4096

static void kdf_memtransfer_buf_init(u8 *dst, size_t buf_count, const u8 *src, size_t src_count) {
  if (src_count > buf_count || access_ok(src, src_count)) memset(dst, 0, buf_count); // Don't copy from userspace (this causes a crash if performed too early in boot)
  else memcpy(dst, src, src_count); // Load from kernelspace
}

static u64 kdf_memtransfer_buf_getval64(const u8 *buf, size_t i, bool FORWARDS, size_t buf_count, size_t src_count) {
  if (src_count > buf_count) return 0;
  u64 val64 = 0;
  size_t this_size = min((size_t)8,src_count-i);
  const u8 * buf_curr = FORWARDS ? &buf[i] : &buf[src_count-i-this_size];
  memcpy(&val64, buf_curr, this_size);
  return val64;
}

// NOTE: kdf_memtransfer() performs both: (i) the shadow memtransfer, AND (ii) if perform_policies is set, the associated load/store policies
void kdf_memtransfer(void *dst, const void *src, uptr count, dfsan_label dst_label, dfsan_label src_label, void * rip, bool perform_policies) {
  u8 buf_copy[MAX_BUF_LEN];
  const bool FORWARDS = dst <= src;
  kdf_memtransfer_buf_init(buf_copy, ARRAY_SIZE(buf_copy), src, count);
  for (size_t i = 0; i < count; i++) {
    u8       *tmp_dst = FORWARDS ? &dst[i] : &dst[count-i-1];
    const u8 *tmp_src = FORWARDS ? &src[i] : &src[count-i-1];
    u64 val64 = kdf_memtransfer_buf_getval64(buf_copy, i, FORWARDS, ARRAY_SIZE(buf_copy), count); // Get the current 8-byte word (even though we apply the policies in 1-byte increments)
    dfsan_label this_label = kdf_get_shadow(tmp_src);                                                              // 1. Begin memtransfer
    if (perform_policies) this_label = kdf_policies_load((void*)tmp_src, sizeof(u8), this_label, src_label, rip);  // 2. Load policy
    this_label = PROPAGATE_LOAD_PTR ? kdf_union(this_label, src_label) : this_label;                               // 3. Load pointer propagation
    if (perform_policies) kdf_policies_store(val64, tmp_dst, sizeof(u8), this_label, dst_label, rip);              // 4. Store policy
    this_label = PROPAGATE_STORE_PTR ? kdf_union(this_label, dst_label) : this_label;                              // 5. Store pointer propagation
    kdf_set_shadow(tmp_dst, this_label);                                                                           // 6. Finish shadow memtransfer
  }
}

void kdf_set_label(dfsan_label label, void *addr, uptr size) {
  for (u8* datap = (u8*) addr; size != 0; --size, ++datap) {
    dfsan_label this_label = kdf_get_shadow(datap);
    if (label != this_label) {
      kdf_set_shadow(datap, label);
    }
  }
}

dfsan_label kdf_union(dfsan_label l1, dfsan_label l2) {
  u8 b_tmp_kdf_union[BITVECTOR_SIZE];

  // possible fast paths
  if (l1 == 0) return l2;
  if (l2 == 0) return l1;
  if (l1 == l2) return l1;

  //u8 b_tmp[NUM_LABELS] = {0};
  __memset(b_tmp_kdf_union, 0, BITVECTOR_SIZE);

  KDF_CHECK_LABEL(l1);
  KDF_CHECK_LABEL(l2);

  // get l1's and l2's bitvectors
  dfsan_label_bitvector * b1 = &label_list->bitvectors[l1];
  dfsan_label_bitvector * b2 = &label_list->bitvectors[l2];

  dfsan_label total_labels = KDF_ATOMIC_READ(label_list->last_label);
  dfsan_label label_color_slot = (KDF_ATOMIC_READ(label_list->last_color) >> 3) + 1;

  // bitwise or the bitvectors up until the current color. After that
  // all are zeroes.
  for(int i_bit = 0; i_bit < label_color_slot; i_bit++) {
    b_tmp_kdf_union[i_bit] = b1->b[i_bit] | b2->b[i_bit];
    //KDF_PANIC_ON(b_tmp_kdf_union[i_bit] != 0 && b_tmp_kdf_union[i_bit] != 1, "kdf_union error: bitvector values should only be 0 or 1");
  }

  
  // check if the resulting bitvector exists
  // TODO: it might be faster to iterate from last_label to 0, assuming labels are most commonly union'ed with recently created labels
  for(dfsan_label lbl = 0; lbl <= total_labels; lbl++) {
    if(kdf_util_memcmp(b_tmp_kdf_union, label_list->bitvectors[lbl].b, label_color_slot) == 0) {
      // if resulting bitvector exists, return its label
      return lbl;
    }
  }

  // otherwise, if resulting bitvector does not exist, insert it with a new label
  dfsan_label new_lbl = kdf_create_next_label((u8 *)b_tmp_kdf_union, "created-by-kdf_union");
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(new_lbl);
  #endif

  return new_lbl;
}

dfsan_label kdf_read_label(const void *addr, uptr n) {
  dfsan_label ret_label = 0;
  for (u8* datap = (u8*) addr; n != 0; --n, ++datap) {
    dfsan_label next_label = kdf_get_shadow(datap);
    if (ret_label != next_label) {
      ret_label = kdf_union(ret_label, next_label);
    }
  }
  return ret_label;
}

void kdf_add_label(dfsan_label label_src, void *addr, uptr size) {
  for (u8* datap = (u8*) addr; size != 0; --size, ++datap) {
    dfsan_label label_tmp = kdf_get_shadow(datap);
    if (label_tmp != label_src) {
      dfsan_label label_dst = kdf_union(label_tmp, label_src);
      kdf_set_shadow(datap, label_dst);
    }
  }
}

dfsan_label kdf_create_label(const char *desc) {
  dfsan_label lbl = kdf_create_next_label(NULL, desc);
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(lbl);
  #endif
  return lbl;
}

int kdf_has_label(dfsan_label haver, dfsan_label havee) {
  u8 *b_haver = label_list->bitvectors[haver].b;
  u8 *b_havee = label_list->bitvectors[havee].b;
  dfsan_label last_color_slot = (KDF_ATOMIC_READ(label_list->last_color)) >> 3;
  for(int i = 0; i <= last_color_slot; i++) {
    if((b_havee[i] | b_haver[i]) ^ b_haver[i]) {
      return false;
    }
  }
  return true;
}

// If the given label contains a label with the description desc, returns that label, else returns 0
dfsan_label kdf_has_label_with_desc(dfsan_label label, const char *desc) {
  // For each label with a matching description
  for(dfsan_label this_lbl = 0; this_lbl <= label_list->last_label; this_lbl++) {
    dfsan_label_bitvector *this_bitvector = &label_list->bitvectors[this_lbl];
    if(kdf_util_strcmp(this_bitvector->desc, desc) == 0) {
      // Check whether given label contains it, and if so, return
      if(kdf_has_label(label, this_lbl) == true) {
        return this_lbl;
      }
    }
  }
  return 0;
}

// Return a label with the matching desc. If multiple labels have the given desc, return the lowest matching label. If no label has the given desc, return 0.
dfsan_label kdf_get_label_with_desc(const char *desc) {
  for(dfsan_label this_lbl = 0; this_lbl <= label_list->last_label; this_lbl++) {
    if(kdf_util_strcmp(label_list->bitvectors[this_lbl].desc, desc) == 0) {
      return this_lbl;
    }
  }
  return 0;
}

// Returns the number of descs written to descs_arr
size_t kdf_get_label_descs(dfsan_label label, char descs_arr[][KDF_DESC_LEN], size_t descs_arr_size) {
  if (label == 0 || descs_arr == NULL || descs_arr_size == 0) return 0;
  KDF_CHECK_LABEL(label);
  size_t num_descs = 0;

  u8 *b = label_list->bitvectors[label].b;
  dfsan_label last_color_slot = KDF_ATOMIC_READ(label_list->last_color) >> 3 ;
  dfsan_label current_label = 0;

  for(dfsan_label i = 0; i <= last_color_slot; i++) {
    for (u8 j = 0; j <  LABEL_SLOT_SIZE; j++) {
      if(b[i] & (1 << j)) {
       current_label = search_unique_color(current_label, i, j);
       kdf_util_strlcpy(descs_arr[num_descs], label_list->bitvectors[current_label].desc, KDF_DESC_LEN);
       num_descs++;
      }
    }
  }
  return num_descs;
}

dfsan_label kdf_get_label_count(void) {
  return label_list->last_label;
}

/**********************************************************************/
/****************** Miscellaneous interface handlers ******************/

void kdf_copy_label_info(dfsan_label label, char * dest, size_t count) {
  dfsan_label current_label = 0;
  u8 *b = label_list->bitvectors[label].b;
  bool first_report = true;

  __memset(dest, 0, count);
  CONCAT_STR("label ", dest, count); CONCAT_NUM(label, 10, dest, count); CONCAT_STR(": {", dest, count);

  dfsan_label last_color_slot = KDF_ATOMIC_READ(label_list->last_color) >> 3 ;

  for(dfsan_label i = 0; i <= last_color_slot; i++) {
    //KDF_PANIC_ON(b[i] != 0 && b[i] != 1, "kdf_print_label_info error: bitvector values should only be 0 or 1");
    for (u8 j = 0; j <  LABEL_SLOT_SIZE; j++) {
      if(b[i] & (1 << j)) {
       if(!first_report) { CONCAT_STR(", ", dest, count); }
       current_label = search_unique_color(current_label, i, j);
       CONCAT_STR("(label: ", dest, count); CONCAT_NUM(current_label, 10, dest, count);
       CONCAT_STR(", desc: '", dest, count); CONCAT_STR(label_list->bitvectors[current_label].desc, dest, count);
       CONCAT_STR("')", dest, count);
       first_report = false;
      }
    }
  }
  CONCAT_STR("}", dest, count);
  KDF_PANIC_ON(first_report && label != 0, "kdf_copy_label_info error: a non-zero label should be composed of at least one bit");
}

void kdf_internal_task_create(struct task_struct *task)
{
	struct kdfsan_ctx *ctx = &task->kdfsan_ctx;
	//struct thread_info *info = current_thread_info();

	__memset(ctx, 0, sizeof(*ctx));
	ctx->allow_reporting = true;
	//kdfsan_internal_unpoison_memory(info, sizeof(*info), false);
}
