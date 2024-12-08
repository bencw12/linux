#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/hugetlb.h>
#include <linux/sched/clock.h>
#include <linux/oom.h>
#include <linux/rwsem.h>
#include <linux/page_detective.h>

#undef pr_fmt
#define pr_fmt(fmt) "Page Detective: " fmt

/*
 * Walk 4T of VA space at a time, in order to periodically release the mmap
 * lock
 */
#define PD_WALK_MAX_RANGE	BIT(42)
static DEFINE_MUTEX(page_detective_mutex);

static void pd_get_comm_pid(struct mm_struct *mm, char *comm, int *pid) {
  struct task_struct *task;

  rcu_read_lock();
  task = rcu_dereference(mm->owner);
  if (task) {
    strscpy(comm, task->comm, TASK_COMM_LEN);
    *pid = task->pid;
  } else {
    strscpy(comm, "__ exited __", TASK_COMM_LEN);
    *pid = -1;
  }
  rcu_read_unlock();
}

struct pd_private_user {
	struct mm_struct *mm;
	unsigned long pfn;
	long maps;
  struct fault_info *info;
};

#define ENTRY_NAME(entry_page_size) ({                            \
    unsigned long __entry_page_size = (entry_page_size);          \
                                                                  \
(__entry_page_size == PUD_SIZE) ? "pud" :                         \
(__entry_page_size == PMD_SIZE) ? "pmd" : "pte";                  \
})                                             

static void pd_print_entry_user(struct pd_private_user *pr,
				unsigned long pfn_current,
				unsigned long addr,
				unsigned long entry_page_size,
				unsigned long entry,
				bool is_hugetlb) {
  unsigned long pfn = pr->pfn;

  if (pfn_current <= pfn &&
      pfn < (pfn_current + (entry_page_size >> PAGE_SHIFT))) {
    char comm[TASK_COMM_LEN];
    int pid;

    pd_get_comm_pid(pr->mm, comm, &pid);
    memcpy(pr->info->comm, comm, TASK_COMM_LEN);
    pr->info->addr = pfn << PAGE_SHIFT;
    pr->info->type = 3;

    addr += ((pfn << PAGE_SHIFT) & (entry_page_size - 1));
    /* pr_info("%smapped by PID[%d] cmd[%s] mm[%px] pgd[%px] at addr[%lx] %s[%lx]\n", */
    /* 	    is_hugetlb ? "hugetlb " : "", */
    /* 	    pid, comm, pr->mm, pr->mm->pgd, addr, */
    /* 	    ENTRY_NAME(entry_page_size), entry); */
    /* pd_show_vma_info(pr->mm, addr); */
    pr->maps++;
  }
}

static int pd_pud_entry_user(pud_t *pud, unsigned long addr, unsigned long next,
			     struct mm_walk *walk) {
  pud_t pudval = READ_ONCE(*pud);

  cond_resched();
  if (!pud_user_accessible_page(pudval))
    return 0;

  pd_print_entry_user(walk->private, pud_pfn(pudval), addr, PUD_SIZE,
		      pud_val(pudval), false);
  return 0;
}

static int pd_pmd_entry_user(pmd_t *pmd, unsigned long addr, unsigned long next,
			     struct mm_walk *walk) {
  pmd_t pmdval = READ_ONCE(*pmd);

  cond_resched();
  if (!pmd_user_accessible_page(pmdval))
    return 0;

  pd_print_entry_user(walk->private, pmd_pfn(pmdval), addr, PMD_SIZE,
		      pmd_val(pmdval), false);

  return 0;
}

static int pd_pte_entry_user(pte_t *pte, unsigned long addr, unsigned long next,
			     struct mm_walk *walk) {
  pte_t pteval = READ_ONCE(*pte);

  if (!pte_user_accessible_page(pteval))
    return 0;

  pd_print_entry_user(walk->private, pte_pfn(pteval), addr, PAGE_SIZE,
		      pte_val(pteval), false);

  return 0;
}

static int pd_hugetlb_entry(pte_t *pte, unsigned long hmask, unsigned long addr,
			    unsigned long next, struct mm_walk *walk) {
  pte_t pteval = READ_ONCE(*pte);

  cond_resched();
  pd_print_entry_user(walk->private, pte_pfn(pteval), addr, next - addr,
		      pte_val(pteval), true);
  return 0;
}

static inline int mmap_read_trylock(struct mm_struct *mm) {
  int ret;
  ret = down_read_trylock(&mm->mmap_sem);
  return ret;
}

static inline void mmap_read_lock(struct mm_struct *mm) {
  down_read(&mm->mmap_sem);
}

static inline void mmap_read_unlock(struct mm_struct *mm) {
  up_read(&mm->mmap_sem);
}

struct pd_private_kernel {
  unsigned long pfn;
  unsigned long direct_map_addr;
  bool direct_map;
  unsigned long vmalloc_maps;
  long maps;
  struct fault_info *info;
};

static void pd_print_entry_kernel(struct pd_private_kernel *pr,
                                  unsigned long pfn_current,
                                  unsigned long addr,
                                  unsigned long entry_page_size,
                                  unsigned long entry)
{
	unsigned long pfn = pr->pfn;

	if (pfn_current <= pfn &&
	    pfn < (pfn_current + (entry_page_size >> PAGE_SHIFT))) {
		bool v, d;

		addr += ((pfn << PAGE_SHIFT) & (entry_page_size - 1));
		v = (addr >= VMALLOC_START && addr < VMALLOC_END);
		d = (pr->direct_map_addr == addr);

		/* if (v) */
		/* 	pr->vmalloc_maps++; */
    /* else if (d) */
		/* 	pr->direct_map = true; */

		pr->info->addr = pfn << PAGE_SHIFT;
		pr->info->type = 2;

		pr->maps++;
	}
}

static int pd_pud_entry_kernel(pud_t *pud, unsigned long addr,
                               unsigned long next,
                               struct mm_walk *walk)
{
	pud_t pudval = READ_ONCE(*pud);

	cond_resched();
	if (!pud_leaf(pudval))
		return 0;

	pd_print_entry_kernel(walk->private, pud_pfn(pudval), addr,
                        PUD_SIZE, pud_val(pudval));

	return 0;
}

static int pd_pmd_entry_kernel(pmd_t *pmd, unsigned long addr,
                               unsigned long next,
                               struct mm_walk *walk)
{
	pmd_t pmdval = READ_ONCE(*pmd);

	cond_resched();
	if (!pmd_leaf(pmdval))
		return 0;

	pd_print_entry_kernel(walk->private, pmd_pfn(pmdval), addr,
                        PMD_SIZE, pmd_val(pmdval));

	return 0;
}

static int pd_pte_entry_kernel(pte_t *pte, unsigned long addr,
                               unsigned long next,
                               struct mm_walk *walk)
{
	pte_t pteval = READ_ONCE(*pte);

	pd_print_entry_kernel(walk->private, pte_pfn(pteval), addr,
                        PAGE_SIZE, pte_val(pteval));

	return 0;
}

static int page_detective_kernel_map_info(unsigned long pfn,
                                          unsigned long direct_map_addr,
                                          struct pd_info *info) {
  struct pd_private_kernel pr = {0};
  unsigned long s, e;

  pr.direct_map_addr = direct_map_addr;
  pr.pfn = pfn;

  pr.info = &info->info;
  pr.maps = 0;

  for (s = PAGE_OFFSET; s != ~0ul; ) {
    e = s + PD_WALK_MAX_RANGE;
    if (e < s)
      e = ~0ul;

    struct mm_walk walk = {
      .pud_entry = pd_pud_entry_kernel,
      .pmd_entry = pd_pmd_entry_kernel,
      .pte_entry = pd_pte_entry_kernel,
    };

    if (walk_page_range_kernel(s, e, &walk, &pr)) {
      pr_info("Received a cancel signal from user, while scanning kernel mappings\n");
      return -1;
    }
    cond_resched();
    s = e;
  }

  return pr.maps;
}

/* Print kernel information about the pfn, return -1 if canceled by user */
static int page_detective_kernel(unsigned long pfn, struct pd_info *info)
{
	unsigned long *mem = __va((pfn) << PAGE_SHIFT);
	unsigned long sum = 0;
	int direct_map;
	u64 s, e;
	int i;

	direct_map = page_detective_kernel_map_info(pfn, (unsigned long)mem, info);

	return direct_map;
}

static long page_detective_user_mm_info(struct mm_struct *mm,
                                        unsigned long pfn, struct pd_info *info) {
  struct pd_private_user pr = {0};
  struct mm_walk walk = {0};
  unsigned long s, e;

  pr.pfn = pfn;
  pr.mm = mm;
  pr.info = &info->info;

  for (s = 0; s != TASK_SIZE; ) {
    e = s + PD_WALK_MAX_RANGE;
    if (e > TASK_SIZE || e < s)
      e = TASK_SIZE;

    mmap_read_lock(mm);

    walk.pud_entry = pd_pud_entry_user;
    walk.pmd_entry = pd_pmd_entry_user;
    walk.pte_entry = pd_pte_entry_user;
    walk.hugetlb_entry = pd_hugetlb_entry;
    walk.mm = mm;
    walk.private = &pr;
    
    walk_page_range(s, e, &walk);
    mmap_read_unlock(mm);
    cond_resched();
    s = e;
  }

  return pr.maps;
}

static int page_detective_usermaps(unsigned long pfn, struct pd_info *info) {
  struct task_struct *task, *t;
  struct mm_struct **mm_table, *mm;
  unsigned long proc_nr, mm_nr, i, mm_not_found, mm_zero;
  long maps, ret;
  u64 s, e;

  mm_not_found = 0;
  mm_zero = 0;
  
  s = sched_clock();
  
  // count number of procs
  proc_nr = 0;
  rcu_read_lock();
  for_each_process(task)
    proc_nr++;
  rcu_read_unlock();

  /* Allocate mm_table to fit mm from every running process */
  mm_table = kvmalloc_array(proc_nr, sizeof(struct mm_struct *),
                            GFP_KERNEL);

  if (!mm_table) {
    pr_info("No memory to traverse through user mappings\n");
    return 0;
  }

  /* get mm from every processes and copy its pointer into mm_table */
  mm_nr = 0;
  rcu_read_lock();
  for_each_process(task) {
    if (mm_nr == proc_nr) {
      pr_info("Number of processes increased while scanning, some will be skipped\n");
      break;
    }

    t = find_lock_task_mm(task);
    if (!t) {
      mm_not_found++;
      continue;
    }

    mm = task->mm;
    if (!mm || !mmget_not_zero(mm)) {
      mm_zero++;
      task_unlock(t);
      continue;
    }
    task_unlock(t);

    mm_table[mm_nr++] = mm;
  }
  rcu_read_unlock();

  info->proc_nr = proc_nr;
  info->mmap_nr = mm_nr;

  /* Walk through every user page table,release mm reference afterwards */
  maps = 0;
  for (i = 0; i < mm_nr; i++) {
    ret = page_detective_user_mm_info(mm_table[i], pfn, info);
    if (ret != -1)
      maps += ret;
    
    mmput(mm_table[i]);
    cond_resched();
  }

  kvfree(mm_table);

  e = sched_clock() - s;

  return maps;
}

static int __page_detective(unsigned long pfn, struct pd_info *info) {
  int usermaps;
  int kernelmaps;

  if (!pfn_valid(pfn)) {
    pr_info("pfn[%lx] is invalid\n", pfn);
    return 0;
  }

  if (pfn == 0) {
    pr_info("Skipping look-up for pfn[0] mapping many times into kernel page table\n");
    return 0;
  }

  // page_detective_usermaps/kernel set the page type
  info->info.type = 0;

  /* Report where/if PFN is mapped in user page tables */
  usermaps = page_detective_usermaps(pfn, info);

  // return early if page is mapped into userspace
  if (usermaps > 0) {
    return usermaps;
  }

  // check if page is mapped into kernel space
  kernelmaps = page_detective_kernel(pfn, info);

  if (kernelmaps > 0) {
    return kernelmaps;
  }
  
  return 0;
}

int page_detective(unsigned long pfn, struct pd_info *info) {
  int ret;
  mutex_lock(&page_detective_mutex);
  ret = __page_detective(pfn, info);
  mutex_unlock(&page_detective_mutex);
  return ret;
}
