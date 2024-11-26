#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/tracepoint.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/page_detective.h>

#include <linux/tracefault.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ben Holmes");
MODULE_DESCRIPTION("A kernel module to trace page faults.");

#define info(fmt, ...) \
  pr_info("tracefault: " fmt, ##__VA_ARGS__)

DEFINE_SPINLOCK(trace_lock);
#define TRACE_LEN (PAGE_SIZE / sizeof(struct fault_info))
#define TRACE_PORT 0x81

static struct fault_info *trace;
static unsigned long idx = 0;
static unsigned long long mmio_base = 0;
static void __iomem *base;
static int init = 0;

// copied from arch/x86/mm/fault.c
static bool is_vsyscall_vaddr(unsigned long vaddr) {
  return unlikely((vaddr & PAGE_MASK) == VSYSCALL_ADDR);
}

bool is_fault_in_kernel_space(unsigned long addr) {
  if (is_vsyscall_vaddr(addr))
    return false;

  return addr >= TASK_SIZE_MAX;
}

static inline void write_u32(uint32_t val) {
    uint16_t port = TRACE_PORT;
    outl(val, port);
}

static inline bool tracefault_enabled(void) {
  return !strstr(saved_command_line, "notracefault");
}

static inline bool memtrace_enabled(void) {
  return !strstr(saved_command_line, "nomemtrace");
}

static inline int get_mmio_base(void) {
  int ret;
  char *param = strstr(saved_command_line, "fault_tracer=");
  int i;
  char addr_str[19];

  if (!param) {
    pr_err("tracefault: mmio base not present on kernel command line\n");
    return ENOENT;
  }
  
  param += strlen("fault_tracer=");
  if (strlen(param) < 3) {
    pr_err("invalid fault_tracer address\n");
    return EINVAL;
  }    
    
  if (!(param[0] == '0' && param[1] == 'x')) {
    pr_err("invalid address pattern\n");
    return EINVAL;
  }

  for (i = 0; i < strlen(param); i++)
    if (param[i] == 0x20) break;

  if (i > 18) {
    pr_err("provided address is too long\n");
    return EINVAL;
  }
  
  memset(addr_str, 0, 18);
  strncpy(addr_str, param, i);
  
  ret = kstrtoull(addr_str, 16, &mmio_base);
  if (ret) {
    pr_err("failed to parse mmio base address: %d\n", ret);
    return ret;
  }

  return 0;
}

static inline void write_u64(uint64_t val) {
  uint16_t port = TRACE_PORT;

  uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
  uint32_t high = (uint32_t)((val >> 32) & 0xFFFFFFFF);
  
  outl(high, port);
  outl(low, port);
}


static void flush_trace(void) {
  writeq(idx, base);
  idx = 0;
}

static void add_trace(struct fault_info *info) {
  spin_lock(&trace_lock);
  trace[idx] = *info;
  idx++;
  if (idx >= TRACE_LEN - 1) {
    flush_trace();
  }
  spin_unlock(&trace_lock);
}


unsigned long user_virt_to_phys(struct mm_struct *mm, unsigned long vaddr) {
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *pte;

  struct page *page;
  unsigned long paddr = 0;

  // traverse
  pgd = pgd_offset(mm, vaddr);
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {
    info("pgd_none\n");
    return paddr;
  }


  // can this be bad?
  p4d = p4d_offset(pgd, vaddr);
  if (p4d_none(*p4d) || p4d_bad(*p4d)) {
    info("p4d_none\n");
    return paddr;
  }

  pud = pud_offset(p4d, vaddr);
  if (pud_none(*pud) || pud_bad(*pud)) {
    info("pud_none\n");
    return paddr;
  }

  pmd = pmd_offset(pud, vaddr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {
    info("pmd none\n");
    return 0;
  }

  pte = pte_offset_map(pmd, vaddr);
  if (pte_none(*pte) || !pte_present(*pte)) {
    info("pte_none\n");
    pte_unmap(pte);
    return 0;
  }

  // Get the page frame number from the PTE and calculate the physical address
  page = pte_page(*pte);
  if (page) {
    paddr = page_to_pfn(page) << PAGE_SHIFT;
    paddr |= vaddr & ~PAGE_MASK;  // Add the offset within the page
  }

  pte_unmap(pte);
  return paddr;
}

int trace_fault(unsigned long fault_vaddr) {
    unsigned long fault_paddr;
    struct fault_info info;

    if (!init) {
      return 0;
    }
    
    fault_paddr = user_virt_to_phys(current->mm, fault_vaddr);

    if (fault_paddr) {
      if (is_fault_in_kernel_space(fault_vaddr))
	info.type = 0;
      else
	info.type = 1;

      info.addr = fault_paddr;
      memset(info.comm, 0, TASK_COMM_LEN);
      memcpy(info.comm, current->comm, TASK_COMM_LEN);

      add_trace(&info);
      flush_trace();
    } else {
      info("tracefault: unresolved fault\n");
    }
    
    return 0;  
}

irqreturn_t tracefault_irq_handler(int irq, void *dev_id) {
  unsigned long pfn;
  int maps = 0;
  struct pd_info info = {0};
  info.info.type = 3;
  bool wrote_stats = false;

  if (!memtrace_enabled())
    return IRQ_HANDLED;

  // trace all of phys mem
  for (pfn = 1; pfn < totalram_pages; pfn++) {
    maps = page_detective(pfn, &info);
    // luckily this only happens once
    if (!wrote_stats) {
      writel(info.proc_nr, base + 4);
      writel(info.mmap_nr, base + 8);
      wrote_stats = true;
    }
    info.info.type = 3;
    if(maps)
      add_trace(&info.info);
  }

  info.info.type = 4;
  add_trace(&info.info);

  flush_trace();
  
  return IRQ_HANDLED;
}

static int __init tracefault_init(void)
{
    int ret;
    unsigned long phys;
    
    if (!tracefault_enabled()) {
      info("disabled\n");
      return 0;
    }

    info("init\n");
       
    ret = get_mmio_base();
    if (ret)
      return ret;
    
    info("mmio_base=0x%llx\n", mmio_base);
    
    trace = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!trace) {
      pr_err("failed to allocate trace page");
      return -ENOMEM;
    }
    memset(trace, 0, PAGE_SIZE);

    // replace with mmio address
    base = ioremap(mmio_base, 0x8);
    if (!base) {
      pr_err("tracefault: failed to map mmio region\n");
      return -ENOMEM;
    }

    ret = request_irq(5, tracefault_irq_handler, 0, "tracefault", NULL);

    if (ret) {
      iounmap(mmio_base);
      pr_err("tracefault: failed to set up irq handler\n");
      return ret;
    }

    phys = virt_to_phys(trace);
    writeq(phys, base);

    init = 1;

    info("init done\n");
    
    return 0;
}

static void __exit tracefault_exit(void)
{
  kfree(trace);
}

module_init(tracefault_init);
module_exit(tracefault_exit);
