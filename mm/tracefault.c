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
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ben Holmes");
MODULE_DESCRIPTION("A kernel module to trace page faults.");

static struct kprobe fault_kp;

struct __attribute__((packed)) fault_info {
  unsigned long type;
  unsigned long addr;
  char comm[TASK_COMM_LEN];
};

DEFINE_SPINLOCK(trace_lock);
#define TRACE_LEN (PAGE_SIZE / sizeof(struct fault_info))
#define TRACE_PORT 0x81

static struct fault_info *trace;
static int idx = 0;

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

static inline void write_u64(uint64_t val) {
  uint16_t port = TRACE_PORT;

  uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
  uint32_t high = (uint32_t)((val >> 32) & 0xFFFFFFFF);
  
  outl(high, port);
  outl(low, port);
}

static void flush_trace(void) {
  write_u32(idx);
  idx = 0;
}

static int fault_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long fault_addr;
    struct task_struct *task = current;
    struct fault_info info;
    
    fault_addr = regs->dx;
    if (is_fault_in_kernel_space(fault_addr))
      info.type = 0;
    else
      info.type = 1;

    info.addr = fault_addr;
    memset(info.comm, 0, TASK_COMM_LEN);
    memcpy(info.comm, task->comm, TASK_COMM_LEN);


    spin_lock(&trace_lock);
    trace[idx] = info;
    idx++;
    flush_trace(); // TODO batch
    spin_unlock(&trace_lock);

    return 0;
}

static int __init tracefault_init(void)
{
    int ret;
    pr_info("Tracefault init\n");

    trace = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!trace) {
      pr_err("failed to allocate trace page");
      return -ENOMEM;
    }
    memset(trace, 0, PAGE_SIZE);

    write_u64(virt_to_phys(trace));

    fault_kp.symbol_name = "handle_page_fault";
    fault_kp.pre_handler = fault_handler;

    ret = register_kprobe(&fault_kp);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
    }

    pr_info("Tracefault init done\n");
    
    return 0;
}

static void __exit tracefault_exit(void)
{
  flush_trace();
  kfree(trace);
  unregister_kprobe(&fault_kp);
}

module_init(tracefault_init);
module_exit(tracefault_exit);
