struct __attribute__((packed)) fault_info {
  unsigned long type;
  unsigned long addr;
  char comm[TASK_COMM_LEN];
};

struct pd_info {
  struct fault_info info;
  int proc_nr;
  int mmap_nr;
};

int page_detective(unsigned long pfn, struct pd_info *info);

