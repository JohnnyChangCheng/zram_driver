#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/vmacache.h>
#include <linux/mm_inline.h>
#include <linux/hugetlb.h>
#include <linux/huge_mm.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/sched/mm.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/shmem_fs.h>
#include <linux/uaccess.h>
#include <linux/pkeys.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <asm/elf.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

static atomic_t atomic_mutex = ATOMIC_INIT(0);

struct vma_fault_record {
	struct vma_fault_record *next;
	struct vma_fault_record *start;
	unsigned long vm_start;
	bool file_page;
	char vma_name[1024];
};
struct memory_profile_data {
	unsigned long long file_fault;
	unsigned long long anon_fault;
	pid_t tgid;
	unsigned long long anon_reclaim;
	unsigned long long file_reclaim;
	struct vma_fault_record *current_vma_fault_record;
};

static struct memory_profile_data profile_data = { 0 };

static unsigned lru_reclaimed[NR_LRU_LISTS] = {0};


void account_file_fault(void)
{
	profile_data.file_fault++;
}
EXPORT_SYMBOL(account_file_fault);

void account_anon_fault(void)
{
	profile_data.anon_fault++;
}

EXPORT_SYMBOL(account_anon_fault);

void account_page_reclaim(struct page *page)
{
	if (page) {
		if(!page_is_file_lru(page))
			profile_data.anon_reclaim++;
		else 
			profile_data.file_reclaim++;
	}
}

EXPORT_SYMBOL(account_page_reclaim);

EXPORT_SYMBOL(reclaim_memory_page);

void reclaim_memory_page(int lru, unsigned long amount)
{
	lru_reclaimed[lru] += amount;
}


void iterate_global_active_lru(void)
{
	struct mem_cgroup *memcg;
    struct lruvec *lruvec;
    struct page *page;
    pg_data_t *pgdat = NODE_DATA(nid);
	printk(KERN_INFO "Tried Iteratro pages\n");
	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		lruvec = mem_cgroup_lruvec(memcg, pgdat);
		list_for_each_entry(page, &lruvec->lists[LRU_UNEVICTABLE], lru) {
            // Do something with the page, e.g., print page info
            printk(KERN_INFO "Active File Page: pfn=%lu\n", page_to_pfn(page));
        }
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
	return;
}

static int is_stack(struct vm_area_struct *vma)
{
	/*
	 * We make no effort to guess what a given thread considers to be
	 * its "stack".  It's not even well-defined for programs written
	 * languages like Go.
	 */
	return vma->vm_start <= vma->vm_mm->start_stack &&
	       vma->vm_end >= vma->vm_mm->start_stack;
}

void account_vma_fault(struct task_struct *p, struct vm_area_struct *vma)
{
	if (atomic_read(&atomic_mutex) == 1)
		return;
	if (p->tgid == profile_data.tgid) {
		struct vma_fault_record *node =
			(struct vma_fault_record *)kmalloc(
				sizeof(struct vma_fault_record), GFP_KERNEL);
		node->vm_start = vma->vm_start;
		if (vma->vm_file) {
			char buff[1024];
			char *name = NULL;
			node->file_page = true;
			name = d_path(&vma->vm_file->f_path, buff, 1024);
			if (!IS_ERR(name)) {
				strncpy(node->vma_name, name, 1024);
			}
		} else {
			const char *name = NULL;
			node->file_page = false;
			if (vma->vm_ops && vma->vm_ops->name) {
				name = vma->vm_ops->name(vma);
			}
			if (!name)
				name = arch_vma_name(vma);
			if (!name) {
				struct anon_vma_name *anon_name;
				if (!vma->vm_mm) {
					name = "[vdso]";
				} else if (vma->vm_start <= vma->vm_mm->brk &&
					   vma->vm_end >=
						   vma->vm_mm->start_brk) {
					name = "[heap]";
				} else if (is_stack(vma)) {
					name = "[stack]";
				} else {
					anon_name = anon_vma_name(vma);
					if (anon_name)
						name = anon_name->name;
				}
			}
			if (name) {
				strncpy(node->vma_name, name, 1024);
			}
		}
		if (profile_data.current_vma_fault_record == NULL) {
			profile_data.current_vma_fault_record = node;
			node->start = node;
		} else {
			node->start =
				profile_data.current_vma_fault_record->start;
			profile_data.current_vma_fault_record->next = node;
			profile_data.current_vma_fault_record = node;
		}
	}
}
EXPORT_SYMBOL(account_vma_fault);

extern __u64 swap_ns;
extern __u64 swap_ns2;
extern __u64 swap_time;
extern __u64 do_swap_ns;
extern __u64 do_swap_time;
static ssize_t total_fault_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "DO Swap Page Cost %llu SWAP Page Cost %llu %llu Total File Fault %llu Anon Fault %llu File Rclaim %llu Anono Reclaim %llu Reclaim inactive anon %llu active anon %llu inactive file %llu active file %llu\n",
			  do_swap_ns/do_swap_time,swap_ns/swap_time, swap_ns2/swap_time, profile_data.file_fault, profile_data.anon_fault, profile_data.file_reclaim, profile_data.anon_reclaim, lru_reclaimed[0], lru_reclaimed[1], lru_reclaimed[2], lru_reclaimed[3]);
}
static ssize_t total_fault_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	profile_data.file_fault = 0;
	profile_data.anon_fault = 0;
	iterate_global_active_lru();
	return count;
}
static DEVICE_ATTR_RW(total_fault);

static ssize_t vma_fault_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	int count = 0;
	long long offset = 0;
	char buff[1248];
	struct file *file;
	struct vma_fault_record *node =
		profile_data.current_vma_fault_record->start;
	struct vma_fault_record *tempt = NULL;
	if (profile_data.current_vma_fault_record == NULL)
		return sysfs_emit(buf, "memory_profile: No node value\n");

	// Open the file
	snprintf(buff, 1248, "/data/local/tmp/%d.txt", profile_data.tgid);
	file = filp_open(buff, O_WRONLY | O_CREAT | O_LARGEFILE, 0644);
	if (IS_ERR(file)) {
		printk(KERN_ERR "Failed to open file\n");
		return PTR_ERR(file);
	}

	while (node) {
		count++;
		snprintf(buff, 1248,
			 "memory_profile: File Fault: %d Start: 0x%x VMA: %s\n",
			 node->file_page, node->vm_start, node->vma_name);
		printk("%s", buff);
		kernel_write(file, buff, strlen(buff), &offset);
		tempt = node;
		node = node->next;
		kfree(tempt);
	}
	profile_data.current_vma_fault_record = NULL;
	filp_close(file, NULL);
	return sysfs_emit(buf, "memory_profile: Provide VMA %d\n", count);
}

static ssize_t vma_fault_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	unsigned long pid;
	struct vma_fault_record *node = NULL, *tempt = NULL;

	atomic_set(&atomic_mutex, 1);
	if (profile_data.current_vma_fault_record)
		node = profile_data.current_vma_fault_record->start;

	pid = simple_strtoul(buf, NULL, 10);

	profile_data.tgid = (pid_t)pid;
	while (node) {
		tempt = node;
		node = node->next;
		kfree(tempt);
	}
	profile_data.current_vma_fault_record = NULL;
	printk("memory_profile: Track tgid %d", profile_data.tgid);
	atomic_set(&atomic_mutex, 0);

	return count;
}
static DEVICE_ATTR_RW(vma_fault);

static struct platform_device memory_profile_platform = {
	.name = "memory_profile",
	.id = PLATFORM_DEVID_NONE,
};

static int __init memory_profile_platform_init(void)
{
	int ret = platform_device_register(&memory_profile_platform);
	ret = device_create_file(&memory_profile_platform.dev,
				 &dev_attr_total_fault);
	ret = device_create_file(&memory_profile_platform.dev,
				 &dev_attr_vma_fault);
	return ret;
}

static void __exit memory_profile_platform_exit(void)
{
	platform_device_unregister(&memory_profile_platform);
}

module_init(memory_profile_platform_init);
module_exit(memory_profile_platform_exit);
MODULE_LICENSE("GPL");
