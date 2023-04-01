// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW         0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

//	cprintf("[%x] pgfault handler: %x\n", sys_getenvid(),  (uintptr_t)addr);

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	pte_t pte = uvpt[(uintptr_t)addr >> PGSHIFT];

	if (!(err & 2)) {
		panic("pgfault was not a write. err: %x", err);
	} else if (!(pte & PTE_COW)) {
		panic("pgfault is not copy on write");
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	// LAB 4: Your code here.
	int perm = PTE_P | PTE_U | PTE_W;
	if ((r = sys_page_alloc(0, UTEMP, perm)) < 0) {
		panic("sys_page_alloc: %e", r);
	}
	memmove(UTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	if ((r = sys_page_map(0,
			      UTEMP,
			      0,
			      ROUNDDOWN(addr, PGSIZE),
			      perm)) < 0) {
		panic("sys_page_map %e", r);
	}
	if ((r = sys_page_unmap(0, UTEMP)) < 0) {
		panic("unmap %e", r);
	}
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
    envid_t parent_envid = sys_getenvid();
    void *va = (void *)(pn * PGSIZE);
    int r;

    if ((uvpt[pn] & PTE_W) == PTE_W || (uvpt[pn] & PTE_COW) == PTE_COW) {
        if ((r = sys_page_map(parent_envid, va, envid, va, PTE_COW | PTE_U | PTE_P)) != 0) {
            panic("duppage: %e", r);
        }
        if ((r = sys_page_map(parent_envid, va, parent_envid, va, PTE_COW | PTE_U | PTE_P)) != 0) {
            panic("duppage: %e", r);
        }
    } else {
        if ((r = sys_page_map(parent_envid, va, envid, va, PTE_U | PTE_P)) != 0) {
            panic("duppage: %e", r);
        }
    }

    return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
    envid_t envid;
    uint32_t addr;
    int r;

    set_pgfault_handler(pgfault);
    envid = sys_exofork();
    if (envid < 0) {
        panic("sys_exofork: %e", envid);
    }
    if (envid == 0) {
        // fix thisenv in child
        thisenv = &envs[ENVX(sys_getenvid())];
        return 0;
    }

    // copy the address space mappings to child
    for (addr = 0; addr < USTACKTOP; addr += PGSIZE) {
        if ((uvpd[PDX(addr)] & PTE_P) == PTE_P && (uvpt[PGNUM(addr)] & PTE_P) == PTE_P) {
            duppage(envid, PGNUM(addr));
        }
    }

    // allocate new page for child's user exception stack
    void _pgfault_upcall();

    if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_W | PTE_U | PTE_P)) != 0) {
        panic("fork: %e", r);
    }
    if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) != 0) {
        panic("fork: %e", r);
    }

    // mark the child as runnable
    if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) != 0)
        panic("fork: %e", r);

    return envid;
}

// Challenge!
int
sfork(void)
{
  panic("sfork not implemented");
  return -E_INVAL;
}
