#ifndef _ASM_X86_PAGE_64_DEFS_H
#define _ASM_X86_PAGE_64_DEFS_H

/* Pierre start ------------------------------------------------------*/
#include "pierre_dcl.h"
/* Pierre end --------------------------------------------------------*/

#define THREAD_ORDER	1
#define THREAD_SIZE  (PAGE_SIZE << THREAD_ORDER)
#define CURRENT_MASK (~(THREAD_SIZE - 1))

#define EXCEPTION_STACK_ORDER 0
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)

#define DEBUG_STACK_ORDER (EXCEPTION_STACK_ORDER + 1)
#define DEBUG_STKSZ (PAGE_SIZE << DEBUG_STACK_ORDER)

#define IRQ_STACK_ORDER 2
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)

#define STACKFAULT_STACK 1
#define DOUBLEFAULT_STACK 2
#define NMI_STACK 3
#define DEBUG_STACK 4
#define MCE_STACK 5
#define N_EXCEPTION_STACKS 5  /* hw limit: 7 */

#define PUD_PAGE_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_PAGE_MASK		(~(PUD_PAGE_SIZE-1))

/*
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*16 (pgd slot 272).  The gap is to allow a space for a
 * hypervisor to fit.  Choosing 16 slots here is arbitrary, but it's
 * what Xen requires.
 */
/* Pierre start ------------------------------------------------------*/
/* #define __PAGE_OFFSET           _AC(0xffff880000000000, UL) */

/* DCL direct mapped area */
#ifdef DCL_REP1
#define __PAGE_OFFSET           _AC(DCL_PAGE_OFFSET_REP1, UL)
#elif defined DCL_REP2
#define __PAGE_OFFSET           _AC(DCL_PAGE_OFFSET_REP2, UL)
#else
/* Default value */
#define __PAGE_OFFSET           _AC(DCL_PAGE_OFFSET_DEFAULT, UL)
#endif /* DCL direct mapped area */
/* Pierre end --------------------------------------------------------*/

#define __PHYSICAL_START	((CONFIG_PHYSICAL_START +	 	\
				  (CONFIG_PHYSICAL_ALIGN - 1)) &	\
				 ~(CONFIG_PHYSICAL_ALIGN - 1))

#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)

/* Pierre start ------------------------------------------------------*/
/* #define __START_KERNEL_map	_AC(0xffffffff80000000, UL) */

#ifdef DCL_REP1
#define __START_KERNEL_map	_AC(DCL_KERNEL_LOC_REP1, UL)
#elif defined DCL_REP2
#define __START_KERNEL_map	_AC(DCL_KERNEL_LOC_REP2, UL)
#else
/* Default value */
#define __START_KERNEL_map	_AC(DCL_KERNEL_LOC_DEFAULT, UL)
#endif /* start kernel map */
/* Pierre end --------------------------------------------------------*/

/* See Documentation/x86/x86_64/mm.txt for a description of the memory map. */
#define __PHYSICAL_MASK_SHIFT	46
#define __VIRTUAL_MASK_SHIFT	47

/*
 * Kernel image size is limited to 512 MB (see level2_kernel_pgt in
 * arch/x86/kernel/head_64.S), and it is mapped here:
 */
/* Pierre start ------------------------------------------------------*/
/* #define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024) */
/* #define KERNEL_IMAGE_START	_AC(0xffffffff80000000, UL) */

#ifdef DCL_REP1
#define KERNEL_IMAGE_SIZE	(DCL_KERNEL_SIZEMB_REP1 * 1024 * 1024)
#define KERNEL_IMAGE_START	_AC(DCL_KERNEL_LOC_REP1, UL)
#elif defined DCL_REP2
#define KERNEL_IMAGE_SIZE	(DCL_KERNEL_SIZEMB_REP2 * 1024 * 1024)
#define KERNEL_IMAGE_START	_AC(DCL_KERNEL_LOC_REP2, UL)
#else /* default */
#define KERNEL_IMAGE_SIZE	(DCL_KERNEL_SIZEMB_DEFAULT * 1024 * 1024)
#define KERNEL_IMAGE_START	_AC(DCL_KERNEL_LOC_DEFAULT, UL)
#endif /* kernel image start and size */
/* Pierre end --------------------------------------------------------*/

#ifndef __ASSEMBLY__
void clear_page(void *page);
void copy_page(void *to, void *from);

/* duplicated to the one in bootmem.h */
extern unsigned long max_pfn;
extern unsigned long phys_base;

extern unsigned long __phys_addr(unsigned long);
#define __phys_reloc_hide(x)	(x)

#define vmemmap ((struct page *)VMEMMAP_START)

extern void init_extra_mapping_uc(unsigned long phys, unsigned long size);
extern void init_extra_mapping_wb(unsigned long phys, unsigned long size);

#endif	/* !__ASSEMBLY__ */

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#endif

#endif /* _ASM_X86_PAGE_64_DEFS_H */
