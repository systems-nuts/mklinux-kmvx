#ifndef _ASM_X86_PGTABLE_64_DEFS_H
#define _ASM_X86_PGTABLE_64_DEFS_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

/* Pierre start ------------------------------------------------------*/
#include "pierre_dcl.h"
/* Pierre end --------------------------------------------------------*/

/*
 * These are used to make use of C type-checking..
 */
typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef struct { pteval_t pte; } pte_t;

#endif	/* !__ASSEMBLY__ */

#define SHARED_KERNEL_PMD	0
#define PAGETABLE_LEVELS	4

/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT	39
#define PTRS_PER_PGD	512

/*
 * 3rd level page
 */
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

/* See Documentation/x86/x86_64/mm.txt for a description of the memory map. */
#define MAXMEM		 _AC(__AC(1, UL) << MAX_PHYSMEM_BITS, UL)

/* Pierre start ----------------------------------------------------- */

/* DCL vmalloc area */
/* #define VMALLOC_START    _AC(0xffffc90000000000, UL) */
/* #define VMALLOC_END      _AC(0xffffe8ffffffffff, UL) */

#ifdef DCL_REP1
#define VMALLOC_START    _AC(DCL_VMALLOC_START_REP1, UL)
#define VMALLOC_END      _AC(DCL_VMALLOC_END_REP1, UL)
#elif defined DCL_REP2
#define VMALLOC_START    _AC(DCL_VMALLOC_START_REP2, UL)
#define VMALLOC_END      _AC(DCL_VMALLOC_END_REP2, UL)
#else /* default values */
#define VMALLOC_START    _AC(DCL_VMALLOC_START_DEFAULT, UL)
#define VMALLOC_END      _AC(DCL_VMALLOC_END_DEFAULT, UL)
#endif /* DCL vmalloc area */

/* struct page array */
/* #define VMEMMAP_START	 _AC(0xffffea0000000000, UL) */

#ifdef DCL_REP1
#define VMEMMAP_START	 _AC(DCL_VMEMMAP_START_REP1, UL)
#elif defined DCL_REP2
#define VMEMMAP_START	 _AC(DCL_VMEMMAP_START_REP2, UL)
#else /* default */
#define VMEMMAP_START	 _AC(DCL_VMEMMAP_START_DEFAULT, UL)
#endif /* struct page array area */

/* Modules area */
/* #define MODULES_VADDR    _AC(0xffffffffa0000000, UL) */
/* #define MODULES_END      _AC(0xffffffffff000000, UL) */

#ifdef DCL_REP1
#define MODULES_VADDR    _AC(DCL_MODULES_START_REP1, UL)
#define MODULES_END      _AC(DCL_MODULES_END_REP1, UL)
#elif defined DCL_REP2
#define MODULES_VADDR    _AC(DCL_MODULES_START_REP2, UL)
#define MODULES_END      _AC(DCL_MODULES_END_REP2, UL)
#else /* default */
#define MODULES_VADDR    _AC(DCL_MODULES_START_DEFAULT, UL)
#define MODULES_END      _AC(DCL_MODULES_END_DEFAULT, UL)
#endif /* modules area */

/* Pierre end ------------------------------------------------------- */

#define MODULES_LEN   (MODULES_END - MODULES_VADDR)

#endif /* _ASM_X86_PGTABLE_64_DEFS_H */
