#ifndef _ASM_X86_PIERRE_DCL_H
#define _ASM_X86_PIERRE_DCL_H

/* NO C++ style comments here !!!
 * (as this will be included in the linker script)
 */

#ifdef CONFIG_KMVX_REP2
#define DCL_REP2
#else
#define DCL_REP1
#endif

/** 
 * To compile replica1 put #define DCL_REP1 in this file. Do the same
 * with DCL_REP2 for replica2. Put none of those #defines to have the
 * default kernel virtual address space (not that for now replica1 has
 * the default virtual address space layout)
 *
 * Modifications list:
 * ==================== 
 * The regular linux #define that are modified here are present in:
 * - arch/x86/include/asm/page_64_types.h
 * - arch/x86/include/asm/pgtable_64_types.h
 * There is also a small printk added in arch/x86/kernel/setup.c
 * Moreover, concerning the kernel executable area in the virtual 
 * address space, chaning #defines is not sufficient. Indeed, the early 
 * page table generation in arch/x86/kernel/head_64.S is hardcoded to
 * generate a page table mapping 0xffffffff80000000 (kernel exec. 
 * location in the virtual address space) to 0x0 (kernel exec. actual
 * location in physical memory). So there is a bit of modifications in
 * head_64.S to generate the correct page table.
 * 
 * Some info:
 * ==========
 * Looking at Documentation/x86/x86_64/mm.txt, there are several area in
 * the virtual address space that we need to be able to move:
 * - The direct mapping of all physical memory
 * - The vmalloc space
 * - The virtual memory map (it is the array of struct page 
 * representing physical pages)
 * - The kernel executable area
 * - The module area
 * 
 * Note that we don't care about the user space area.
 * 
 * 1) Direct mapping of all physical memory
 * ----------------------------------------
 * It starts in the virtual address space at __PAGE_OFFSET. This 
 * constant is defined in arch/x86/include/asm/page_64_types.h. As this
 * is a direct mapping (va == pa + __PAGE_OFFSET), if we shift 
 * __PAGE_OFFSET by more than the amount of RAM available, we shoud get
 * a kernel with this area non overlapping the one of a regular kernel.
 * Normally, __PAGE_OFFSET is 0xffff880000000000. We cannot shift by 
 * less than 0x100000000000 because of some bitmask operations (I guess
 * something to do with __VIRTUAL_MASK_SHIFT also defined in the same
 * file). So for the first replica we put the regular value for 
 * __PAGE_OFFSET, and for the second one its 
 * 0xffff880000000000 + 0x100000000000 = 0xffff980000000000
 * This shift corresponds to a value of 16TB. It means that in the 
 * general case we are good, but on systems with more than 16TB of RAM
 * the area in replica 1 will start to overlap on the one in replica 2.
 * We can try other tricks to increase this 16TB limit (shifting by 
 * more than 0x100000000000, but not sure if it is really necessary).
 * 
 * 2) Vmalloc area
 * ---------------
 * This area boundaries are defined as VMALLOC_START and VMALLOC_END in
 * arch/x86/include/asm/pgtable_64_types.h. Normally, they are defined 
 * so that the area spans from 0xffffc90000000000 to 0xffffe8ffffffffff.
 * Its size is then 0x270000000000. If we divide it by two we can have
 * two non overlapping areas each of size 0x138000000000:
 * - One for replica1 ranging from 0xffffc90000000000 to 
 * 			0xffffdc7fffffffff
 * - The other for replica2 from 0xffffdc8000000000 to 
 * 			0xffffe8ffffffffff
 * I do not know if we are restraining something when dividing by two 
 * the size of the vmalloc area. Note that the size of each area is 
 * 19.5 TB, so it should be okay.
 * 
 * 3) struct page array
 * --------------------
 * This is an array of struct page, each one representing one page of 
 * physical memory. They are contiguously ordered by page frame number.
 * The beginning of the array (i.e. the first struct page) is defined
 * in arch/x86/include/asm/pgtable_64_types.h as VMEMMAP_START. 
 * According to the documentation the virtual area dedicated to this 
 * array ranges from 0xffffea0000000000 to 0xffffeaffffffffff so its 
 * size is 0x10000000000. We can divide it into two _nearly_ equal 
 * sections:
 * - Replica1 from 0xffffea0000000000 to 0xffffea7fffffffff 
 * 		(size 0x8000000000)
 * - Replica2 from 0xffffea8000000000 to 0xffffeaffffffffff 
 * 		(size 0x8000000000)
 * Sizes of the areas are 512GB, given that one struct page size is 0x40
 * (64 bytes) for our kernel version, it gives space for 8589934592 
 * pages in each area, corresponding to 32 TB of physical RAM.
 * 
 * 4) Module area
 * --------------
 * Normally mapped from 0xffffffffa0000000 to 0xfffffffffff00000, these
 * values are defined in arch/x86/include/asm/pgtable_64_types.h, 
 * respectively as MODULES_VADDR and MODULES_END. 
 * We can as for vmalloc divide that area by two and give one 
 * sub-area to each replica. Now it seems that because of the use of 
 * some bitmasks, MODULES_VADDR must be multiple of 0x1000000, so we do
 * not have the same size for each area.
 * - Replica1 from 0xffffffffa0000000 to 0xFFFFFFFFCEFFFFFF (size
 * 			0x2EFFFFFF)
 * - Replica2 from 0xFFFFFFFFCF000000 to 0xfffffffffff00000 (size 
 * 			0x30F00000)
 * So the VM space available for modules is for replica 1 752MB, and
 * 783MB for replica2. In a regular kernel, it is 1.5GB.
 * 
 * 5) Kernel executable area
 * -------------------------
 * The location of the kernel executable area is defined in 
 * arch/x86/include/asm/page_64_types.h in two macros:
 * __START_KERNEL_map and KERNEL_IMAGE_START (they should have the same
 * value). They default to 0xffffffff80000000. Also, the maximum kernel 
 * size is defined in KERNEL_IMAGE_SIZE, which is actually the size of 
 * the VM area for the kernel executable (512 MB).
 * 
 * What we can do is divide by two this area and give one 256MB sized
 * area to each replica:
 * - Replica1 from 0xffffffff80000000 to 0xffffffff8fffffff (size
 * 			256MB)
 * - Replica2 from 0xffffffff90000000 to 0xffffffff9fffffff (size
 * 			256MB)
 * So we must also modify KERNEL_IMAGE_SIZE to 256 MB.
 * 
 * Only modifying these #defines don't work for replica2. Indeed, after 
 * the kernel is decompressed (at physical address 0x0), a page table 
 * is installed, mapping KERNEL_IMAGE_SIZE amount of memory from virtual
 * address 0xffffffff80000000 (default value for __START_KERNEL_map) to 
 * physical address 0x0. This is done using 2MB pages, and the process 
 * is hardcoded to map from 0xffffffff80000000. This is done in 
 * arch/x86/kernel/head_64.h (in the data section the page table are
 * defined)
 * 
 * No modifications are required for replica1 because the base address
 * does not change. For replica2, we need to modify the page table to
 * map from 0xffffffff90000000. There is a macro to create the last
 * level of page table in head_64.S named PMDS which fill that last 
 * level (PMD, as we are using 2MB pages PME directly point to memory 
 * page, there is no PTE). I extended PMDS to pad the start of the 
 * corresponding PMD with zeroes in order to actually map 
 * 0xffffffff90000000 and so on to physical 0x0 in replica2 (new name of
 * the macro is PMDSO). The macro also work when generating replica1
 * by padding nothing (as the first entry in the PMD corresponds to
 * 0xffffffff80000000).
 */

/* Direct mapping area
 * --------------------
 * Compute the value of __PAGE_OFFSET to make the direct mapping non
 * overlapping.
 * Note that we cannot do complex computations that would need 
 * parenthesis here because of the way __PAGE_OFFSET is defined (i.e. 
 * concatenation with UL in the end is broken by the closing 
 * parenthesis). This is also true for the constants defining several 
 * other areas: vmalloc, TODO
 *  */
#define DCL_PAGE_OFFSET_DEFAULT	0xffff880000000000
#define DCL_PAGE_OFFSET_REP1	DCL_PAGE_OFFSET_DEFAULT
#define DCL_PAGE_OFFSET_REP2	0xffff980000000000 /* +0x100000000000 */

/* vmalloc area
 * ------------
 * Set vmalloc area boundaries according to the computations presented 
 * above
 */
#define DCL_VMALLOC_START_DEFAULT	0xffffc90000000000
#define DCL_VMALLOC_END_DEFAULT		0xffffe8ffffffffff
#define DCL_VMALLOC_START_REP1		0xffffc90000000000
#define DCL_VMALLOC_END_REP1		0xffffdc7fffffffff
#define DCL_VMALLOC_START_REP2		0xffffdc8000000000
#define DCL_VMALLOC_END_REP2		0xffffe8ffffffffff

/* struct page array
 * -----------------
 * See the info above for computation of the boundaries
 */
#define DCL_VMEMMAP_START_DEFAULT	0xffffea0000000000
#define DCL_VMEMMAP_START_REP1		DCL_VMEMMAP_START_DEFAULT
#define DCL_VMEMMAP_START_REP2		0xffffea8000000000 /* +0x8000000000 */

/* module area
 * -----------
 * Set module area boundaries according to the computations presented 
 * above
 */
#define DCL_MODULES_START_DEFAULT	0xffffffffa0000000
#define DCL_MODULES_END_DEFAULT		0xffffffffff000000
#define DCL_MODULES_START_REP1		0xffffffffa0000000
#define DCL_MODULES_END_REP1		0xffffffffceffffff
#define DCL_MODULES_START_REP2		0xffffffffcf000000
#define DCL_MODULES_END_REP2		0xffffffffff000000

/* kernel executable area
 * ----------------------
 */
#define DCL_KERNEL_LOC_DEFAULT		0xffffffff80000000
#define DCL_KERNEL_SIZEMB_DEFAULT	512
#define DCL_KERNEL_LOC_REP1			DCL_KERNEL_LOC_DEFAULT
#define DCL_KERNEL_SIZEMB_REP1		256
#define DCL_KERNEL_LOC_REP2			0xffffffff90000000
#define DCL_KERNEL_SIZEMB_REP2		256
#define DCL_KERNEL_OFFSET_REP1		((DCL_KERNEL_LOC_REP1) - (DCL_KERNEL_LOC_DEFAULT))
#define DCL_KERNEL_OFFSET_REP2		((DCL_KERNEL_LOC_REP2) - (DCL_KERNEL_LOC_DEFAULT))
#define DCL_KERNEL_OFFSET_DEFAULT	0
										
/* Check that DCL_REP1 and DCL_REP2 are not both defined at the same 
 * time */
#ifdef DCL_REP1
#ifdef DCL_REP2
#error "DCL_REP1 and DCL_REP2 should not be defined at the same time."	
#endif /* DCL_REP2 */
#endif /* DCL_REP1 */

#endif /* _ASM_X86_PIERRE_DCL_H */
