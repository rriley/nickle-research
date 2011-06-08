extern target_ulong get_paddr(CPUState *env, target_ulong addr);
extern void * get_laddr(CPUState *env, target_ulong addr, void *offset);
extern int rkprot_flag;

int verify_copy_kernel(CPUState *env, TranslationBlock *tb);
int verify_copy_module(CPUState *env, TranslationBlock *tb, target_ulong mod_vaddr);
void nickle_main(CPUState *env, TranslationBlock *tb, target_ulong pc_ptr);
int rewrite_code(CPUState *env, target_ulong tpc);


/* May need to be changed for your preferences or kernel,
 * but this set of code is probably fine.
 * It corresponds to return -1;
 */
#define REWRITE_CODE "\xb8\xff\xff\xff\xff\xc3"
#define REWRITE_CODE_LEN 6

/* The following come from System.map 
 * STARTUP_32 is the address of startup_32
 * MODSB is the address of sys_init_module
 * MODSE is the address of whatever is after sys_init_module
 */
#define STARTUP_32 0xc0100000
#define MODSB 0xc011baa0
#define MODSE 0xc011c0d0

/*  This tells NICKLE which register to check for the
 *  module data structure address.  It was EBX in one
 *  of my kernel builds and EBP in another.
 */
#define MODREG R_EBP
