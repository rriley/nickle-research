/*
 *  NICKLE code for Linux 2.4.18
 *
 *  This file contains all the code for NICKLE on
 *  Linux 2.4.18.  To protect a different OS, a modified
 *  version of this file would be needed for the details.
 * 
 *  Copyright (c) 2007 Ryan Riley
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>

#include "cpu.h"
#include "exec-all.h"
#include "disas.h"

// RDR
#include "sha1.h"
#include "nickle.h"

void nickle_main(CPUState *env, TranslationBlock *tb, target_ulong pc_ptr)
{
	target_ulong tpc;

	tpc = get_paddr(env,pc_ptr);

	if (phys_ram_base[tpc] != phys_ram_base2[tpc]) {
		/* Do a check to see if we're module loading...
		 * The two addresses below come from system.map
		 *
		 * Basically, we check the return address on the
		 * stack to see if it is within the module loading
		 * system call.  If it is, then we assume a module
		 * is being loaded and call verify_copy_module to
		 * see if the module is valid.  The real work related
		 * to modules happens in that function.
		 *
		 * If we're not loading a module (and hence just have
		 * unauthorized execution) or if the module fails
		 * verification, then we modify the code a bit.  Our
		 * code changing scheme is not the cleanest, but it
		 * does work.  There is a chance, however, that
		 * innocent code could get changes.
		 *
		 * Also notice that our check above, comparing the
		 * single bytes of standard and shadow memory, opens
		 * a security hole for a crafty attacker to modify
		 * existing code.  Can you see what it is?
		 * (The fix is conceptually easy, but practically
		 * difficult.  Perhaps QEMU already has some code that
		 * would help.)
		 */
		target_ulong *uptr;
		uptr = (void *)(get_paddr(env,env->regs[R_ESP]) + phys_ram_base);
		if (!(*uptr > MODSB && *uptr < MODSE) 
		    || !verify_copy_module(env, tb, env->regs[MODREG]))
		{
			/* Rewrite mode */
			if (rkprot_flag == 1) {
				printf("Unauthorized code execution @ " 
				       TARGET_FMT_lx "\n", pc_ptr);
				rewrite_code(env,tpc);
				printf("\tCode successfully rewritten\n");
			}
			/* Observe mode and Break mode */
			else if (rkprot_flag == 2 || rkprot_flag == 3) {
				printf("Unauthorized code execution @ " 
				       TARGET_FMT_lx "\n", pc_ptr);
			}
		}			
	}
	
	/* The following 'if' has a hardcoded address taken
	 * from System.map.  It is the address of startup_32
	 * We mask off the first byte to make the virtual address
	 * into the physical address.  (Look Ma, no pagetable!)
	 */
	if (tpc == (STARTUP_32 & 0x0fffffff)) {
		verify_copy_kernel(env,tb);
	}       	
}

int rewrite_code(CPUState *env, target_ulong tpc)
{
	char code_buf[] = REWRITE_CODE;
	char *tptr;

	tptr = phys_ram_base2 + tpc;
	memcpy(tptr,code_buf,REWRITE_CODE_LEN);
	tptr = phys_ram_base + tpc;
	memcpy(tptr,code_buf,REWRITE_CODE_LEN);
	return 0;
}

int verify_copy_kernel(CPUState *env, TranslationBlock *tb)
{
	/* This handles verifying and copying the kernel.
	 * We get to play a nice trick here because we
	 * know that the kernel's core code will always
	 * be in contiguous physical frames.  (Something
	 * we don't know about kernel modules.)
	 *
	 * Also note the use of ntimes.  The startup_32
	 * function gets called twice during kernel 
	 * initialization (sort of) and we only want
	 * the second one.
	 */
	unsigned long kstart;
	unsigned long klen;

	char *src = NULL;
	char *dst = NULL;

	unsigned char sha1sum[20];
	unsigned char tmpsum[20];

	int i,j;
	static int ntimes = 1;

	char buf[200] = "config/kernel";
	char buf2[41];

	FILE *cf = NULL;
	
	if (ntimes != 0) {
		ntimes--;
		goto kernel_skip;
	}
	
	printf("base = %p; base2 = %p; dirty= %p; size = %u\n",
	       phys_ram_base, phys_ram_base2, phys_ram_dirty, 
	       phys_ram_size);
	
	// Get info from file...
	cf = fopen(buf,"r");
	if (cf == NULL) {
		printf("Config file not available for kernel!\n");
		goto kernel_end;
	}
	while (!feof(cf)) {
		if (!fgets(buf,200,cf)) {
			//printf("Config file ends abruptly!\n");
			fclose(cf);
			goto kernel_end;
		}
		if (buf[0] == '#')
			continue;
		
		// Get information about the code segment...
		if (sscanf(buf,"%lx:%lx:%40s\n",&kstart,&klen,buf2) != 3) {
			printf("Config file corrupt(1)\n");
			fclose(cf);
			goto kernel_end;
		}
		// Convert checksum from ascii to real data
		buf2[40] = '\0';
		for(i=0, j=0; i < strlen(buf2) && j < 20; i+=2) {
			char tb[3];
			tb[2] = '\0';
			memcpy(tb,buf2+i,2);
			sha1sum[j++] = (unsigned char)strtoul(tb,NULL,16);
		}
		
		// Translate it!
		src = phys_ram_base + kstart;
		dst = phys_ram_base2 + kstart;
		
		// Hash it!
		sha1_csum(src,klen,tmpsum);
		
		// Log it!
		if (loglevel & CPU_LOG_KMODS) {
			fprintf(logfile, "%s: ", "kernel");
			for(i = 0; i < 20; i++)
				fprintf(logfile, "%02x", tmpsum[i]);
			fprintf(logfile, "\n");			
		}
		
		// Verify it!
		if (memcmp(sha1sum, tmpsum, 20) == 0) {
			// Copy it!
			memcpy(dst, src, klen);
			
			printf("kernel verification succeeded\n");
		}
		else {
			printf("kernel verification FAILED: ");
			for(i = 0; i < 20; i++)
				printf("%02x", tmpsum[i]);
			printf("\n");	
		}
	}
	fclose(cf);
 kernel_end:;
	/* Check to see if the user wants us 
	 * to automatically turn on arbiter.
	 * This gets set to -# in vl.c
	 */
	if (rkprot_flag < 0) {
		tb_flush(env);
		tlb_flush(env,1);
		rkprot_flag *= -1;
	}
 kernel_skip:;			
	return 0;
}


/*
  Takes as an argument the virtual address of the module structure.
  (MODREG is defined in nickle.h to be the register to check.)

  Returns   0 for verification and copy failed
            1 for succeed.
*/
int verify_copy_module(CPUState *env, TranslationBlock *tb, target_ulong mod_vaddr)
{
	int ret = 0;
	unsigned long pd;
	unsigned long pd2;
	unsigned int *t;
	unsigned long tc;
	char *name;
	FILE *cf = NULL;
	char buf[200];
	unsigned int cstart, clen;
	char *mod;
	unsigned long modc;
	unsigned int offset;
	int i,j;
	
	target_ulong tmp, vaddr;
	unsigned long len;
	unsigned long header;
	unsigned char sha1sum[20];
	unsigned char tmpsum[20];
	
	/* Don't cache this block later...
	 * Jump over to cpu-exec.c:tb_find_fast to
	 * get an idea of what this does to the TB cache.
	 */
	tb->nc = 1;
	
	/* At this point, mod_vaddr stores the address of the
	 * module being loaded.  We need to figure out
	 * the size and hash the module.  Hashing is good.
	 * Key attributes:
	 *        mod->name is at mod_vaddr + 8
	 *        mod->size is at mod_vaddr + 12
	 */
	
	// Get the size of the module and allocate local space for it.
	t = (void *)get_laddr(env, mod_vaddr, phys_ram_base);
	len = *(t+3);
	header = *t;
	mod = malloc(len);
	if (!mod) {
		printf("Could not allocate memory.\n");
		goto nope_nf;
	}
	
	// Get the name...
	name = (char *)(get_laddr(env, *(t+2), phys_ram_base) | (*(t+2) & 0xfff));
	
	/* The file containing config info...
	 * This is NOT a secure way to determine the config file name
	 * and needs to be reworked.
	 */
	snprintf(buf,200,"config/%s",name);
	cf = fopen(buf,"r");
	if (cf == NULL) {
		//printf("Config file not available for %s!\n", name);
		printf("Kernel module not allowed: %s\n", name);
		goto nope;
	}
	if (!fgets(buf,200,cf)) {
		printf("Config file is empty!\n");
		fclose(cf);
		goto nope;
	}
	// Get information about the code segment...
	if (sscanf(buf,"%x:%x\n",&cstart,&clen) != 2) {
		printf("Config file corrupt(1)\n");
		fclose(cf);
		goto nope;
	}
	// Get the sha1 checksum from the file...
	if (!fgets(buf,200,cf)) {
		printf("Config file corrupt(2)\n");
		fclose(cf);
		goto nope;
	}
	for(i=0, j=0; i < strlen(buf) && j < 20; i+=2) {
		char tb[3];
		tb[3] = '\0';
		memcpy(tb,buf+i,2);
		sha1sum[j++] = (unsigned char)strtoul(tb,NULL,16);
	}
	
	/* Copy the module into the local buffer.
	 * We do this one page at at time because
	 * the virtual pages might not correspond
	 * to contiguously increasing physical frames.
	 * In fact, in Linux 2.4, they don't.  They go
	 * in reverse.
	 */
	vaddr = mod_vaddr;
	tmp = vaddr;
	modc = 0;
	while(tmp < vaddr+len) {
		
		// # bytes to copy
		if (tmp != (tmp & ~0xfff)) // first iteration.
			tc = ((tmp+4096)&~0xfff) - tmp;				
		else
			tc = (vaddr+len)-tmp;
		
		if (tc > 4096)
			tc = 4096;
					
		// Copy
		pd = get_laddr(env, tmp, phys_ram_base);
		pd |= (tmp & 0xfff);
		memcpy(mod + modc, (char *)pd, tc);
		modc += tc;
		
		// increment.
		if (tmp != (tmp & ~0xfff)) // first iteration.
			tmp = (tmp + 4096) & ~0xfff;				
		else   
			tmp += 4096;
	}       
	
	/* Read the offsets out of the file and zero
	 * out those bytes in our module.
	 */
	while (fgets(buf, 200, cf)) {
		if (sscanf(buf, "%x\n", &offset) != 1) {
			printf("Config file is corrupt!\n");				
			goto nope;
		}
		mod[offset] = 0;
		mod[offset+1] = 0;
		mod[offset+2] = 0;
		mod[offset+3] = 0;
	}
	
	/* Take the hash of the module. */
	sha1_csum(mod+cstart, clen, tmpsum);
	

	/* Cleanup. */
	free(mod);
	mod = NULL; 
	
	/* Log it, if need be. */
	if (loglevel & CPU_LOG_KMODS) {
		fprintf(logfile, "%s: ", name);
		for(i = 0; i < 20; i++)
			fprintf(logfile, "%02x", tmpsum[i]);
		fprintf(logfile, "\n");			
	}
	
	/*  Compare the hashes and see if we match.
	 *  If so, copy the module from standard to shadow
	 *  memory, once again one page at a time.
	 */
	if (memcmp(sha1sum,tmpsum,20) == 0) {			
		printf("Kernel module verified and copied: %s\n", name);
		ret = 1;
		
		tmp = vaddr + cstart;
		while(tmp < vaddr+cstart+clen) {
			
			// # bytes to copy.
			if (tmp != (tmp & ~0xfff)) // first iteration.
				tc = ((tmp+4096)&~0xfff) - tmp;				
			else
				tc = (vaddr+len)-tmp;
			
			if (tc > 4096)
				tc = 4096;
			
			// Copy bytes
			pd = get_laddr(env, tmp, phys_ram_base);
			pd |= (tmp & 0xfff);
			pd2 = get_laddr(env, tmp, phys_ram_base2);
			pd2 |= (tmp & 0xfff);

			memcpy((void *)pd2, (void *)pd, tc);
			
			// increment.
			if (tmp != (tmp & ~0xfff)) // first iteration.
				tmp = (tmp + 4096) & ~0xfff;				
			else   
				tmp += 4096;
		}
	}
	else {
		printf("Kernel module not allowed: %s\n", name);
	}						
	
 nope:
	free(mod);
 nope_nf:
	return ret;
}
