/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *              Pentium Pro/II routines:
 *              Alexander Kjeldaas <astor@guardian.no>
 *              Finn Arne Gangstad <finnag@guardian.no>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * Changes:     Ingo Molnar, converted csum_partial_copy() to 2.1 exception
 *			     handling.
 *		Andi Kleen,  add zeroing on error
 *                   converted to pure assembler
 */

#include <linux/export.h>
#include <asm/nospec-branch.h>

/*
unsigned int csum_partial_copy_generic (const char *src, char *dst,
				  int len)
 */

/*
 * Copy from ds while checksumming, otherwise like csum_partial
 */

#define EXC(y...)						\
	9999: y;						\
	_ASM_EXTABLE_TYPE(9999b, 9f, EX_TYPE_UACCESS)

#ifndef CONFIG_X86_USE_PPRO_CHECKSUM

#define ARGBASE 16
#define FP		12

SYM_FUNC_START(csum_partial_copy_generic)
	subl  $4,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl ARGBASE+12(%esp),%ecx	# len
	movl ARGBASE+4(%esp),%esi	# src
	movl ARGBASE+8(%esp),%edi	# dst

	xorl %eax,%eax			# sum
	testl $2, %edi			# Check alignment.
	jz 2f				# Jump if alignment is ok.
	subl $2, %ecx			# Alignment uses up two bytes.
	jae 1f				# Jump if we had at least two bytes.
	addl $2, %ecx			# ecx was < 2.  Deal with it.
	jmp 4f
EXC(1:	movw (%esi), %bx	)
	addl $2, %esi
EXC(	movw %bx, (%edi)	)
	addl $2, %edi
	addw %bx, %ax
	adcl $0, %eax
2:
	movl %ecx, FP(%esp)
	shrl $5, %ecx
	jz 2f
	testl %esi, %esi		# what's wrong with clc?
EXC(1:	movl (%esi), %ebx	)
EXC(	movl 4(%esi), %edx	)
	adcl %ebx, %eax
EXC(	movl %ebx, (%edi)	)
	adcl %edx, %eax
EXC(	movl %edx, 4(%edi)	)

EXC(	movl 8(%esi), %ebx	)
EXC(	movl 12(%esi), %edx	)
	adcl %ebx, %eax
EXC(	movl %ebx, 8(%edi)	)
	adcl %edx, %eax
EXC(	movl %edx, 12(%edi)	)

EXC(	movl 16(%esi), %ebx 	)
EXC(	movl 20(%esi), %edx	)
	adcl %ebx, %eax
EXC(	movl %ebx, 16(%edi)	)
	adcl %edx, %eax
EXC(	movl %edx, 20(%edi)	)

EXC(	movl 24(%esi), %ebx	)
EXC(	movl 28(%esi), %edx	)
	adcl %ebx, %eax
EXC(	movl %ebx, 24(%edi)	)
	adcl %edx, %eax
EXC(	movl %edx, 28(%edi)	)

	lea 32(%esi), %esi
	lea 32(%edi), %edi
	dec %ecx
	jne 1b
	adcl $0, %eax
2:	movl FP(%esp), %edx
	movl %edx, %ecx
	andl $0x1c, %edx
	je 4f
	shrl $2, %edx			# This clears CF
EXC(3:	movl (%esi), %ebx	)
	adcl %ebx, %eax
EXC(	movl %ebx, (%edi)	)
	lea 4(%esi), %esi
	lea 4(%edi), %edi
	dec %edx
	jne 3b
	adcl $0, %eax
4:	andl $3, %ecx
	jz 7f
	cmpl $2, %ecx
	jb 5f
EXC(	movw (%esi), %cx	)
	leal 2(%esi), %esi
EXC(	movw %cx, (%edi)	)
	leal 2(%edi), %edi
	je 6f
	shll $16,%ecx
EXC(5:	movb (%esi), %cl	)
EXC(	movb %cl, (%edi)	)
6:	addl %ecx, %eax
	adcl $0, %eax
7:
	xorl %edx, %edx
8:
	popl %ebx
	popl %esi
	popl %edi
	popl %ecx			# equivalent to addl $4,%esp
	RET
9:
	movl $-1,%eax
	movl $-1,%edx
	jmp 8b
SYM_FUNC_END(csum_partial_copy_generic)

#else

/* Version for PentiumII/PPro */

#define ROUND1(x) \
	EXC(movl x(%esi), %ebx	)	;	\
	addl %ebx, %eax			;	\
	EXC(movl %ebx, x(%edi)	)	;

#define ROUND(x) \
	EXC(movl x(%esi), %ebx	)	;	\
	adcl %ebx, %eax			;	\
	EXC(movl %ebx, x(%edi)	)	;

#define ARGBASE 12

SYM_FUNC_START(csum_partial_copy_generic)
	pushl %ebx
	pushl %edi
	pushl %esi
	movl ARGBASE+4(%esp),%esi	#src
	movl ARGBASE+8(%esp),%edi	#dst
	movl ARGBASE+12(%esp),%ecx	#len
	xorl %eax, %eax			#sum
#	movl %ecx, %edx
	movl %ecx, %ebx
	movl %esi, %edx
	shrl $6, %ecx
	andl $0x3c, %ebx
	negl %ebx
	subl %ebx, %esi
	subl %ebx, %edi
	lea  -1(%esi),%edx
	andl $-32,%edx
	lea 3f(%ebx,%ebx), %ebx
	testl %esi, %esi
	JMP_NOSPEC ebx
1:	addl $64,%esi
	addl $64,%edi
	EXC(movb -32(%edx),%bl)	; EXC(movb (%edx),%bl)
	ROUND1(-64) ROUND(-60) ROUND(-56) ROUND(-52)
	ROUND (-48) ROUND(-44) ROUND(-40) ROUND(-36)
	ROUND (-32) ROUND(-28) ROUND(-24) ROUND(-20)
	ROUND (-16) ROUND(-12) ROUND(-8)  ROUND(-4)
3:	adcl $0,%eax
	addl $64, %edx
	dec %ecx
	jge 1b
4:	movl ARGBASE+12(%esp),%edx	#len
	andl $3, %edx
	jz 7f
	cmpl $2, %edx
	jb 5f
EXC(	movw (%esi), %dx         )
	leal 2(%esi), %esi
EXC(	movw %dx, (%edi)         )
	leal 2(%edi), %edi
	je 6f
	shll $16,%edx
5:
EXC(	movb (%esi), %dl         )
EXC(	movb %dl, (%edi)         )
6:	addl %edx, %eax
	adcl $0, %eax
7:
	xorl %edx, %edx
8:
	popl %esi
	popl %edi
	popl %ebx
	RET
9:
	movl $-1,%eax
	movl $-1,%edx
	jmp 8b
SYM_FUNC_END(csum_partial_copy_generic)

#undef ROUND
#undef ROUND1

#endif
EXPORT_SYMBOL(csum_partial_copy_generic)
