USE32

ENTRY  equ 0x400000

magic dd 0x1dab00c
size  dd last - start
base  dd ENTRY

;org      0x400000
start:
   push  0xAAAAAAAA
   call  invert
   add   esp, 4
   push  eax
   mov   ecx, esp
   mov   edx, 4
   mov   ebx, 1
   mov   eax, 4
   int   0x80
   push  ENTRY+hello-start
   call  strlen
   add   esp, 4
   mov   ebx, 1
   mov   eax, 1
   int   0x80
invert:
   push ebp
   mov  ebp, esp
   mov  eax, [ebp + 8]
   not  eax
   leave
   ret
strlen:
   mov  esi, [esp + 4]
   xor  ecx, ecx
top:
   lodsb
   test al, al
   je   done
   inc  ecx
   jmp  top
done:
   mov  eax, ecx   
   ret
hello  db 'Hello', 0
last:
   