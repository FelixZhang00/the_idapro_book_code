/*
   Copyright (c) 2003,2006 Chris Eagle (cseagle at gmail d0t c0m)
   
   Permission is hereby granted, free of charge, to any person obtaining a copy of 
   this software and associated documentation files (the "Software"), to deal in 
   the Software without restriction, including without limitation the rights to 
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
   the Software, and to permit persons to whom the Software is furnished to do so, 
   subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in all 
   copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
   FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
   COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
 
/*
  IDA Pro script to unpack UPX compressed Windows PE files, including those
  scrambled with UPX-Scrambler.  Note, this currently only works on binaries
  that make use of the n2b_d32 decompressor from the UCL compression library.
  I suspect it can be easily modified to handle other decompression algorithm
  variants.
  
  The script automatically extracts a few variables from the
  decompressor, decompresses the executable, initiates autoanalysis of the 
  decompressed binary, then reconstructs the import list and import table to 
  make analysis easier.
*/

#include <idc.idc>

#define gte(z) ((z & 0x80000000) == 0)
#define lt(z) ((z & 0x80000000) == 0x80000000)

//Undefine 4 consecutive bytes
static undefDword(addr) {
   auto cnt;
   for (cnt = 0; cnt < 4; cnt = cnt + 1) {
      MakeUnkn(addr + cnt, 1);
   }
}

//Ida4.9 has problems when patching a value to 0xFF
//need to path to some other value first
static ensurePatch(addr, val) {
   auto cnt;
   for (cnt = 0; cnt < 4; cnt = cnt + 1) {
      PatchByte(addr + cnt, 0);
      PatchByte(addr + cnt, val);
      val = val >> 8;
   }
}

/*
   Analyze the import list, define strings as they are located.
   For each function name found, define a new label at the appropriate
   location in the import table
   Parameters:
      start - The address at which the import list starts
      codeGuess - The address at which we believe the code was unpacked to
*/
static imports(start, codeGuess) {
   auto dword1, dword2, end, cnt, func;
   auto ebx;

   //Message("start = %x\n", start);
   
   SetLongPrm(INF_STRTYPE, ASCSTR_TERMCHR);
   while (1) {
      undefDword(start);
      MakeDword(start);
      dword1 = Dword(start);
      //Message("dword1 = %x\n", dword1);
      if (dword1 == 0) return;
      start = start + 4;
      undefDword(start);
      MakeDword(start);
      dword2 = Dword(start);
      ebx = codeGuess + dword2;
      //Message("dword2 = %x\n", dword2);
      start = start + 4;
      MakeUnkn(start, 1);
      while (Byte(start) == 1) {
         //Message("inside loop\n");
         start = start + 1;
         end = start;
         func = "";
         while (Byte(end) != 0) {
            MakeUnkn(end, 1);
            //build a string representation of the function name
            func = form("%s%c", func, Byte(end));
            end = end + 1;
         }
         MakeUnkn(end, 1);
         end = end + 1;
         MakeUnkn(start, 1);
         //Message("Converting %x..%x to %s\n", start, end, func);
         MakeStr(start, end);
         start = end;
         MakeUnkn(start, 1);

         //assign a name to the function pointer
         undefDword(ebx);
         MakeDword(ebx);
         //define a label for the function just discovered
         if (LocByName(func) != BADADDR) {
            func = form("%s_", func);
         }
         MakeName(ebx, func);
         ebx = ebx + 4;
      }
      start = start + 1;
   }
}

/*
   This is the decode function.  It performs the unpacking operation.
   Commented labels correspond to labels in the actual n2b_d32 source.
   Parameters:
      source - The starting address of the compressed data
      dest - The start address for the decompressed data
      numFixes - the number of relocation fix ups to perform
      ediValue - byte value for edi comparison in fix up loop
*/
static decode(source, dest, numFixes, ediValue) {
   auto eax, ebx, ecx, ebp;
   auto edi, esi, al;
   auto skip, b1, b2, b3;
   auto carry, edx, bl, code;

   code = dest;
   
   ebp = 0xFFFFFFFF;

   ebx = 0; //forces dc11_n2b on first pass
//decompr_loop_n2b
   while (1) {
//decompr_loop_n2b
      while (1) {
         carry = lt(ebx);
         ebx = ebx * 2;
         if (ebx == 0) {
//dcl1_n2b
            ebx = Dword(source);
            source = source + 4;
            carry = lt(ebx);
            ebx = ebx * 2 + 1;
         }
         if (carry == 0) break;
//decompr_literalb_n2b
         MakeUnkn(dest, 0);
         PatchByte(dest, 0);
         PatchByte(dest, Byte(source));
         source = source + 1;
         dest = dest + 1;
      }
      eax = 1;
//loop1_n2b   
      while (1) {
         carry = lt(ebx) ? 1 : 0;
         ebx = ebx * 2;
         if (ebx == 0) {
            ebx = Dword(source);
            source = source + 4;
            carry = lt(ebx) ? 1 : 0;
            ebx = ebx * 2 + 1;
         }
         eax = eax * 2 + carry;
         carry = lt(ebx) ? 1 : 0;
         ebx = ebx * 2;
         if (carry == 0) continue;   //jnc
         if (ebx != 0) break;
         ebx = Dword(source);
         source = source + 4;
         carry = lt(ebx) ? 1 : 0;
         ebx = ebx * 2 + 1;
         if (carry == 1) break;  //continue on jnb
      }
//loopend1_n2b
      ecx = 0;
      carry = (eax >= 0 && eax < 3) ? 1 : 0;
      eax = eax - 3;
      if (carry == 0) {  //jb
         eax = eax << 8;
         eax = eax | Byte(source);
         source = source + 1;
         eax = ~eax;
         if (eax == 0) break;
         ebp = eax;
      }
//decompr_ebpeax_n2b   
      carry = lt(ebx) ? 1 : 0;
      ebx = ebx * 2;
      if (ebx == 0) {
         ebx = Dword(source);
         source = source + 4;
         carry = lt(ebx) ? 1 : 0;
         ebx = ebx * 2 + 1;
      }
//gotbit_2
      ecx = ecx * 2 + carry;
      carry = lt(ebx) ? 1 : 0;
      ebx = ebx * 2;
      if (ebx == 0) {
         ebx = Dword(source);
         source = source + 4;
         carry = lt(ebx) ? 1 : 0;
         ebx = ebx * 2 + 1;
      }
//gotbit_3
      ecx = ecx * 2 + carry;
      if (ecx == 0) {
         ecx = 1;
//loop2_n2b
         while (1) {
            carry = lt(ebx) ? 1 : 0;
            ebx = ebx * 2;
            if (ebx == 0) {
               ebx = Dword(source);
               source = source + 4;
               carry = lt(ebx) ? 1 : 0;
               ebx = ebx * 2 + 1;
            }
//gotbit_4
            ecx = ecx * 2 + carry;
            carry = lt(ebx) ? 1 : 0;
            ebx = ebx * 2;
            if (carry == 0) continue;
            if (ebx != 0) break;
            ebx = Dword(source);
            source = source + 4;
            carry = lt(ebx) ? 1 : 0;
            ebx = ebx * 2 + 1;
            if (carry == 1) break;
         }
//loopend2_n2b
         ecx = ecx + 2;
      }
//decompr_got_mlen_n2b
      carry = (ebp < 0xFFFFF300 || ebp >= 0) ? 1 : 0;
      ecx = ecx + 1 + carry;
      edx = dest + ebp;
      if (ebp > -4 && ebp < 0) {
//loop3_n2b
         do {
            MakeUnkn(dest, 0);
            PatchByte(dest, 0);
            PatchByte(dest, Byte(edx));
            edx = edx + 1;
            dest = dest + 1;
            ecx = ecx - 1;
         } while (ecx != 0);
         continue;      
      }
//decompr_copy4_n2b
      do {
         MakeUnkn(dest, 0);
         ensurePatch(dest, Dword(edx));   
         edx = edx + 4;
         dest = dest + 4;
         carry = (ecx & 0xFFFFFFFC) == 0 ? 1 : 0;
         ecx = ecx - 4;
      } while (carry == 0 && ecx != 0);
      dest = dest + ecx;
   }
//decompr_end_n2b;
//if (AskYN(0, "Done expanding, do fixup?") == 0) return;

   //the unpacking is complete, go back and fix up relative
   //jumps and references
   esi = code;
   edi = esi;
   al = 2;
   for (ecx = numFixes; ecx > 0; ecx--) {
      while (al > 1 || Byte(edi) != ediValue) {
         al = Byte(edi);
         edi = edi + 1;
         al = (al - 0xE8) & 0xFF;  //+= 0x18
      }
      eax = Dword(edi);
      bl = Byte(edi + 4);
      
      b1 = (eax >> 8) & 0xFF;
      b2 = (eax >> 16) & 0xFF;
      b3 = (eax >> 24) & 0xFF;
      eax = (b1 << 16) + (b2 << 8) + b3;
      eax = eax - edi;
      bl = (bl - 0xE8) & 0xFF;
      eax = eax + esi;
      MakeUnkn(dest, 0);
      ensurePatch(edi, eax);
      edi = edi + 5;
      al = bl;
   }
   return;
}

#define DATA_START 1
#define CODE_START 6
#define NUM_FIXUPS 0xD5
#define EDI_GUESS 0xE3
#define IMPORT_LIST 0x106
#define IMPORT_TABLE 0x115

//------------------------------------------------------------------------
static main(void) {
  auto from,to,size,start;
  auto addr, last;
  auto dataGuess, codeGuess, fixUpGuess;
  auto importList, ediGuess, importTable;
  auto importTableLoc, importListLoc;
  
  start = LocByName("start");
  importListLoc = IMPORT_LIST;
  importTableLoc = IMPORT_TABLE;
  last = BADADDR;
  addr = FirstSeg();
  while (addr != BADADDR) {
    last = SegEnd(addr);
    addr = NextSeg(addr);
  }
  //Message("last address = %x\n", last);

  from = start;
  //guess where the compressed data starts
  dataGuess = GetOperandValue(start + DATA_START, 1);
  //guess where the data is to be unpacked to
  codeGuess = dataGuess + GetOperandValue(start + CODE_START, 1);
  //guess how many relative fixups we need to make
  fixUpGuess = GetOperandValue(start + NUM_FIXUPS, 1);
  //guess what value edi will be compared to in the fix up loop
  ediGuess = GetOperandValue(start + EDI_GUESS, 1);
  Message("dataGuess: %x, codeGuess: %x, fixUpGuess: %x\n", dataGuess, codeGuess, fixUpGuess);
  if (Byte(start + importListLoc) != 0x8D) {
     importListLoc = 0xD3;
     importTableLoc = 0xE2;
  }
  //guess where the list of imports begins
  importList = codeGuess + GetOperandValue(start + importListLoc, 1);
  //guess where the import jump table begins
  importTable = codeGuess + GetOperandValue(start + importTableLoc, 1);
  Message("importTable: %x, importList: %x, ediGuess: %x\n", importTable, importList, ediGuess);

//  SegDelete(dataGuess, 0);
  decode(dataGuess, codeGuess, fixUpGuess, ediGuess);

  Message("Analyzing: %x..%x\n", codeGuess, last);
  AnalyseArea(codeGuess, last);
//  if (AskYN(0, "Convert import table?") == 1) {
     imports(importList, codeGuess);
//  }
  
//  AnalyseArea(from, last);
}
