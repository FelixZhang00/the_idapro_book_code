/*
    The IDA Pro Book - Chapter 22 Instruction Scanner
    Copyright (C) 2008 Chris Eagle <cseagle@gmail.com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA

*/

/*
 * Scan a binary for instruction sequences that can be used to 
 * transfer control to your shellcode such as "jmp esp"
 */

#include <idc.idc>

static main() {
   auto ea, code, reg, regstr, count, op, prev;
   count = 0;
   regstr = AskStr("esp", "What register points to your shellcode?");
   if (regstr != 0) {
      Message("Searching...\n");
      reg = -1;
      if (regstr == "eax")
         reg = 0;
      else if (regstr == "ecx")
         reg = 1;
      else if (regstr == "edx")
         reg = 2;
      else if (regstr == "ebx")
         reg = 3;
      else if (regstr == "esp")
         reg = 4;
      else if (regstr == "ebp")
         reg = 5;
      else if (regstr == "esi")
         reg = 6;
      else if (regstr == "edi")
         reg = 7;
      if (reg != -1) {
         code = form("FF E%d", reg);
         ea = FindBinary(MinEA(), SEARCH_DOWN | SEARCH_CASE, code);
         while (ea != BADADDR) {
            Message("Found jmp %s (%s) at 0x%x\n", regstr, code, ea);
            count++;
            ea = FindBinary(ea, SEARCH_NEXT | SEARCH_CASE, code);
         }
         code = form("FF D%d", reg);
         ea = FindBinary(MinEA(), SEARCH_DOWN | SEARCH_CASE, code);
         while (ea != BADADDR) {
            Message("Found call %s (%s) at 0x%x\n", regstr, code, ea);
            count++;
            ea = FindBinary(ea, SEARCH_NEXT | SEARCH_CASE, code);
         }
         code = form("5%d C3", reg);
         ea = FindBinary(MinEA(), SEARCH_DOWN | SEARCH_CASE, code);
         while (ea != BADADDR) {
            Message("Found push %s/ret (%s) at 0x%x\n", regstr, code, ea);
            count++;
            ea = FindBinary(ea, SEARCH_NEXT | SEARCH_CASE, code);
         }
         code = form("5%d C2", reg);
         ea = FindBinary(MinEA(), SEARCH_DOWN | SEARCH_CASE, code);
         while (ea != BADADDR) {
            Message("Found push %s/retN (%s) at 0x%x\n", regstr, code, ea);
            count++;
            ea = FindBinary(ea, SEARCH_NEXT | SEARCH_CASE, code);
         }
      }
      else { //look for pop/ret and pop/pop/ret
         for (op = 0x58; op <= 0x5f; op++) {
            if (op == 0x5c) continue;  //skip pop esp
            code = form("%02x C3", op);
            ea = FindBinary(MinEA(), SEARCH_DOWN | SEARCH_CASE, code);
            while (ea != BADADDR) {
               Message("Found pop/ret (%s) at 0x%x\n", code, ea);
               prev = Byte(ea - 1);
               if (prev >= 0x58 && prev <= 0x5f && prev != 0x5c) {
                  Message("Found pop/pop/ret (%02x %s) at 0x%x\n", prev, code, ea - 1);
                  count++;
               }
               count++;
               ea = FindBinary(ea, SEARCH_NEXT | SEARCH_CASE, code);
            }
         }
      }
   }
   Message("Found %d occurrences\n", count);
}
