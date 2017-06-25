/*
    The IDA Pro Book - Rebuild Process Import Table Example
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
 * This script should be run from an IDA debugger session as it expects to
 * parse PE headers for loaded libraries prior to terminating the process
 * being debugged
 */

#include <idc.idc>

#define MZ_MAGIC 0x5A4D
#define PE_MAGIC 0x4550
#define e_lfanew 0x3C
#define IMAGE_EXPORT_DIRECTORY 0x78
#define NumberOfFunctions 0x14
#define NumberOfNames 0x18
#define AddressOfFunctions 0x1C
#define AddressOfNames 0x20
#define AddressOfNameOrdinals 0x24

static main() {

   auto func, base, lfanew, pehdr, export_dir;
   auto eat, ent, eot, nof, non;
   auto i, j, a, name, idata, end;

   end = SelEnd();
   if (end == BADADDR) return;
   for (idata = SelStart(); idata < end; idata = idata + 4) {
      MakeDword(idata);
      func = Dword(idata);
      base = func & ~0xFFF;
   
      while (1) {
         while (base > MinEA() && Word(base) != MZ_MAGIC) {
            base = base - 0x1000;
         }
         lfanew = Word(base + e_lfanew);
         if (base < MinEA() || Word(base + lfanew) == PE_MAGIC) break;
      }
      if (base >= MinEA()) {
         pehdr = base + lfanew;
         export_dir = base + Dword(pehdr + IMAGE_EXPORT_DIRECTORY);
         nof = Dword(export_dir + NumberOfFunctions);
         non = Dword(export_dir + NumberOfNames);
         eat = base + Dword(export_dir + AddressOfFunctions);
         ent = base + Dword(export_dir +  AddressOfNames);
         eot = base + Dword(export_dir + AddressOfNameOrdinals);
         for (i = 0; i < nof; i++) {
            a = Dword(eat + i * 4) + base;
            if (a == func) break;
         }
         if (i < nof) {
            for (j = 0; j < non; j++) {
               if (Word(eot + j * 2) == i) break;
            }
            if (j < non) {
               name = Dword(ent + j * 4) + base;
               Message("%s\n", GetString(name, -1, ASCSTR_C));
               if (MakeNameEx(idata, GetString(name, -1, ASCSTR_C), SN_NOCHECK | SN_NOWARN) == 0) {
                  MakeNameEx(idata, GetString(name, -1, ASCSTR_C) + "_", SN_NOCHECK | SN_NOWARN);
               }
            }
         }
      }
   }
}
