/*
    The IDA Pro Book - Listing 15-4
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

#include <idc.idc>

static list_callers(bad_func) {
   auto func, addr, xref, source;
   func = LocByName(bad_func);
   if (func == BADADDR) {
      Warning("Sorry, %s not found in database", bad_func);
   }
   else {
      for (addr = RfirstB(func); addr != BADADDR; addr = RnextB(func, addr)) {
         xref = XrefType();
         if (xref == fl_CN || xref == fl_CF) {
            source = GetFunctionName(addr);
            Message("%s is called from 0x%x in %s\n", bad_func, addr, source);
         }
      }
   }
}
static main() {
   list_callers("_strcpy");
   list_callers("_sprintf");
}
