/*
    The IDA Pro Book - GOT Entry Locator
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

static main() {
   auto ea, xref;
   ea = ScreenEA();
   xref = Rfirst0(ea);
   if (xref != BADADDR && XrefType() == fl_CN && SegName(xref) == ".plt") {
      ea = Dfirst(xref);
      if (ea != BADADDR) {
         Message("GOT entry for %s is at 0x%08x\n", GetFunctionName(xref), ea);
      }
      else {
         Message("Sorry, failed to locate GOT entry\n");
      }
   }
   else {
      Message("Sorry this does not appear to be a library function call\n");
   }
}
