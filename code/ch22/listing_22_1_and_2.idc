/*
    The IDA Pro Book - Listing 22-1 and Listing 22-2
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

static getFuncAddr(fname) {
   auto func, seg;
   func = LocByName(fname);
   if (func != BADADDR) {
      seg = SegName(func);
      //what segment did we find it in?
      if (seg == "extern") {
         //Likely an ELF if we are in "extern"
         //First (and only) data xref should be from got
         func = DfirstB(func);
         if (func != BADADDR) {
            seg = SegName(func);
            if (seg != ".got") return BADADDR;
            //Now, first (and only) data xref should be from plt
            func = DfirstB(func);
            if (func != BADADDR) {
               seg = SegName(func);
               if (seg != ".plt") return BADADDR;
            }
         }
      }
      else if (seg != ".text") {
         //otherwise, if the name was not in the .text
         //section, then we don't have an algorithm for
         //finding it automatically
         func = BADADDR;
      }
   }
   return func;
}

static flagCalls(fname) {
   auto func, xref;
   //get the callable address of the named function
   func = getFuncAddr(fname);
   if (func != BADADDR) {
      //Iterate through calls to the named function, and add a comment
      //at each call
      for (xref = RfirstB(func); xref != BADADDR; xref = RnextB(func, xref)) {
         if (XrefType() == fl_CN || XrefType() == fl_CF) {
            MakeComm(xref, "*** AUDIT " + fname + " HERE ***");
         }
      }
      //Iterate through data references to the named function, and add a
      //comment at reference
      for (xref = DfirstB(func); xref != BADADDR; xref = DnextB(func, xref)) {
         if (XrefType() == dr_O) {
            MakeComm(xref, "*** AUDIT " + fname + " HERE ***");
         }
      }
   }
}

static main() {
   flagCalls("strcpy");
   flagCalls("strcat");
   flagCalls("sprintf");
   flagCalls("gets");
}
