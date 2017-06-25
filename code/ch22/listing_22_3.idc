/*
    The IDA Pro Book - Listing 22-3
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

static findStackBuffers(func_addr, minsize) {
   auto frame, member, idx, prev_idx, delta, prev;
   prev_idx = -1;
   frame = GetFrame(func_addr);
   if (frame == -1) return;   //bad function
   for (idx = 0; idx < GetStrucSize(frame); ) {
      member = GetMemberName(frame, idx);
      if (member != "") {
         if (prev_idx != -1) {
            //compute distance from previous field to current field
            delta = idx - prev_idx; 
            if (delta >= minsize) {
               Message("%s: possible buffer %s: %d bytes\n", 
                       GetFunctionName(func_addr), prev, delta);
            }
         }
         prev_idx = idx;
         prev = member;
         idx = idx + GetMemberSize(frame, idx);
      }
      else idx++;
   }
}

static main() {
   auto func, func_attr;

   for (func = NextFunction(0); func != BADADDR; func = NextFunction(func)) {
      func_attr = GetFunctionAttr(func, FUNCATTR_FLAGS);
      if (func_attr & FUNC_THUNK) continue;
      findStackBuffers(func, 16);
   }
}
