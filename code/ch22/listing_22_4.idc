/*
    The IDA Pro Book - Listing 22-4
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
   auto func, frame, args, member, eip_loc, idx, prev_idx, prev, delta;
   func = ScreenEA(); //process function at cursor location
   frame = GetFrame(func);
   if (frame == -1) return;
   Message("Enumerating stack for %s\n", GetFunctionName(func));
   eip_loc = GetFrameLvarSize(func) + GetFrameRegsSize(func);
   prev_idx = -1;
   for (idx = 0; idx < GetStrucSize(frame); ) {
      member = GetMemberName(frame, idx);
      if (member != "") {
         if (prev_idx != -1) {
            //compute distance from previous field to current field
            delta = idx - prev_idx; 
            Message("%15s: %4d bytes (%4d bytes to eip)\n", 
                    prev, delta, eip_loc - prev_idx);
         }
         prev_idx = idx;
         prev = member;
         idx = idx + GetMemberSize(frame, idx);
      }
      else idx++;
   }
   if (prev_idx != -1) {
      //make sure we print the last field in the frame
      delta = GetStrucSize(frame) - prev_idx; 
      Message("%15s: %4d bytes (%4d bytes to eip)\n", 
              prev, delta, eip_loc - prev_idx);
   }
}

