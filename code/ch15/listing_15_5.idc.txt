/*
    The IDA Pro Book - Listing 15-5
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
   auto entryPoints, i, ord, addr, name, purged, file, fd;
   file = AskFile(1, "*.idt", "Select IDT save file");
   fd = fopen(file, "w");
   entryPoints = GetEntryPointQty();
   fprintf(fd, "ALIGNMENT 4\n");
   fprintf(fd, "0 Name=%s\n", GetInputFile());
   for (i = 0; i < entryPoints; i++) {
      ord = GetEntryOrdinal(i);
      if (ord == 0) continue;
      addr = GetEntryPoint(ord);
      if (ord == addr) {
         continue; //entry point has no ordinal
      }
      name = Name(addr);
      fprintf(fd, "%d Name=%s", ord, name);
      purged = GetFunctionAttr(addr, FUNCATTR_ARGSIZE);
      if (purged > 0) {
         fprintf(fd, " Pascal=%d", purged);
      }
      fprintf(fd, "\n");
   }
}
