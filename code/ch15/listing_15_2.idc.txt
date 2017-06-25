/*
    The IDA Pro Book - Listing 15-2
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
   auto func, end, count, inst;
   func = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
   if (func != -1) {
      end = GetFunctionAttr(func, FUNCATTR_END);
      count = 0;
      inst = func;
      while (inst < end) {
         count++;
         inst = FindCode(inst, SEARCH_DOWN | SEARCH_NEXT);
      }
      Warning("%s contains %d instructions\n", Name(func), count);
   }
   else {
      Warning("No function found at location %x", ScreenEA());
   }
}
