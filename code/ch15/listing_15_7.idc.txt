/*
    The IDA Pro Book - Listing 15-7
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

auto var_4, edx, eax, al;
var_4 = 0;
while (var_4 <= 0x3C1) {
   edx = var_4;
   edx = edx + 0x804B880;
   eax = var_4;
   eax = eax + 0x804B880;
   al = Byte(eax);
   al = al ^ 0x4B;
   PatchByte(edx, al);
   var_4++;
}
