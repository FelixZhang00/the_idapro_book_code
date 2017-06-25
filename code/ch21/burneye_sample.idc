/*
    The IDA Pro Book - Listing 15-1
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
  auto ecx,esi,edi,ebx,edx,eax,cf;

ecx = Dword(0x5371000);
esi = 0x5371087;
edi = esi;
ebx = Dword(0x5371004);

if(ebx!=0){
  edx = 0;
  do{
    eax = 8;
    do{
      edx = (edx>>1) & 0x7FFFFFFF;
      cf = ebx&1;
      if(cf == 1){
        edx = edx|0x80000000;
      }
      ebx = (ebx>>1)& 0x7FFFFFFF;
      if(cf == 1){
       ebx = ebx^0xC0000057; 
      }
      eax--;
    }while(eax!=0);
    
    edx = (edx>>24)&0xFF;
    eax = Byte(esi++);
    eax = eax ^ edx;
    PatchByte(edi++,eax);
    ecx--;
  }while(ecx!=0);
} 
  
}


