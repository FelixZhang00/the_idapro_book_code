/*
   The IDA Pro Book - Simple Python Byte Code Module
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

#include "python.hpp"

char *compare_ops[] = {
    "<", "<=", "==", "!=", ">", ">=",
    "in", "not in", "is", "is not", "exception match", "BAD"
};

//----------------------------------------------------------------------
void idaapi py_out(void) {
   char str[MAXSTR];  //MAXSTR is an IDA define from pro.h
   init_output_buffer(str, sizeof(str));
   OutMnem(12);       //first we output the mnemonic
   if(cmd.Op1.type != o_void) {  //then there is an argument to print
      out_one_operand(0);
   }
   term_output_buffer();
   gl_comm = 1;      //we want comments!
   MakeLine(str);    //output the line with default indentation
}

//--------------------------------------------------------------------------
// function to produce start of disassembled text
//set as member of LPH struct
void idaapi header(void) {
   MakeLine("My header line");
}

void idaapi footer() {
   MakeLine("My footer line");
}

//----------------------------------------------------------------------
// function to produce start of segment
void idaapi segstart(ea_t ea) {  
}

//--------------------------------------------------------------------------
// function to produce end of segment
void idaapi segend(ea_t ea) {
}

//--------------------------------------------------------------------------
void idaapi python_data(ea_t ea) {
   char obuf[256];
   init_output_buffer(obuf, sizeof(obuf));
   int col = 0;
   uint32 flags = get_flags_novalue(ea);
   if (isWord(flags)) {
      out_snprintf("%s %xh", ash.a_word ? ash.a_word : "", get_word(ea));
   }
   else if (isDwrd(flags)) {
      out_snprintf("%s %xh", ash.a_dword ? ash.a_dword : "", get_long(ea));
   }
   else { //if (isByte(flags)) {
      int val = get_byte(ea);
      char ch = ' ';
      if (val >= 0x20 && val <= 0x7E) {
         ch = val;
      }
      out_snprintf("%s %02xh   ; %c", ash.a_byte ? ash.a_byte : "", val, ch);
   }
   term_output_buffer();
   gl_comm = 1;
   MakeLine(obuf);
   return;
}

//--------------------------------------------------------------------------

bool idaapi py_outop(op_t& x) {
   if (cmd.itype == COMPARE_OP) {
      //For comparisons, the argument indicates the type of comparison to be
      //performed.  Print a symbolic representation of the comparison rather
      //than a number.
      if (x.value < qnumber(compare_ops)) {
         OutLine(compare_ops[x.value]);
      }
      else {
         OutLine("BAD OPERAND");
      }
   }
   else if (cmd.auxpref & HAS_JREL) {
      //we don't test for x.type == o_near here because we need to distinguish
      //between relative jumps and absolute jumps.  In our case, HAS_JREL 
      //implies o_near
      out_name_expr(x, x.addr, x.addr);
   }
   else {  //otherwise just print the operand value
      OutValue(x);
   }
   return true;
}

