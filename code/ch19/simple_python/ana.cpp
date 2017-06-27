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

unsigned short flags[256] = {
/*  0*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 16*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 32*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 48*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 64*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 80*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
          HAS_NAME, //STORE_NAME
          HAS_NAME,   //DELETE_NAME
          HAS_IMM,    //UNPACK_SEQUENCE
          HAS_JREL,   //FOR_ITER
          0, 
          HAS_NAME, //STORE_ATTR
/* 96*/   HAS_NAME, HAS_NAME, HAS_NAME, 
          HAS_IMM,    //DUP_TOPX
          HAS_CONST | HAS_READ,    //LOAD_CONST
          HAS_NAME | HAS_READ,    //LOAD_NAME
          HAS_IMM,    //BUILD_TUPLE
          HAS_IMM,    //BUILD_LIST
          HAS_IMM,    //BUILD_MAP
          HAS_NAME | HAS_READ,   //LOAD_ATTR
          HAS_COMPARE,     //COMPARE_OP
          HAS_NAME | HAS_READ, //IMPORT_NAME
          HAS_NAME | HAS_READ, //IMPORT_FROM
          0, 
          HAS_JREL,    //JUMP_FORWARD
          HAS_JREL,    //JUMP_IF_FALSE
/*112*/   HAS_JREL,    //JUMP_IF_TRUE
          HAS_JABS,    //JUMP_ABSOLUTE
          0, 
          0, 
          HAS_NAME | HAS_READ,   //LOAD_GLOBAL
          0, 
          0, 
          HAS_JABS,   //CONTINUE_LOOP
          HAS_JREL,   //SETUP_LOOP
          HAS_JREL,   //SETUP_EXCEPT
          HAS_JREL,   //SETUP_FINALLY
          0, 
          HAS_LOCAL | HAS_READ,   //LOAD_FAST
          HAS_LOCAL | HAS_WRITE,  //STORE_FAST
          HAS_LOCAL,              //DELETE_FAST
          0,
/*128*/   0, 
          0, 
          HAS_IMM,   //RAISE_VARARGS
          HAS_CALL | HAS_IMM,    //CALL_FUNCTION
          HAS_IMM,   //MAKE_FUNCTION
          HAS_IMM,   //BUILD_SLICE 
          HAS_IMM,   //MAKE_CLOSURE 
          HAS_FREE | HAS_READ,   //LOAD_CLOSURE
          HAS_FREE | HAS_READ,   //LOAD_DEREF
          HAS_FREE | HAS_WRITE,  //STORE_DEREF
          0, 
          0, 
          HAS_CALL,  //CALL_FUNCTION_VAR
          HAS_CALL,  //CALL_FUNCTION_KW
          HAS_CALL,  //CALL_FUNCTION_VAR_KW
          0,  //EXTENDED_ARG
/*144*/   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//----------------------------------------------------------------------
int idaapi py_ana(void) {
   cmd.itype = ua_next_byte();    //opcodes ARE itypes for us (updates cmd.size)
   if (cmd.itype >= PYTHON_LAST) return 0;             //invalid instruction
   if (Instructions[cmd.itype].name == NULL) return 0; //invalid instruction
   if (cmd.itype < HAVE_ARGUMENT) { //no operands
      cmd.Op1.type = o_void;      //Op1 is a macro for Operand[0] (see ua.hpp)
      cmd.Op1.dtyp = dt_void;
   }
   else {   //instruction must have two bytes worth of operand data
      if (flags[cmd.itype] & (HAS_JREL | HAS_JABS)) {
         cmd.Op1.type = o_near;  //operand refers to a code location
      }
      else {
         cmd.Op1.type = o_mem;   //operand refers to memory (sort of)
      }
      cmd.Op1.offb = 1;          //operand offset is 1 byte into instruction
      cmd.Op1.dtyp = dt_dword;   //No sizes in python so we just pick something

      cmd.Op1.value = ua_next_word(); //fetch the operand word (updates cmd.size)
      cmd.auxpref = cmd.Op1.reg = flags[cmd.itype]; //save flags for later stages

      if (flags[cmd.itype] & HAS_JREL) {
         //compute relative jump target
         cmd.Op1.addr = cmd.ea + cmd.size + cmd.Op1.value;
      }
      else if (flags[cmd.itype] & HAS_JABS) {
         cmd.Op1.addr = cmd.Op1.value;  //save absolute address
      }
      else if (flags[cmd.itype] & HAS_CALL) {
         //target of call is on the stack in Python, the operand indicates
         //how many arguments are on the stack, save these for later stages
         cmd.Op1.specflag1 = cmd.Op1.value & 0xFF;         //positional parms
         cmd.Op1.specflag2 = (cmd.Op1.value >> 8) & 0xFF;  //keyword parms
      }
   }
   return cmd.size;
}
