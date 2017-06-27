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

#include <ida.hpp>
#include <frame.hpp>
#include "python.hpp"

short stack_delta[256] = {
   0, // STOP_CODE
   1, // POP_TOP
   0, // ROT_TWO
   0, // ROT_THREE
   -1, // DUP_TOP
   0, // ROT_FOUR
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, // NOP
   0, // UNARY_POSITIVE
   0, // UNARY_NEGATIVE
   0, // UNARY_NOT
   0, // UNARY_CONVERT
   0, //  NULL
   0, // UNARY_INVERT
   0, //  NULL
   0, //  NULL
   2, // LIST_APPEND
   1, // BINARY_POWER
   1, // BINARY_MULTIPLY
   1, // BINARY_DIVIDE
   1, // BINARY_MODULO
   1, // BINARY_ADD
   1, // BINARY_SUBTRACT
   1, // BINARY_SUBSCR
   1, // BINARY_FLOOR_DIVIDE
   1, // BINARY_TRUE_DIVIDE
   1, // INPLACE_FLOOR_DIVIDE
   1, // INPLACE_TRUE_DIVIDE
   0, // SLICE
   1, // SLICE+1
   1, // SLICE+2
   2, // SLICE+3
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   2, // STORE_SLICE
   3, // STORE_SLICE+1
   3, // STORE_SLICE+2
   4, // STORE_SLICE+3
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   0, //  NULL
   1, // DELETE_SLICE
   2, // DELETE_SLICE+1
   2, // DELETE_SLICE+2
   3, // DELETE_SLICE+3
   0, //  NULL
   1, // INPLACE_ADD
   1, // INPLACE_SUBTRACT
   1, // INPLACE_MULTIPLY
   1, // INPLACE_DIVIDE
   1, // INPLACE_MODULO
   3, // STORE_SUBSCR
   2, // DELETE_SUBSCR
   1, // BINARY_LSHIFT
   1, // BINARY_RSHIFT
   1, // BINARY_AND
   1, // BINARY_XOR
   1, // BINARY_OR
   1, // INPLACE_POWER
   0, // GET_ITER
   0, //  NULL
   1, // PRINT_EXPR
   1, // PRINT_ITEM
   0, // PRINT_NEWLINE
   2, // PRINT_ITEM_TO
   1, // PRINT_NEWLINE_TO
   1, // INPLACE_LSHIFT
   1, // INPLACE_RSHIFT
   1, // INPLACE_AND
   1, // INPLACE_XOR
   1, // INPLACE_OR
   0, // BREAK_LOOP
   0, //  NULL
   -1, // LOAD_LOCALS
   1, // RETURN_VALUE
   1, // IMPORT_STAR
   3, // EXEC_STMT
   1, // YIELD_VALUE
   0, // POP_BLOCK
   0, // END_FINALLY
   2, // BUILD_CLASS
   1, // STORE_NAME
   0, // DELETE_NAME
   128, // UNPACK_SEQUENCE
   -1, // FOR_ITER
   0, //  NULL
   2, // STORE_ATTR
   1, // DELETE_ATTR
   0, // STORE_GLOBAL
   0, // DELETE_GLOBAL
   128, // DUP_TOPX
   -1, // LOAD_CONST
   -1, // LOAD_NAME
   128, // BUILD_TUPLE
   128, // BUILD_LIST
   -1, // BUILD_MAP
   0, // LOAD_ATTR
   1, // COMPARE_OP
   -1, // IMPORT_NAME
   0, // IMPORT_FROM
   0, //  NULL
   0, // JUMP_FORWARD
   0, // JUMP_IF_FALSE
   0, // JUMP_IF_TRUE
   0, // JUMP_ABSOLUTE
   0, //  NULL
   0, //  NULL
   -1, // LOAD_GLOBAL
   0, //  NULL
   0, //  NULL
   0, // CONTINUE_LOOP
   0, // SETUP_LOOP
   0, // SETUP_EXCEPT
   0, // SETUP_FINALLY
   0, //  NULL
   -1, // LOAD_FAST
   1, // STORE_FAST
   0, // DELETE_FAST
   0, //  NULL
   0, //  NULL
   0, //  NULL
   128, // RAISE_VARARGS
   128, // CALL_FUNCTION
   -1, // MAKE_FUNCTION
   128, // BUILD_SLICE
   128, // MAKE_CLOSURE
   -1, // LOAD_CLOSURE
   -1, // LOAD_DEREF
   1, // STORE_DEREF
   0, //  NULL
   0, //  NULL
   128, // CALL_FUNCTION_VAR
   128, // CALL_FUNCTION_KW
   128, // CALL_FUNCTION_VAR_KW
   0 // EXTENDED_ARG
};

//----------------------------------------------------------------------
int idaapi py_emu(void) {
   //We can only resolve target addresses for relative jumps
   if (cmd.auxpref & HAS_JREL) {
      ua_add_cref(cmd.Op1.offb, cmd.Op1.addr, fl_JN);
   }
   //Add the sequential flow as long as CF_STOP is not set
   if((cmd.get_canon_feature() & CF_STOP) == 0) {
      //cmd.ea + cmd.size computes the address of the next instruction
      ua_add_cref(0, cmd.ea + cmd.size, fl_F);
   }   
   return 1;
}

