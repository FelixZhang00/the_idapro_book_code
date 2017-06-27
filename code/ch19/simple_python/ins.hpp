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

#ifndef __INST_H
#define __INST_H

/* Instruction opcodes for compiled code */

enum opcodes {
   STOP_CODE = 0,
   POP_TOP = 1,
   ROT_TWO = 2,
   ROT_THREE = 3,
   DUP_TOP = 4,
   ROT_FOUR = 5,
   NOP = 9,
   
   UNARY_POSITIVE = 10,
   UNARY_NEGATIVE = 11,
   UNARY_NOT = 12,
   UNARY_CONVERT = 13,
   
   UNARY_INVERT = 15,
   
   LIST_APPEND = 18,
   BINARY_POWER = 19,
   
   BINARY_MULTIPLY = 20,
   BINARY_DIVIDE = 21,
   BINARY_MODULO = 22,
   BINARY_ADD = 23,
   BINARY_SUBTRACT = 24,
   BINARY_SUBSCR = 25,
   BINARY_FLOOR_DIVIDE = 26,
   BINARY_TRUE_DIVIDE = 27,
   INPLACE_FLOOR_DIVIDE = 28,
   INPLACE_TRUE_DIVIDE = 29,
   
   SLICE = 30,
   /* Also uses 31-33 */
   
   STORE_SLICE = 40,
   /* Also uses 41-43 */
   
   DELETE_SLICE = 50,
   /* Also uses 51-53 */
   
   INPLACE_ADD = 55,
   INPLACE_SUBTRACT = 56,
   INPLACE_MULTIPLY = 57,
   INPLACE_DIVIDE = 58,
   INPLACE_MODULO = 59,
   STORE_SUBSCR = 60,
   DELETE_SUBSCR = 61,
   
   BINARY_LSHIFT = 62,
   BINARY_RSHIFT = 63,
   BINARY_AND = 64,
   BINARY_XOR = 65,
   BINARY_OR = 66,
   INPLACE_POWER = 67,
   GET_ITER = 68,
   
   PRINT_EXPR = 70,
   PRINT_ITEM = 71,
   PRINT_NEWLINE = 72,
   PRINT_ITEM_TO = 73,
   PRINT_NEWLINE_TO = 74,
   INPLACE_LSHIFT = 75,
   INPLACE_RSHIFT = 76,
   INPLACE_AND = 77,
   INPLACE_XOR = 78,
   INPLACE_OR = 79,
   BREAK_LOOP = 80,
   
   LOAD_LOCALS = 82,
   RETURN_VALUE = 83,
   IMPORT_STAR = 84,
   EXEC_STMT = 85,
   YIELD_VALUE = 86,
   
   POP_BLOCK = 87,
   END_FINALLY = 88,
   BUILD_CLASS = 89,
   
   HAVE_ARGUMENT = 90, 
   /* Opcodes from here have an argument: */
   
   STORE_NAME = 90, /* Index in name list */
   DELETE_NAME = 91, /* "" */
   UNPACK_SEQUENCE = 92, /* Number of sequence items */
   FOR_ITER = 93,
   
   STORE_ATTR = 95, /* Index in name list */
   DELETE_ATTR = 96, /* "" */
   STORE_GLOBAL = 97, /* "" */
   DELETE_GLOBAL = 98, /* "" */
   DUP_TOPX = 99, /* number of items to duplicate */
   LOAD_CONST = 100, /* Index in const list */
   LOAD_NAME = 101, /* Index in name list */
   BUILD_TUPLE = 102, /* Number of tuple items */
   BUILD_LIST = 103, /* Number of list items */
   BUILD_MAP = 104, /* Always zero for now */
   LOAD_ATTR = 105, /* Index in name list */
   COMPARE_OP = 106, /* Comparison operator */
   IMPORT_NAME = 107, /* Index in name list */
   IMPORT_FROM = 108, /* Index in name list */
   
   JUMP_FORWARD = 110, /* Number of bytes to skip */
   JUMP_IF_FALSE = 111, /* "" */
   JUMP_IF_TRUE = 112, /* "" */
   JUMP_ABSOLUTE = 113, /* Target byte offset from beginning of code */
   
   LOAD_GLOBAL = 116, /* Index in name list */
   
   CONTINUE_LOOP = 119, /* Start of loop (absolute) */
   SETUP_LOOP = 120, /* Target address (absolute) */
   SETUP_EXCEPT = 121, /* "" */
   SETUP_FINALLY = 122, /* "" */
   
   LOAD_FAST = 124, /* Local variable number */
   STORE_FAST = 125, /* Local variable number */
   DELETE_FAST = 126, /* Local variable number */
   
   RAISE_VARARGS = 130, /* Number of raise arguments (1, 2 or 3) */
   /* CALL_FUNCTION_XXX opcodes defined below depend on this definition */
   CALL_FUNCTION = 131, /* #args + (#kwargs<<8) */
   MAKE_FUNCTION = 132, /* #defaults */
   BUILD_SLICE = 133, /* Number of items */
   
   MAKE_CLOSURE = 134, /* #free vars */
   LOAD_CLOSURE = 135, /* Load free variable from closure */
   LOAD_DEREF = 136, /* Load and dereference from closure cell */
   STORE_DEREF = 137, /* Store into cell */
   
   /* The next 3 opcodes must be contiguous and satisfy
   (CALL_FUNCTION_VAR - CALL_FUNCTION) & 3 == 1 */
   CALL_FUNCTION_VAR = 140, /* #args + (#kwargs<<8) */
   CALL_FUNCTION_KW = 141, /* #args + (#kwargs<<8) */
   CALL_FUNCTION_VAR_KW = 142, /* #args + (#kwargs<<8) */
   
   /* Support for opargs more than 16 bits long */
   EXTENDED_ARG = 143,
   PYTHON_LAST = 144
};

extern instruc_t Instructions[];

#endif
