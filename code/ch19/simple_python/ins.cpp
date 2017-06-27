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
#include <idp.hpp>
#include "ins.hpp"

instruc_t Instructions[] = {
   {"STOP_CODE", CF_STOP},   /* 0 */
   {"POP_TOP", 0},           /* 1 */
   {"ROT_TWO", 0},           /* 2 */
   {"ROT_THREE", 0},         /* 3 */
   {"DUP_TOP", 0},           /* 4 */
   {"ROT_FOUR", 0},          /* 5 */
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {"NOP", 0},               /* 9 */
   {"UNARY_POSITIVE", 0},    /* 10 */
   {"UNARY_NEGATIVE", 0},    /* 11 */
   {"UNARY_NOT", 0},         /* 12 */
   {"UNARY_CONVERT", 0},     /* 13 */
   {NULL, 0},                
   {"UNARY_INVERT", 0},      /* 15 */
   {NULL, 0},                
   {NULL, 0},
   {"LIST_APPEND", 0},  /* 18 */
   {"BINARY_POWER", 0}, /* 19 */
   {"BINARY_MULTIPLY", 0},  /* 20 */
   {"BINARY_DIVIDE", 0},    /* 21 */
   {"BINARY_MODULO", 0},    /* 22 */
   {"BINARY_ADD", 0},       /* 23 */
   {"BINARY_SUBTRACT", 0},  /* 24 */
   {"BINARY_SUBSCR", 0},    /* 25 */
   {"BINARY_FLOOR_DIVIDE", 0},  /* 26 */
   {"BINARY_TRUE_DIVIDE", 0},   /* 27 */
   {"INPLACE_FLOOR_DIVIDE", 0}, /* 28 */
   {"INPLACE_TRUE_DIVIDE", 0},  /* 29 */
   {"SLICE", 0},    /* 30 */
   {"SLICE+1", 0},  /* 31 */
   {"SLICE+2", 0},  /* 32 */
   {"SLICE+3", 0},  /* 33 */
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {"STORE_SLICE", 0},   /* 40 */
   {"STORE_SLICE+1", 0}, /* 41 */
   {"STORE_SLICE+2", 0}, /* 42 */
   {"STORE_SLICE+3", 0}, /* 43 */
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {"DELETE_SLICE", 0},   /* 50 */
   {"DELETE_SLICE+1", 0}, /* 51 */
   {"DELETE_SLICE+2", 0}, /* 52 */
   {"DELETE_SLICE+3", 0}, /* 53 */
   {NULL, 0},
   {"INPLACE_ADD", 0},      /* 55 */
   {"INPLACE_SUBTRACT", 0}, /* 56 */
   {"INPLACE_MULTIPLY", 0}, /* 57 */
   {"INPLACE_DIVIDE", 0},   /* 58 */
   {"INPLACE_MODULO", 0},   /* 59 */
   {"STORE_SUBSCR", 0},     /* 60 */
   {"DELETE_SUBSCR", 0},    /* 61 */
   {"BINARY_LSHIFT", CF_SHFT},  /* 62 */
   {"BINARY_RSHIFT", CF_SHFT},  /* 63 */
   {"BINARY_AND", 0},     /* 64 */
   {"BINARY_XOR", 0},     /* 65 */
   {"BINARY_OR", 0},      /* 66 */
   {"INPLACE_POWER", 0},  /* 67 */
   {"GET_ITER", 0},       /* 68 */
   {NULL, 0},
   {"PRINT_EXPR", 0},    /* 70 */
   {"PRINT_ITEM", 0},    /* 71 */
   {"PRINT_NEWLINE", 0}, /* 72 */
   {"PRINT_ITEM_TO", 0}, /* 73 */
   {"PRINT_NEWLINE_TO", 0}, /* 74 */
   {"INPLACE_LSHIFT", CF_SHFT},   /* 75 */
   {"INPLACE_RSHIFT", CF_SHFT},   /* 76 */
   {"INPLACE_AND", 0},      /* 77 */
   {"INPLACE_XOR", 0},      /* 78 */
   {"INPLACE_OR", 0},       /* 79 */
   {"BREAK_LOOP", CF_STOP},       /* 80 */
   {NULL, 0},
   {"LOAD_LOCALS", 0},  /* 82 */
   {"RETURN_VALUE", CF_STOP}, /* 83 */
   {"IMPORT_STAR", 0},  /* 84 */
   {"EXEC_STMT", 0},    /* 85 */
   {"YIELD_VALUE", 0},  /* 86 */
   {"POP_BLOCK", 0},    /* 87 */
   {"END_FINALLY", 0},  /* 88 */
   {"BUILD_CLASS", 0},  /* 89 */
   {"STORE_NAME", CF_CHG1},      /* 90 */
   {"DELETE_NAME", 0},     /* 91 */
   {"UNPACK_SEQUENCE", 0}, /* 92 */
   {"FOR_ITER", 0},        /* 93 */
   {NULL, 0},
   {"STORE_ATTR", CF_CHG1},     /* 95 */
   {"DELETE_ATTR", 0},    /* 96 */
   {"STORE_GLOBAL", CF_CHG1},   /* 97 */
   {"DELETE_GLOBAL", 0},  /* 98 */
   {"DUP_TOPX", 0},       /* 99 */
   {"LOAD_CONST", CF_USE1},     /* 100 */
   {"LOAD_NAME", CF_USE1},      /* 101 */
   {"BUILD_TUPLE", 0},    /* 102 */
   {"BUILD_LIST", 0},     /* 103 */
   {"BUILD_MAP", 0},      /* 104 */
   {"LOAD_ATTR", CF_USE1},      /* 105 */
   {"COMPARE_OP", 0},     /* 106 */
   {"IMPORT_NAME", 0},    /* 107 */
   {"IMPORT_FROM", CF_USE1},    /* 108 */
   {NULL, 0},
   {"JUMP_FORWARD", CF_STOP},    /* 110 */
   {"JUMP_IF_FALSE", 0},   /* 111 */
   {"JUMP_IF_TRUE", 0},    /* 112 */
   {"JUMP_ABSOLUTE", CF_STOP},   /* 113 */
   {NULL, 0},
   {NULL, 0},
   {"LOAD_GLOBAL", CF_USE1}, /* 116 */
   {NULL, 0},
   {NULL, 0},
   {"CONTINUE_LOOP", CF_STOP | CF_USE1},  /* 119 */
   {"SETUP_LOOP", 0},     /* 120 */
   {"SETUP_EXCEPT", 0},   /* 121 */
   {"SETUP_FINALLY", 0},  /* 122 */
   {NULL, 0},
   {"LOAD_FAST", 0},    /* 124 */
   {"STORE_FAST", CF_CHG1},   /* 125 */
   {"DELETE_FAST", 0},  /* 126 */
   {NULL, 0},
   {NULL, 0},
   {NULL, 0},
   {"RAISE_VARARGS", CF_STOP}, /* 130 */
   {"CALL_FUNCTION", CF_CALL},  /* 131 */
   {"MAKE_FUNCTION", 0},  /* 132 */
   {"BUILD_SLICE", 0},    /* 133 */
   {"MAKE_CLOSURE", 0},  /* 134 */
   {"LOAD_CLOSURE", 0},  /* 135 */
   {"LOAD_DEREF", CF_USE1},    /* 136 */
   {"STORE_DEREF", CF_CHG1},   /* 137 */
   {NULL, 0},
   {NULL, 0},
   {"CALL_FUNCTION_VAR", CF_CALL},    /* 140 */
   {"CALL_FUNCTION_KW", CF_CALL},     /* 141 */
   {"CALL_FUNCTION_VAR_KW", CF_CALL}, /* 142 */
   {"EXTENDED_ARG", 0} /* 143 */
};
