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

#ifndef __PYTHON_HPP
#define __PYTHON_HPP

#define PLFM_PYTHON 0x31337

#include <pro.h>
#include <kernwin.hpp>
#include "../idaidp.hpp"
#include <fpro.h>
#include "ins.hpp"

#pragma pack(1)

//------------------------------------------------------------------------
enum py_registers { rVcs, rVds };

//------------------------------------------------------------------------
void  idaapi header(void);
void  idaapi footer(void);

void  idaapi segstart(ea_t ea);
void  idaapi segend(ea_t ea);

int   idaapi py_ana(void);
int   idaapi py_emu(void);
void  idaapi py_out(void);
bool  idaapi py_outop(op_t &op);

void  idaapi python_data(ea_t ea);

void  loader(linput_t *li, bool manualload);
ea_t  idaapi get_ref_addr(ea_t ea, const char *str, int pos);

int   cmp_opnd(op_t &op1, op_t &op2);

//opcode flags
//co_consts
#define HAS_CONST    1
//co_names index
#define HAS_NAME     2
#define HAS_JREL     4
//co_varnames index
#define HAS_LOCAL    8
#define HAS_READ     0x10
#define HAS_FREE     0x20
#define HAS_JABS     0x40
#define HAS_WRITE    0x80
#define HAS_CALL     0x100
#define HAS_IMM      0x200
#define HAS_COMPARE  0x400

#pragma pack()
#endif

