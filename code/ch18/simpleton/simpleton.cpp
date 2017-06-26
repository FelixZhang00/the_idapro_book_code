/*
   The IDA Pro Book - Simpleton Loader
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

/* Simpleton loader for Ida Pro Book 
 * This loader loads files in the following format
 * uint32 magic   - magic number 0x1DAB00C (big endian)
 * uint32 size    - size of the text section
 * uint32 base    - base loading address for the text section
 * uint8  bytes[size] - x86 program bytes
 */

#include "../idaldr.h"

#define SIMPLETON_MAGIC 0x1DAB00C

/*
 * define your binary file header structure
 */
struct simpleton {
   uint32_t magic;
   uint32_t size;
   uint32_t base;
};

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_simpleton_file(linput_t *li,
                       char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
   uint32   magic;
   // read as much of the file as you need to to determine whether
   // it is something that you recognize
   if(n || lread4bytes(li, &magic, false)) {  //reads as little endian
      return 0;
   }
   if (magic != SIMPLETON_MAGIC) {
      return 0;
   }
   //if you recognize the file, then say so
   qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "Simpleton Loader");
   return 1;
}

//----------------------------------------------------------------------
//      initialize user configurable options based on the input file.
static bool idaapi init_simpleton_options(linput_t*) {
   //set the processor type
   msg("INIT_SIMPLETON_OPTIONS\n");
   set_processor_type("metapc", SETPROC_ALL|SETPROC_FATAL);
   return true;
}

//--------------------------------------------------------------------------
//
//      load file into the database.
// This is only called if the user chooses our loader as the one to use
static void idaapi load_simpleton_file(linput_t *li, ushort neflags,
                      const char * /*fileformatname*/) {
   //NOTE, if you are using an existing Ida processor module,
   //then all you really need to do is load bytes from the file
   //into the database, create sections, and add entry points
   simpleton hdr;
   //read the program header from the input file
   lread(li, &hdr, sizeof(simpleton));
   //file2base does a seek and read from the input file into the database
   //file2base is prototyped in loader.hpp
   file2base(li, sizeof(simpleton), hdr.base, hdr.base + hdr.size, FILEREG_PATCHABLE);
   //try to add a new code segment to contain the program bytes
   if (!add_segm(0, hdr.base, hdr.base + hdr.size, NAME_CODE, CLASS_CODE)) {
      loader_failure();
   }
   //retrieve a handle to the new segment
   segment_t *s = getseg(hdr.base);
   //so that we can set 32 bit addressing mode on
   set_segm_addressing(s, 1);  //set 32 bit addressing
   //tell IDA to create the file header comment for us.  Do this only once
   create_filename_cmt();
   //Add an entry point so that the processor module knows at least one
   //address that contains code.  This is the root of the recursive descent
   //disassembly process
   add_entry(hdr.base, hdr.base, "_start", true);
}

int idaapi save_simpleton_file(FILE *fp, const char *fileformatname) {
   uint32 magic = SIMPLETON_MAGIC;
   if (fp == NULL) return 1;
   segment_t *s = getnseg(0);
   if (s) {
      uint32 sz = s->endEA - s->startEA;
      qfwrite(fp, &magic, sizeof(uint32));
      qfwrite(fp, &sz, sizeof(uint32));
      qfwrite(fp, &s->startEA, sizeof(uint32));
      base2file(fp, sizeof(simpleton), s->startEA, s->endEA);
      return 1;
   }
   else {
      return 0;
   }
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
  IDP_INTERFACE_VERSION,
  0,                     // loader flags
  accept_simpleton_file, // test simpleton format.
  load_simpleton_file,   // load file into the database.
  save_simpleton_file,   // simpleton is an easy format to save
  NULL,                  // no special handling for moved segments
  NULL                   // no special handling for File->New
};

//----------------------------------------------------------------------
