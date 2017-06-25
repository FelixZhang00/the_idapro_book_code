/*
   Copyright (c) 2008 Chris Eagle (cseagle at gmail d0t c0m)
   
   Permission is hereby granted, free of charge, to any person obtaining a copy of 
   this software and associated documentation files (the "Software"), to deal in 
   the Software without restriction, including without limitation the rights to 
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
   the Software, and to permit persons to whom the Software is furnished to do so, 
   subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in all 
   copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
   FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
   COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
 * fix_proc is a replacement for the mkidp utility included with the IDA SDK.
 * The intent of this program is to eliminate the need to incorporate 
 * <SDKDIR>/proc/stub into your build process for processor modules.  This program
 * makes no assumption about what compiler you used to build your processor, it
 * simply replaces the MS-DOS stub with the stub supplied with the SDK, moves the
 * PE header as far as possible to create room for the processor description, and
 * writes the processor description string into the processor module.  The last
 * step replaces the functionality of mkidp, while the other steps allow for a wider
 * variety of build environments.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDA_STUB_END 0x80

unsigned char ida_proc_stub[] =
   "\x4D\x5A\x00\x02\x01\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00"
   "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00"
   "\xBA\x10\x00\x0E\x1F\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x90\x90"
   "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x64\x69\x73\x61\x73\x73"
   "\x65\x6D\x62\x6C\x65\x72\x20\x6D\x6F\x64\x75\x6C\x65\x20\x66\x6F"
   "\x72\x20\x49\x44\x41\x24\x00\x00\x20\x50\x4E\x41\x4D\x45\x53\x3A";
IMAGE_DOS_HEADER *ida_dos_stub = (IMAGE_DOS_HEADER*)ida_proc_stub;

void error_exit(FILE *fp, char *msg) {
   fprintf(stderr, "%s", msg);
   fclose(fp);
   exit(0);
}

int main(int argc, char **argv) {
   IMAGE_DOS_HEADER dos;
   IMAGE_NT_HEADERS nt;
   IMAGE_SECTION_HEADER sect;
   int desc_len, space, n;
   unsigned int originalPE, updatedPE;
   unsigned int endSectionHdrs;
   unsigned int firstSection;
   unsigned int delta;
   unsigned int totalPE;
   unsigned char *headers;
   
   FILE *proc;
   if (argc != 3) {
      fprintf(stderr, "usage: fix_proc <plugin module name> <description>\n");
      exit(0);
   }
   proc = fopen(argv[1], "rb+");
   if (proc == NULL) {
      fprintf(stderr, "fix_proc: failed to open input file: %s\n", argv[1]);
      exit(0);
   }
   if (fread(&dos, sizeof(dos), 1, proc) != 1) {
      error_exit(proc, "fix_proc: failed to read IMAGE_DOS_HEADER");
   }
   originalPE = dos.e_lfanew;

   if (fseek(proc, originalPE, SEEK_SET)) {
      error_exit(proc, "fix_proc: failed to seek to PE header");
   }
   if (fread(&nt, sizeof(nt), 1, proc) != 1) {
      error_exit(proc, "fix_proc: failed to read IMAGE_NT_HEADERS");
   }
   for (n = 0; n < nt.FileHeader.NumberOfSections; n++) {
      if (fread(&sect, sizeof(sect), 1, proc) != 1) {
         error_exit(proc, "fix_proc: failed to read IMAGE_SECTION_HEADER");
      }
      firstSection = sect.PointerToRawData;
      if (firstSection) break;
   }
   if (firstSection == 0) {
      error_exit(proc, "fix_proc: unable to locate first file section");
   }
   endSectionHdrs = originalPE + sizeof(nt) + nt.FileHeader.NumberOfSections * sizeof(sect);

   //compute how far we can move PE header
   delta = firstSection - endSectionHdrs;
   fprintf(stderr, "Moving PE header a total of 0x%x bytes\n", delta);

   //allocate new, empty header block
   headers = (unsigned char *)calloc(firstSection, 1);

   //update ida_dos_stub to point to new PE header location
   updatedPE = originalPE + delta;
   ida_dos_stub->e_lfanew = updatedPE;
   
   //copy updated dos stub into new header block
   memcpy(headers, ida_dos_stub, IDA_STUB_END);

   //length of processor description string
   desc_len = strlen(argv[2]);
   
   //compute available space mkidp requires at least 20 zeroes following
   //null terminator of description string (not sure why).
   space = updatedPE - IDA_STUB_END - 21;
   
   if (desc_len > space) {
      error_exit(proc, "fix_proc: not enough space to write description");
   }

   //copy description string into new header block following dos stub
   memcpy(headers + IDA_STUB_END, argv[2], desc_len);

   //prepare to read original PE headers
   fseek(proc, originalPE, SEEK_SET);
   
   //compute original PE headers size
   totalPE = endSectionHdrs - originalPE;

   //read original PE header into new location within header block
   if (fread(headers + updatedPE, 1, totalPE, proc) != totalPE) {
      error_exit(proc, "fix_proc: failed to read pe data\n");
   }
   
   //rewrite new header block to original file
   fseek(proc, 0, SEEK_SET);
   if (fwrite(headers, 1, firstSection, proc) != firstSection) {
      error_exit(proc, "fix_proc: failed to write new headers\n");
   }
   fprintf(stderr, "fix_proc: success\n");
      
   fclose(proc);
   free(headers);
   return 0;
}
