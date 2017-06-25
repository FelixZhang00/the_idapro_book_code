/*
   Source for ida_patcher
   Copyright (c) 2006 Chris Eagle cseagle at gmail.com
      
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

/*
 * This program reads an Ida Pro generated .dif file and applies
 * the differences to the original binary to create a patched binary
 * The program will infer the name of the binary from the content of 
 * the dif file, or take the name as a command line option.
 * CAUTION: The program transforms the input binary so if you wish
 * to preserve the original binary make sure you make a copy and
 * transform the copy.
 */

#include <stdio.h>

int main(int argc, char **argv) {
   char line[256];
   FILE *patch = stdin;
   FILE *input = NULL;
   unsigned int offset;
   int orig;
   int newval;
  
   int i;
  
   for (i = 1; i < argc; i += 2) {
      if (!strcmp(argv[i], "-p")) {
         if ((i + 1) < argc) {
            FILE *f = fopen(argv[i+1], "r");
            if (f) {
               patch = f;
            }
            else {
               fprintf(stderr, "Failed to open patch file %s\n", argv[i+1]);
               exit(0);
            }
         }
      }
      else if (!strcmp(argv[i], "-i")) {
         if ((i + 1) < argc) {
         	fprintf(stderr, "Opening %s\n", argv[i+1]);
            input = fopen(argv[i+1], "rb+");
            if (input == NULL) {
               fprintf(stderr, "Failed to open input file %s\n", argv[i+1]);
               exit(0);
            }
         }
      }
      else {
         fprintf(stderr, "usage:\n\t%s [-i <binary>] [-p <dif file>]\n", argv[0]);
         fprintf(stderr, "\t%s [-p <dif file>]\n", argv[0]);
         fprintf(stderr, "\t%s [-i <binary>] < <dif file>\n", argv[0]);
         fprintf(stderr, "\t%s < <dif file>\n", argv[0]);
         exit(0);
      }
   }

   if (patch == stdin) {
      fprintf(stderr, "Reading patch data from stdin.\n");
   }
   fgets(line, sizeof(line), patch); /* eat dif file intro line */
   fgets(line, sizeof(line), patch); /* eat blank line */
   
   if (input == NULL) {
      fprintf(stderr, "Inferring input file name from patch file data.\n");
	   fscanf(patch, "%256s", line);
      input = fopen(line, "rb+");
      if (input == NULL) {
         fprintf(stderr, "Failed to open input file %s\n", line);
         exit(0);
      }
   }
   else { /* don't need input file name, but need to skip it in dif file */
	   fgets(line, sizeof(line), patch);
	}

   while (fscanf(patch, "%x: %x %x", &offset, &orig, &newval) == 3) {
      fseek(input, offset, SEEK_SET);
      if (fgetc(input) == orig) {
	      fseek(input, offset, SEEK_SET);
	      fputc(newval, input);
      }
      else {
         //original bytes don't match expected?
      }
   }
   fclose(input);
   if (patch != stdin) {
      fclose(patch);
   }
}
