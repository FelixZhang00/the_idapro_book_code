/*
   Copyright (c) 2008 Chris Eagle (cseagle at gmail d0t com)
   
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

#include <stdlib.h>

#pragma pack(1)

struct ch8_struct {
   int field1;
   short field2;
   char field3;
   int field4;
   double field5;
};

int main() {
   struct ch8_struct *heap_struct;
   heap_struct = (struct ch8_struct*)malloc(sizeof(struct ch8_struct));
   heap_struct->field1 = 10;
   heap_struct->field2 = 20;
   heap_struct->field3 = 30;
   heap_struct->field4 = 40;
   heap_struct->field5 = 50.0;   
}
