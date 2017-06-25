/*
   Copyright (c) 2007 Chris Eagle (cseagle at gmail d0t com)
   
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
 * Parameter labeling script for programs compiled with newer versions of gcc
 * which uses mov instructions rather than push to place function arguments on
 * the stack.
 *
 * This script scans a single function and adds comments at each instruction
 * that is used to mov arguments into the stck prior to a function call.  Where
 * possible, the script will indicate the data type and formal parameter name
 * as part of the comment.
 */

#include <idc.idc>

static getArgCount(func) {
   auto type, idx, count;
   type = GetType(func);
   if (type != "") {
      if (strstr(type, "()") != -1) return 0;
      if (strstr(type, "( )") != -1) return 0;
      if (strstr(type, "(void)") != -1) return 0;
      idx = strstr(type, "(");
      if (idx != -1) {
         count = 1;
         while (strstr(type, ",") != -1) {
            idx = strstr(type, ",");
            count++;
            type = substr(type, idx + 1, -1);
         }
         return count;
      }
   }
   return -1;
}

static getArg(func, n, nargs) {
   auto type, idx, count;
   type = GetType(func);
   if (type != "") {
      if (strstr(type, "()") != -1) return "";
      if (strstr(type, "( )") != -1) return "";
      if (strstr(type, "(void)") != -1) return "";
      idx = strstr(type, "(");
      if (idx != -1) {
         count = 1;
         do {
            type = substr(type, idx + 1, -1);
            Message("%d/%d: %s\n", count, nargs, type);
            idx = strstr(type, ",");
            if (count == n) {
               if (idx == -1) {
                  idx = strstr(type, ")");
               }
               return substr(type, 0, idx);
            }
            idx = strstr(type, ",");
            count++;
         } while (count <= nargs);
      }
   }
   return "";
}

static get_arg(ea, n) {
   auto op, tgt, flow, end, nargs;
   end = GetFunctionAttr(ea, FUNCATTR_END);
   while (ea < end && ea != BADADDR) {
      tgt = Rfirst0(ea);
      if (tgt != BADADDR) {
         flow = XrefType();
         if (flow == fl_CF || flow == fl_CN) {
            Message("found call at %x, target is %x\n", ea, tgt);
            nargs = getArgCount(tgt);
            Message("arg count = %d\n", nargs);
            if (nargs == -1) {
               return "";
            }
            if (n <= nargs) {
               return getArg(tgt, n, nargs);
            }
         }
      }
      ea = FindCode(ea, SEARCH_DOWN | SEARCH_NEXT);
   } 
   return "";
}

static main() {
   auto func, ea, comment, op, max, arg, idx;
   auto func_flags, type, val, call_loc;

   func = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
   func_flags = GetFunctionFlags(func);
   if (func_flags & FUNC_FRAME) {
      max = GetFunctionAttr(func, FUNCATTR_END);
      for (ea = func; ea < max && ea != BADADDR; ea = FindCode(ea, SEARCH_DOWN | SEARCH_NEXT)) {
         type = GetOpType(ea, 0);
         if (type == 3) {
            //base + index
            if (GetOperandValue(ea, 0) == 4) {  //esp
               arg = get_arg(ea, 1);
               if (arg != "") {
                  comment = arg;
               }
               else {
                  comment = "arg_0";
               }
               MakeComm(ea, comment);
            }
         }
         else if (type == 4) {
            //base + disp + index
            op = GetOpnd(ea, 0);
            idx = strstr(op, "[esp");
            if (idx != -1) {
               val = GetOperandValue(ea, 0);
               arg = get_arg(ea, val / 4 + 1);
               if (arg != "") {
                  comment = arg;
               }
               else {
                  comment = form("arg_%d", val);
               }
               MakeComm(ea, comment);
            }
         }
      }
   }
}
