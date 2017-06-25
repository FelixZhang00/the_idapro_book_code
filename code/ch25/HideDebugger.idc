/*
    The IDA Pro Book - Example 25-2
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

/*
 * A script to perform some simple debugger hiding tricks
 * Use this script to launch your Windows process.  The script
 * stops execution at the process entry point and resets some
 * flags within the PEB that can be used to detect the presence
 * of a debugger.
 */

#include <idc.idc>

//handle a return from NtQueryInformationProcess
#define ProcessDebugPort 7
static bpt_NtQueryInformationProcess() {
   auto p_ret;
   if (Dword(ESP + 8) == ProcessDebugPort) {//test ProcessInformationClass
      p_ret = Dword(ESP + 12);
      if (p_ret) {
         PatchDword(p_ret, 0);  //fake no debugger present
      }
   }
}

#define ThreadHideFromDebugger 0x11
static bpt_NtSetInformationThread() {
   if (Dword(ESP + 8) == ThreadHideFromDebugger) { //test ThreadInformationClass
      EAX = 0;                                      //STATUS_SUCCESS
      EIP = GetFunctionAttr(EIP, FUNCATTR_END) - 3; //jump to end of function
   }
}

static main() {
   auto globalFlags, func, end;
   RunTo(BeginEA());
   GetDebuggerEvent(WFNE_SUSP, -1);
   //ebx points to peb on entry.  This is only true at BeginEA, not main
   PatchByte(EBX + 2, 0);           //PEB!IsDebugged = 0;
   //no need to mess with IsDebuggerPresent anymore
   //now reset some heap flags in the PEB!NtGlobalFlags field
   globalFlags = Dword(EBX + 0x68) & ~0x70;
   PatchDword(EBX + 0x68, globalFlags);

//   func = LocByName("ntdll_NtQueryInformationProcess");
   func = LocByName("ntdll_ZwQueryInformationProcess");
   MakeFunction(func, BADADDR);
   end = GetFunctionAttr(func, FUNCATTR_END) - 3;
   AddBpt(end);
   SetBptAttr(end, BPT_BRK, 0);  //don't stop
   SetBptCnd(end, "bpt_NtQueryInformationProcess()");

//   func = LocByName("ntdll_NtSetInformationThread");
   func = LocByName("ntdll_ZwSetInformationThread");
   AddBpt(func);                  //break at function entry
   MakeFunction(func, BADADDR);
   SetBptAttr(func, BPT_BRK, 0);  //don't stop
   SetBptCnd(func, "bpt_NtSetInformationThread()");

   func = LocByName("kernel32_OutputDebugStringA");
   MakeFunction(func, BADADDR);
   end = GetFunctionAttr(func, FUNCATTR_END) - 3;
   AddBpt(end);
   SetBptAttr(end, BPT_BRK, 0);  //don't stop
   //fix the return value as expected in non-debugged processes
   SetBptCnd(end, "EAX = 1");

}
