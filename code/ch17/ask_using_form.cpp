/*
    The IDA Pro Book - AskUsingForm_c demo plugin
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
 * AskUsingForm_c demo plugin
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>


char *dialog = 
   "STARTITEM 0\n"
   "This is the title\n\n"
   "This is static text\n"
   "<String:A:32:32::>\n"               //need char[MAXSTR]
   "<Decimal:D:10:10::>\n"              //sval_t*
   "<#No leading 0x#Hex:M:8:10::>\n"    //uval_t*
   "<Button:B::::>\n"                   //formcb_t
   "<##Radio Buttons##Radio 1:R>\n"
   "<Radio 2:R>>\n"                     //ushort* number of selected radio
   "<##Check Boxes##Check 1:C>\n"
   "<Check 2:C>>\n";                    //ushort* bitmask of checks
   

//typedef void (idaapi *formcb_t)(TView *fields[],int code); // callback for buttons
void idaapi button_func(TView *fields[], int code) {
   msg("The button was pressed!\n");
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user activates the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//
void idaapi run(int arg) {
   char input[MAXSTR];
   sval_t dec = 0;
   uval_t hex = 0xdeadbeef;
   ushort radio = 1;
   ushort checkmask = 3;
   qstrncpy(input, "initial value", sizeof(input));
   if (AskUsingForm_c(dialog, input, &dec, &hex, button_func, &radio, &checkmask) == 1) {
      msg("The input string was: %s\n", input);
      msg("Decimal: %d, Hex %x\n", dec, hex);
      msg("Radio button %d is selected\n", radio);
      for (int n = 0; checkmask; n++) {
         if (checkmask & 1) {
            msg("Checkbox %d is checked\n", n);
         }
         checkmask >>= 1;
      }
   }
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void) {
   return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
   //nothing to do for our simple plugin
}

//--------------------------------------------------------------------------
char comment[] = "This plugin is an example of using AskUsingForm_c.";

char help[] = "Demo AskUsingForm_c\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "AskUsingForm_c demo";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Ctrl-F7";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
