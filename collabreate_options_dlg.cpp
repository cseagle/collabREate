/*
    Collabreate GUI and communications layer
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>
    Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>


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

#include <windows.h>
#include "collabreate.h"
#include "buffer.h"
#include "resource.h"

#include <ida.hpp>
#include <kernwin.hpp>

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
#include "ms_stdint.h"
#endif
#else
#include <stdint.h>
#endif

extern HMODULE hModule;

#define COLLAB_SUB_ALL 1000
#define COLLAB_SUB_ONLY 1001
#define COLLAB_OK 1002
#define COLLAB_CANCEL 1003
#define COLLAB_CB_BASE 2000

static Options *optsIn, *optsOut, *optsMask;
static int numOpts;

/*
 * This function is used strictly for debugging the contents
 * of a dialog template array
 */
void hexDump(const unsigned char *buf, int blen) {
   int offset = 0;
   int len = 0;
   int total = 0;
   char ascii[32];
   ascii[16] = 0;
   char hex[50] = "";
   while (total < blen) {
      unsigned char val = buf[total++];
      qsnprintf(hex + len * 3, 4, "%02x ", val);
      if (val >= 0x20 && val <= 0x7e) {
         ascii[len] = (char)val;
      }
      else {
         ascii[len] = '.';
      }
      len++;
      if (len == 16) {
#ifdef DEBUG
         msg(PLUGIN_NAME": %08x:    %-52s%s\n", offset, hex, ascii);
#endif
         offset += 16;
         len = 0;
      }
   }
   if (len != 0) {
      ascii[len] = 0;
      hex[len * 3] = 0;
#ifdef DEBUG
      msg(PLUGIN_NAME": %08x:    %-52s%s\n", offset, hex, ascii);
#endif
   }
}

/*
 * This function is used to pad buffer to dword lengths
 * which is required when building a dialog template
 */
void padBuffer(Buffer &b) {
    int sz = b.size() & 3;
    while (sz & 3) {
      b.write(0);
      sz++;
   }
}

//message handler for the project options dialog
BOOL CALLBACK OptionsDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         //need to set initial checkbox states
#ifdef DEBUG
         msg(PLUGIN_NAME": init dialog\n");
#endif
         uint64_t bit = 1;
         for (int i = 0; i < numOpts; i++) {
            if (IsWindowEnabled(GetDlgItem(hwndDlg, COLLAB_CB_BASE + i * 2))) {
               if (optsIn->pub.ll & bit) {
                 CheckDlgButton(hwndDlg, COLLAB_CB_BASE + i * 2, BST_CHECKED);
               }
            }
            if (IsWindowEnabled(GetDlgItem(hwndDlg, COLLAB_CB_BASE + i * 2 + 1))) {
               if (optsIn->sub.ll & bit) {
                 CheckDlgButton(hwndDlg, COLLAB_CB_BASE + i * 2 + 1, BST_CHECKED);
               }
            }
            bit <<= 1;
         }
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               //need to collect final checkbox states
               uint64_t bit = 1;
               for (int i = 0; i < numOpts; i++) {
                  if (IsDlgButtonChecked(hwndDlg, COLLAB_CB_BASE + i * 2) == BST_CHECKED) {
                     optsOut->pub.ll |= bit;
                  }
                  else {
                     optsOut->pub.ll &= ~bit;
                  }
                  if (IsDlgButtonChecked(hwndDlg, COLLAB_CB_BASE + i * 2 + 1) == BST_CHECKED) {
                     optsOut->sub.ll |= bit;
                  }
                  else {
                     optsOut->sub.ll &= ~bit;
                  }
                  bit <<= 1;
               }
               EndDialog(hwndDlg, 1);
               return TRUE;
            }
            case IDCANCEL: //Cancel Button
               EndDialog(hwndDlg, 0);
               return TRUE;
            case COLLAB_SUB_ALL: {//Subscribe all button
#ifdef DEBUG
               msg(PLUGIN_NAME": sub all pressed\n");
#endif
               for (int i = 0; i < numOpts; i++) {
                  if (IsWindowEnabled(GetDlgItem(hwndDlg, COLLAB_CB_BASE + i * 2 + 1))) {
                     CheckDlgButton(hwndDlg, COLLAB_CB_BASE + i * 2 + 1, BST_CHECKED);
                  }
               }
               return TRUE;
            }
            case COLLAB_SUB_ONLY: //Subscribe only button
#ifdef DEBUG
               msg(PLUGIN_NAME": sub only pressed\n");
#endif
               for (int i = 0; i < numOpts; i++) {
                  CheckDlgButton(hwndDlg, COLLAB_CB_BASE + i * 2, BST_UNCHECKED);
               }
               return TRUE;
         }
         break;
   }
   return FALSE;
}

static unsigned short BUTTON_CLASS[] = {0xFFFF, 0x0080};
static unsigned short STATIC_CLASS[] = {0xFFFF, 0x0082};

#define BORDER 10
#define TEXT_SPACING 2
#define TEXT_TO_BUTTON_SPACING 5
#define BUTTON_SPACING 5
#define CB_SIZE 10
#define CB_SPACE 10

/*
 * The purpose of this function is to layout and display the pub/sub options
 * dialog based on a variable number of input options.  The input option
 * mask dictates which options are enabled by default, while the output mask is
 * used to indicate which options were selected by the user (from the 
 * available options specified by in. Mask determines which options are available.  
 */
void showOptionsDlg(HWND parent, char **optionLabels, int numOptions, Options *in, Options *out, Options *mask) {
   HDC dc = GetDC(parent);
   
   //need to create font used by dialog and select into context
   //so that we can compute text string sizes
   HFONT font = CreateFont(8, 0, 0, 0, FW_NORMAL, false, false, false, 
                    ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
                    DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, 
                    "MS Shell Dlg");
   SelectObject(dc, (HGDIOBJ) font);
   
   SIZE sz;
   
   optsIn = in;
   optsOut = out;
   optsMask = mask;
   numOpts = numOptions;

   char desc[1024];
   int plistExists = 0;
  
   //This is the number of individual items that will be created within the dialog
   //7 represents 3 static stings + 4 push buttons
   //* 3 represents the 3 items per option (option name + 2 checkboxes)
   int numItems = 7 + numOptions * 3;
   int textHeight = 0;
   int textWidth = 0;
   //Row start y coordinate begins after accounting for the border height
   int rowStart = BORDER;
   
   //loop to find the widest/tallest option label
   for (int i = 0; i < numOptions; i++) {
      GetTextExtentPoint32(dc, optionLabels[i], strlen(optionLabels[i]), &sz);
      if (sz.cy > textHeight) {
         textHeight = sz.cy;
      }
      if (sz.cx > textWidth) {
         textWidth = sz.cx;
      }
   }

   //comput the vertical height of the push buttons
   int buttonHeight = textHeight * 2;

   //compute the width of the buttons based on the width of the longest button label
   //the size in the following allows for 2 spaces on either side of the label
   GetTextExtentPoint32(dc, "Subscribe Only", 18, &sz);
   int buttonWidth = sz.cx;
   
   //compute the width and height of the dialog box based on the 
   //sums of the component dimensions and spacing
   short height = 2 * BORDER + (numOptions + 1) * textHeight + (numOptions) * TEXT_SPACING + 
                  TEXT_TO_BUTTON_SPACING + BUTTON_SPACING + buttonHeight * 2;
   short width = 2 * BORDER + textWidth + 2 * CB_SIZE + 2 * CB_SPACE;
   
   //compute width required to accomodate the buttons
   short buttonReqWidth = BORDER * 2 + 2 * buttonWidth + BUTTON_SPACING;
   
   //recompute width if buttons are wider than option labels
   if (width < buttonReqWidth) {
      width = buttonReqWidth;
   }
   
   //compute x offset to the pub checkboxes
   int cbStart = width - BORDER - 2 * CB_SIZE - 2 * CB_SPACE;
   
   //build the dialog template into a Buffer
   Buffer dlgTemplate;
   DLGTEMPLATE temp;
   temp.style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_CENTER | DS_MODALFRAME | WS_CAPTION | DS_SETFONT;
   temp.dwExtendedStyle = 0;
   temp.cdit = numItems;
   temp.x = 0;
   temp.y = 0;
   temp.cx = width;
   temp.cy = height;
   dlgTemplate.write(&temp, sizeof(temp));
   dlgTemplate.writeShort(0);   //no menu
   dlgTemplate.writeShort(0);   //predefined dialog class

   desc[0] = '\0';
   plistExists = GetDlgItemText(parent, IDC_PROJECT_LIST, desc, sizeof(desc));
   //if(GetDlgItemText(parent, IDC_PROJECT_LIST, desc, sizeof(desc)) ) { //GetDlgItem returns #TChar or NULL
   if (strcmp(desc, "<New project>") == 0 || !plistExists) {   //should be for snapshots too...
      dlgTemplate.writeWide("Set Permissions");        //unicode dialog title
   }
   else {
      dlgTemplate.writeWide("Project Join Options");   //unicode dialog title
   }
#ifdef DEBUG
   msg(PLUGIN_NAME": PROJECT LIST is %s , strcmp is: %d \n", desc,strcmp(desc,"<New project>"));
#endif

   dlgTemplate.writeShort(0x0800);   //font size in network byte order
   dlgTemplate.writeWide("MS Shell Dlg");   //unicode font name
   padBuffer(dlgTemplate);
   
   DLGITEMTEMPLATE item, text;
   
   //common values for all static text elements
   //Start with the three static column headers
   text.style = WS_CHILD | WS_VISIBLE | SS_LEFT;
   text.dwExtendedStyle = 0;
   text.x = BORDER;
   text.y = rowStart;
   text.cx = textWidth;
   text.cy = textHeight;
   text.id = 0xFFFF;

   dlgTemplate.write(&text, sizeof(text));
   dlgTemplate.write(STATIC_CLASS, sizeof(STATIC_CLASS)); //item class
   dlgTemplate.writeWide("Options"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   //center the Pub label over the pub checkbox location
   GetTextExtentPoint32(dc, "Pub", 3, &sz);
   text.x = (short)(cbStart + (CB_SIZE - sz.cx) / 2);
   text.cx = (short)(sz.cx);

   dlgTemplate.write(&text, sizeof(text));
   dlgTemplate.write(STATIC_CLASS, sizeof(STATIC_CLASS)); //item class
   dlgTemplate.writeWide("Pub"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   //center the Sub label over the sub checkbox location
   GetTextExtentPoint32(dc, "Sub", 3, &sz);
   text.x = (short)(cbStart + CB_SIZE + CB_SPACE + (CB_SIZE - sz.cx) / 2);
   text.cx = (short)(sz.cx);

   dlgTemplate.write(&text, sizeof(text));
   dlgTemplate.write(STATIC_CLASS, sizeof(STATIC_CLASS)); //item class
   dlgTemplate.writeWide("Sub"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   rowStart += textHeight;
   
   item.style = WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP;  
   item.dwExtendedStyle = 0;
   item.cx = CB_SIZE;
   item.cy = CB_SIZE;

   //print all of the option labels and their checkboxes
   uint64_t bit = 1;
   for (int i = 0; i < numOptions; i++) {
      rowStart += TEXT_SPACING;
      
      text.x = BORDER;
      text.y = rowStart;
      text.cx = textWidth;
   
      dlgTemplate.write(&text, sizeof(text));
      dlgTemplate.write(STATIC_CLASS, sizeof(STATIC_CLASS)); //item class
      dlgTemplate.writeWide(optionLabels[i]); //item text  unicode
      dlgTemplate.writeShort(0);   //class data
      padBuffer(dlgTemplate);

      //test option bits to see if the publish bit is set
      if (optsMask->pub.ll & bit) {
         item.style &= ~WS_DISABLED;
      }
      else {
         item.style |= WS_DISABLED;
      }
      item.x = cbStart;
      item.y = rowStart;
      item.id = COLLAB_CB_BASE + i * 2;
      
      dlgTemplate.write(&item, sizeof(item));
      dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
      dlgTemplate.writeWide(""); //item text  unicode
      dlgTemplate.writeShort(0);   //class data
      padBuffer(dlgTemplate);

      //test option bits to see if the subscribe bit is set
      if (optsMask->sub.ll & bit) {
         item.style &= ~WS_DISABLED;
      }
      else {
         item.style |= WS_DISABLED;
      }
      item.x = cbStart + CB_SIZE + CB_SPACE;
      item.id = COLLAB_CB_BASE + i * 2 + 1;
      
      dlgTemplate.write(&item, sizeof(item));
      dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
      dlgTemplate.writeWide(""); //item text  unicode
      dlgTemplate.writeShort(0);   //class data
      padBuffer(dlgTemplate);

      rowStart += textHeight;
      bit <<= 1;
   }

   rowStart += TEXT_TO_BUTTON_SPACING;

   //layout the 4 pushbuttons
   item.style = WS_CHILD | WS_VISIBLE | BS_CENTER | BS_PUSHBUTTON | WS_TABSTOP;  
   item.x = (width - 2 * buttonWidth - BUTTON_SPACING) / 2;
   item.y = rowStart;
   item.cx = buttonWidth;
   item.cy = buttonHeight;
   item.id = COLLAB_SUB_ALL;
   
   dlgTemplate.write(&item, sizeof(item));
   dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
   dlgTemplate.writeWide("Subscribe All"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   item.x += buttonWidth + BUTTON_SPACING;
   item.id = COLLAB_SUB_ONLY;
   
   dlgTemplate.write(&item, sizeof(item));
   dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
   dlgTemplate.writeWide("Subscribe Only"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   rowStart += buttonHeight + BUTTON_SPACING;

   //must align each item to dword 
   item.style = WS_CHILD | WS_VISIBLE | BS_CENTER | BS_DEFPUSHBUTTON | WS_TABSTOP;  
   item.x = (width - 2 * buttonWidth - BUTTON_SPACING) / 2;
   item.y = rowStart;
   item.id = IDOK;
   
   dlgTemplate.write(&item, sizeof(item));
   dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
   dlgTemplate.writeWide("OK"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

   //must align each item to dword 
   item.style = WS_CHILD | WS_VISIBLE | BS_CENTER | BS_PUSHBUTTON | WS_TABSTOP;  

   item.x += buttonWidth + BUTTON_SPACING;
   item.id = IDCANCEL;
   
   dlgTemplate.write(&item, sizeof(item));
   dlgTemplate.write(BUTTON_CLASS, sizeof(BUTTON_CLASS)); //item class
   dlgTemplate.writeWide("Cancel"); //item text  unicode
   dlgTemplate.writeShort(0);   //class data
   padBuffer(dlgTemplate);

//   hexDump(dlgTemplate.get_buf(), dlgTemplate.size());
   
   //need to point this to "global memory" ??
   HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, dlgTemplate.size());
   DLGTEMPLATE *lpdt = (DLGTEMPLATE*)GlobalLock(hgbl);
   memcpy(lpdt, dlgTemplate.get_buf(), dlgTemplate.size());

   GlobalUnlock(hgbl); 
   int res = DialogBoxIndirect(hModule, (LPDLGTEMPLATE)hgbl, parent, OptionsDlgProc); 
   if (res == 1) {
      //read checkboxes for options
   }
   else if (res == -1) {
      DWORD err = GetLastError();
      msg(PLUGIN_NAME": Options dialog error %d, 0x%x\n", err, err);
   }
   GlobalFree(hgbl);
   ReleaseDC(parent, dc); 
}
