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

#ifdef _WIN32
#ifndef _MSC_VER
#include <windows.h>
#endif
#include <winsock2.h>
#endif

#include "resource.h"

#include "sdk_versions.h"
#if IDA_SDK_VERSION < 550
#include "idanet.hpp"
#else
#include "idanet.hpp"
#endif
#include "collabreate.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <md5.h>
#include <netnode.hpp>
#include <time.h>

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
#include "ms_stdint.h"
#endif
#else
#include <stdint.h>
#endif

#include "buffer.h"

#if IDA_SDK_VERSION < 500
#include <fpro.h>
#endif

#define SOCKET_MSG WM_USER

HWND mainWindow;
HMODULE hModule;

void showOptionsDlg(HWND parent, char **optionLabels, int numOptions, Options *in, Options *out, Options *mask);

static Dispatcher tempDispatcher;
//global pointer to the incoming project list buffer.  Used to fill
//the project list dialog
static Buffer *projectBuffer;

//message handler for the server connection dialog
BOOL CALLBACK ConnectDlgProc(HWND hwndDlg, UINT message, 
                             WPARAM wParam, LPARAM lParam) { 
   char host[128];
   char sport[16];
   int port;
   switch (message) { 
      case WM_INITDIALOG: {
         port = (int)cnn.altval(LAST_PORT_ALTVAL);
         if (port == 0) {
            port = 5042;
         }
         
         host[0] = 0;
         cnn.supstr(LAST_SERVER_SUPVAL, host, sizeof(host));

         qsnprintf(sport, sizeof(sport), "%d", port);
         SetDlgItemText(hwndDlg, IDC_SERVER, host);
         SetDlgItemText(hwndDlg, IDC_PORT, sport);
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDOK: {//OK Button 
            GetDlgItemText(hwndDlg, IDC_SERVER, host, sizeof(host));
            GetDlgItemText(hwndDlg, IDC_PORT, sport, sizeof(sport));
            port = atoi(sport);

            cnn.altset(LAST_PORT_ALTVAL, port);
            cnn.supset(LAST_SERVER_SUPVAL, host);

            //connect to the server.
#if IDA_SDK_VERSION < 550 
            _SOCKET conn = connect_to(host, port);
            if (conn == INVALID_SOCKET) {
               EndDialog(hwndDlg, 0);
            }            
            else if (createSocketWindow(conn, tempDispatcher)) {
               msg(PLUGIN_NAME": successfully connected to %s:%d\n", host, port);
               EndDialog(hwndDlg, 1);
            }
            else {
               closesocket(conn);
               EndDialog(hwndDlg, 0);
            }
#else
            if (connect_to(host, port, tempDispatcher)) {
               msg(PLUGIN_NAME": successfully connected to %s:%d\n", host, port);
               EndDialog(hwndDlg, 1);
            }
            else {
               EndDialog(hwndDlg, 0);
            }
#endif
            return TRUE; 
         }
         case IDCANCEL: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

//message handler for the client authentication dialog
BOOL CALLBACK AuthDlgProc(HWND hwndDlg, UINT message,
                          WPARAM wParam, LPARAM lParam) {
   char username[64];
   switch (message) {
      case WM_INITDIALOG: {
         username[0] = 0;
         cnn.supstr(LAST_USER_SUPVAL, username, sizeof(username));
         SetDlgItemText(hwndDlg, IDC_USERNAME, username);
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
         case IDOK: {//OK Button
            char password[64];
            GetDlgItemText(hwndDlg, IDC_USERNAME, username, sizeof(username));
            GetDlgItemText(hwndDlg, IDC_PASSWORD, password, sizeof(password));

            saveAuthData(username, password);
            
            memset(password, 0, sizeof(password));

            EndDialog(hwndDlg, 1);
            return TRUE;
         }
         case IDCANCEL: //Cancel Button
            EndDialog(hwndDlg, 0);
            return TRUE;
         }
   }
   return FALSE;
}

//The global projectBuffer pointer should be initialized to point to 
//the incoming buffer that contains the project list to be displayed in
//the project list dialog PRIOR to calling DialogBox
BOOL CALLBACK ProjectDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         int numProjects = projectBuffer->readInt();
         numProjectsGlobal = numProjects;
         
         projects = (int*)qalloc(numProjects * sizeof(int));
         snapUpdateIDs = (uint64_t*)qalloc(numProjects * sizeof(uint64_t));
         optMasks = (Options*)qalloc(numProjects * sizeof(Options));
         
         SetDlgItemText(hwndDlg, IDC_PROJECT_LIST, "");
         SetDlgItemText(hwndDlg, IDC_DESCRIPTION, "");
         //the New project is always listed as the first option
         SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_ADDSTRING, (WPARAM)0, (LPARAM)"<New project>");
         for (int i = 0; i < numProjects; i++) {
            projects[i] = projectBuffer->readInt();
            snapUpdateIDs[i] = projectBuffer->readLong();
            //if (snapUpdateIDs[i] > 0 ) {
            //   msg(PLUGIN_NAME": project %d is a snapshot\n", i + 1);
            //}
            char *desc = projectBuffer->readUTF8();
            int isSnapShot = 0;
            if ( snapUpdateIDs[i] !=0 ) {
               isSnapShot = 1;
            }
#ifdef DEBUG
            msg(PLUGIN_NAME": %d : %d - %s (%d) ", i, projects[i], desc, isSnapShot);
#endif
            SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_ADDSTRING, (WPARAM)0, (LPARAM)desc);
            qfree(desc);
            
            //need to read options mask for this project
            //but for now everything is enabled
            //memset(optMasks + i, 0xFF, sizeof(Options));
            optMasks[i].pub.ll = projectBuffer->readLong();
            optMasks[i].sub.ll = projectBuffer->readLong();
#ifdef DEBUG
            msg(PLUGIN_NAME": P %x  S %x \n", optMasks[i].pub.ii[0], optMasks[i].sub.ii[0]);
#endif
         }
         int numOptions = projectBuffer->readInt();
         numOptionsGlobal = numOptions;

         optLabels = (char**)qalloc(numOptions * sizeof(char*));
         for (int i = 0; i < numOptions; i++) {
            optLabels[i] = projectBuffer->readUTF8();
         }

         CheckDlgButton(hwndDlg, IDC_PUBLISH, BST_CHECKED);
         CheckDlgButton(hwndDlg, IDC_SUBSCRIBE, BST_CHECKED);
         return TRUE;
      }
      case WM_COMMAND: {
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               char description[1024];
               int selected = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETCURSEL, 0, 0);
               GetDlgItemText(hwndDlg, IDC_DESCRIPTION, description, sizeof(description));
               if (selected == 0) {
                  //new project, make sure that user hasn't tried to name the project using
                  //an existing project name
                  int count = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETCOUNT, 0, 0);
                  for (int n = 1; n < count; n++) {
                     int len = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETLBTEXTLEN, n, 0);
                     if (len != CB_ERR) {
                        char *item = new char[len + 1];
                        SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETLBTEXT, n, (LPARAM)item);
                        char *i = strchr(item, ']');
                        if (i != NULL) {
                           i += 2;
                           if (strcmp(i, description) == 0) {
                              ::MessageBox(hwndDlg, "Project already exists. Join existing project or change name.", "Error", MB_OK | MB_ICONERROR);
                              delete [] item;
                              return FALSE;
                           }
                        }
                        delete [] item;
                     }
                  }
               }
               selected = chooseProject(selected, description);
               EndDialog(hwndDlg, selected);
               return TRUE;
            }
            case IDCANCEL: { //Cancel Button
               EndDialog(hwndDlg, -1);
               return TRUE;
            }
            case IDC_PROJECT_LIST: {
               if (HIWORD(wParam) == CBN_SELCHANGE) {
                  int selected = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETCURSEL, 0, 0);
                  HWND desc = GetDlgItem(hwndDlg, IDC_DESCRIPTION);
                  if (changeProject(selected)) {
                     EnableWindow(desc, TRUE);
                  }
                  else {
                     EnableWindow(desc, FALSE);
                  }
                  return TRUE;
               }
               break;
            }
            case IDC_OPTIONS: {
#ifdef DEBUG
               msg(PLUGIN_NAME": calling showOptionsDlg\n");
#endif
               showOptionsDlg(hwndDlg, optLabels, numOptionsGlobal, &userOpts, &userOpts, &userOpts);
               return TRUE;
            }
         }
      }
   }
   return FALSE;
}

BOOL CALLBACK CommandsDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {   
   switch (message) {
      case WM_INITDIALOG: {
         int i = 0;
         for (const char *cmd = getRunCommand(i); cmd; cmd = getRunCommand(i)) {
            SendDlgItemMessage(hwndDlg, IDC_COMMAND_LIST, LB_ADDSTRING, (WPARAM)0, (LPARAM)cmd);
            i++;
         }
         return TRUE;
      }
      case WM_COMMAND: {
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               int selected = SendDlgItemMessage(hwndDlg, IDC_COMMAND_LIST, LB_GETCURSEL, 0, 0);
               if (selected == LB_ERR) selected = -1;
               EndDialog(hwndDlg, selected);
               return TRUE;
            }
            case IDCANCEL: { //Cancel Button
               EndDialog(hwndDlg, -1);
               return TRUE;
            }
         }
      }
   }
   return FALSE;
}

bool do_project_select(Buffer &b) {
   projects = NULL;
   snapUpdateIDs = NULL;
   projectBuffer = &b;
   bool result = true;
   int index = DialogBox(hModule, MAKEINTRESOURCE(IDD_PROJECT_SELECT), mainWindow, ProjectDlgProc);

   if (index == -1) {
#ifdef DEBUG
      msg(PLUGIN_NAME": project select canceled\n");
#endif
      result = false;
   }
   else {
      selectProject(index);
   }
   freeProjectFields();
   return result;
}

int do_auth(unsigned char *challenge, int challenge_len) {
   int rval = 0;
   if (DialogBox(hModule, MAKEINTRESOURCE(IDD_AUTH), mainWindow, AuthDlgProc) == 1) {
      sendAuthData(challenge, challenge_len);
   }
   else {
      msg(PLUGIN_NAME": authentication canceled.\n");
      rval = 1;
   }         
   return rval;
}

bool do_connect(Dispatcher d) {
   //if we are already connected then do nothing.
   if (is_connected()) return true;

   tempDispatcher = d;
   return DialogBox(hModule, MAKEINTRESOURCE(IDD_CONNECT), mainWindow, ConnectDlgProc) == 1;
}

int do_choose_command() {
   return DialogBox(hModule, MAKEINTRESOURCE(IDD_COMMANDS), mainWindow, CommandsDlgProc);
}

bool do_choose_perms(Buffer &b) {
#ifdef DEBUG
   msg(PLUGIN_NAME": in do_choose_perms\n");
#endif
   Options mask;
   projectBuffer = &b;
   tempOpts.pub.ll = projectBuffer->readLong();
   tempOpts.sub.ll = projectBuffer->readLong();
   mask.pub.ll = projectBuffer->readLong();
   mask.sub.ll = projectBuffer->readLong();

   Options current = tempOpts;

#ifdef DEBUG
   msg(PLUGIN_NAME":  P %x  S %x\n", (uint32_t)tempOpts.pub, (uint32_t)tempOpts.sub);
#endif

   int numOptions = projectBuffer->readInt();
   numOptionsGlobal = numOptions;

   optLabels = (char**)qalloc(numOptions * sizeof(char*));
   for (int i = 0; i < numOptions; i++) {
      optLabels[i] = projectBuffer->readUTF8();
   }
   showOptionsDlg(mainWindow, optLabels, numOptionsGlobal, &tempOpts, &tempOpts, &mask);

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;
   
   return memcmp(&current, &tempOpts, sizeof(Options)) != 0;
}

bool sameDay(time_t t1, time_t t2) {
   tm tm1 = *localtime(&t1);
   tm tm2 = *localtime(&t2);
   return tm1.tm_yday == tm2.tm_yday && tm1.tm_year == tm2.tm_year;
}

static const char *months[] = {
   "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

void postCollabMessage(const char *message, time_t t) {
   static time_t last = 0;
   if (t == 0) {
      time(&t);
   }
   bool same = sameDay(last, t);
   last = t;
   tm *lt = localtime(&t);
   if (!same) {
      char change[80];
      ::qsnprintf(change, sizeof(change), "Day changed to %02d %s %4d", lt->tm_mday, months[lt->tm_mon], lt->tm_year + 1900); 
      msg("%s\n", change);
      if (msgHistory != NULL) {
         msgHistory->writeUTF8(change);
      }
   }
   last = t;
   uint32_t len = 16 + strlen(message);
   char *m = new char[len];
   ::qsnprintf(m, len, "%02d:%02d %s", lt->tm_hour, lt->tm_min, message);
   msg("%s\n", m);
   if (msgHistory != NULL) {
      msgHistory->writeUTF8(m);
   }
   delete [] m;
}
