
#include <pro.h>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <loader.hpp>

#include <json.h>

#include "collabreate.h"
#include "collabreate_ui.h"

static TForm *cform;
static qstring cmsg;
static textctrl_info_t chistory;

bool do_connect(Dispatcher disp) {
   const char *format = "BUTTON YES* Ok\nBUTTON CANCEL Cancel\nConnect to collabREate server\n\n\n<Server:A:64:64::>\n<Port:D:16:16::>\n";

   char host[128];

   if (is_connected()) return true;

   sval_t port = cnn.altval(LAST_PORT_ALTVAL);
   if (port == 0) {
      port = 5042;
   }
   
   host[0] = 0;
   cnn.supstr(LAST_SERVER_SUPVAL, host, sizeof(host));

   int res = AskUsingForm_c(format, host, &port);
   if (res == ASKBTN_YES) {
      cnn.altset(LAST_PORT_ALTVAL, port);
      cnn.supset(LAST_SERVER_SUPVAL, host);
   
      //connect to the server.
      if (!connect_to(host, port, disp)) {
         //open failure dialog here, require user to use cancel button
         //to close the connect dialog
         //build a better error message including host:port
         warning("Error connection to database server failed");
         return false;
      }            
      msg(PLUGIN_NAME": successfully connected to %s:%d\n", host, port);
      return true;
   }
   return false;   
}

bool do_auth() {
   const char *format = "BUTTON YES* Ok\nBUTTON CANCEL Cancel\ncollabREate Login\n\n\n<User Name:A:64:64::>\n<Password:A:64:64::>\n";

   char user[128];
   char password[128];
   
   user[0] = 0;
   password[0] = 0;
   cnn.supstr(LAST_USER_SUPVAL, user, sizeof(user));

   int res = AskUsingForm_c(format, user, password);
   if (res == ASKBTN_YES) {
      ::saveAuthData(user, password);
      return true;
   }
   return false;   
}

int choose_project(json_object *json) {
   const char *format = "BUTTON YES* Ok\nBUTTON CANCEL Cancel\nProject Selection\n\n\nSelect a project to join:\n<Description (New project only):A:1024:64::>\n<Project:b:0:::>\n";

   description[0] = 0;

   json_object *jprojects;

   if (!json_object_object_get_ex(json, "projects", &jprojects)) {
      return -1;
   }

   uint32_t numProjects = json_object_array_length(jprojects);
   numProjectsGlobal = numProjects;
   
   ::qstrvec_t projectList;
   int sel = 0;
   
   projects = (int*)qalloc(numProjects * sizeof(int));
   snapUpdateIDs = (uint64_t*)qalloc(numProjects * sizeof(uint64_t));
   optMasks = (Options*)qalloc(numProjects * sizeof(Options));
   
   //the New project is always listed as the first option
   projectList.push_back("<New project>");
   for (uint32_t i = 0; i < numProjects; i++) {
      json_object *project = json_object_array_get_idx(jprojects, i);

      if (!int32_from_json(project, "id", &projects[i])) {
         //malformed json
         return -1;
      }
      if (!uint64_from_json(project, "snap_id", &snapUpdateIDs[i])) {
         //malformed json
         return -1;
      }
      //if (snapUpdateIDs[i] > 0 ) {
      //   msg(PLUGIN_NAME": project %d is a snapshot\n", i+1);
      //}
      const char *desc = string_from_json(project, "description");
      if (desc == NULL) {
         //malformed json
         return -1;
      }
#ifdef DEBUG
      int isSnapShot = 0;
      if (snapUpdateIDs[i] != 0) {
         isSnapShot = 1;
      }
      msg(PLUGIN_NAME": %d : %d - %s (%d) ", i, projects[i], desc, isSnapShot);
#endif
      projectList.push_back(desc);
      
      //need to read options mask for this project
      //but for now everything is enabled
      //memset(optMasks + i, 0xFF, sizeof(Options));
      if (!uint64_from_json(project, "pub_mask", &optMasks[i].pub.ll)) {
         //malformed json
         return -1;
      }
      if (!uint64_from_json(project, "sub_mask", &optMasks[i].sub.ll)) {
         //malformed json
         return -1;
      }
#ifdef DEBUG
      msg(PLUGIN_NAME": P %x  S %x \n", optMasks[i].pub.ii[0], optMasks[i].sub.ii[0]);
#endif
   }

   json_object *options;
   if (!json_object_object_get_ex(json, "options", &options)) {
      return -1;
   }

   int numOptions = json_object_array_length(options);
   numOptionsGlobal = numOptions;
   optLabels = (char**)qalloc(sizeof(char*) * numOptions);

   for (int i = 0; i < numOptions; i++) {
      json_object *label = json_object_array_get_idx(options, i);
      optLabels[i] = qstrdup(json_object_to_json_string(label));
   }

   int res = AskUsingForm_c(format, description, &projectList, &sel);
   if (res == ASKBTN_YES) {
      return sel;
   }
   return -1;
}

bool do_project_select(json_object *json) {
   bool result = true;
   projects = NULL;
   snapUpdateIDs = NULL;
   int selected = choose_project(json);
   if (selected >= 0) {
      selectProject(selected);
   }
   else {
#ifdef DEBUG
      msg(PLUGIN_NAME": project select cancelled\n");
#endif
      result = false;
   }
   freeProjectFields();
   return result;
}

int idaapi ui_collab(void *user_data, int notification_code, va_list va) {
   if (notification_code == ui_tform_visible) {
      TForm *form = va_arg(va, TForm *);
      if (form == user_data) {
         //tc.flags = TXTF_READONLY | TXTF_FIXEDFONT;
         //tc.text = ??;
/*
         QWidget *w = (QWidget *)form;
         cform = new CollabLayout();
         w->setLayout(cform);
*/
         msg("CollabREate form is visible\n");
         switchto_tform(cform, true);
/*
         if (msgHistory == NULL) {
            uint32_t sz = cnn.blobsize(1, COLLABREATE_MSGHISTORY_TAG);
            if (sz > 0) {
               msgHistory = new Buffer(cnn.getblob(NULL, (size_t*)&sz, 1, COLLABREATE_MSGHISTORY_TAG), sz, false);
               char *str;
               while ((str = msgHistory->readUTF8()) != NULL) {
                  cform->append(str);
                  qfree(str);
               }
               msgHistory->reset_error();
            }
            else {
               msgHistory = new Buffer();
            }
         }
*/
         if (msgHistory == NULL) {
            ssize_t sz = cnn.supstr(1, NULL, 0, COLLABREATE_MSGHISTORY_TAG);
            if (sz > 0) {
               char *tmp = new char[sz + 2];
               cnn.supstr(1, tmp, sz + 2, COLLABREATE_MSGHISTORY_TAG);
               msgHistory = new qstring(tmp);
               delete [] tmp;
               chistory.text += *msgHistory;
//               cform->append(msgHistory->c_str());
            }
            else {
               msgHistory = new qstring();
            }
         }
         else {
//            cform->append(msgHistory->c_str());
         }
      }
   }
   else if (notification_code == ui_tform_invisible) {
      TForm *form = va_arg(va, TForm *);
      if (form == user_data) {
         // user defined form is closed, destroy its controls
         // (to be implemented)
         msg("CollabREate form is closed\n");
         unhook_from_notification_point(HT_UI, ui_collab);
         cform = NULL;
         if (msgHistory != NULL) {
            cnn.supset(1, msgHistory->c_str(), 0, COLLABREATE_MSGHISTORY_TAG);
            delete msgHistory;
            msgHistory = NULL;
         }
      }
   }
   return 0;
}

#ifndef FORM_MDI
#define FORM_MDI 0
#endif

int idaapi collab_cb(int field_id, form_actions_t &fa) {
   msg("collab_ui called for %d\n", field_id);
   return -1;
}

void createCollabStatus() {   
   chistory.flags = TXTF_READONLY | TXTF_FIXEDFONT;
   if (msgHistory == NULL) {
      ssize_t sz = cnn.supstr(1, NULL, 0, COLLABREATE_MSGHISTORY_TAG);
      if (sz > 0) {
         char *tmp = new char[sz + 2];
         cnn.supstr(1, tmp, sz + 2, COLLABREATE_MSGHISTORY_TAG);
         msgHistory = new qstring(tmp);
         delete [] tmp;
         chistory.text += *msgHistory;
      }
      else {
         msgHistory = new qstring();
      }
   }

/*
   cform = OpenForm_c("BUTTON YES NONE\nBUTTON NO NONE\nBUTTON CANCEL NONE\nCollabREate Status\n\n\n%/<:t1::::><:q2::::>",
                      FORM_MDI|FORM_TAB|FORM_MENU|FORM_RESTORE, collab_cb, &chistory, &cmsg);
   hook_to_notification_point(HT_UI, ui_collab, cform);
*/

/*
   HWND hwnd = NULL;
   TForm *form = create_tform("CollabREate", &hwnd);
   if (hwnd != NULL) {
      hook_to_notification_point(HT_UI, ui_collab, form);
      open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU|FORM_RESTORE|FORM_QWIDGET);
   }
   else {
      close_tform(form, FORM_SAVE);
   }
*/
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
   //get local time to prepend to message
   if (t == 0) {
      time(&t);
   }
   bool same = sameDay(last, t);
   last = t;
   tm *lt = localtime(&t);
   char change[80];
   if (!same) {
      ::qsnprintf(change, sizeof(change), "Day changed to %02d %s %4d\n", lt->tm_mday, months[lt->tm_mon], lt->tm_year + 1900); 
      if (msgHistory != NULL) {
         *msgHistory += change;
      }
   }
   uint32_t len = 16 + strlen(message);
   char *m = new char[len];
   ::qsnprintf(m, len, "%02d:%02d %s\n", lt->tm_hour, lt->tm_min, message);
   if (msgHistory != NULL) {
      *msgHistory += m;
   }
/*   
   if (cform) {
      if (!same) {
         cform->append(change);
      }
      cform->append(m);
   }
   else {
      if (!same) {
         msg("%s\n", change);
      }
      msg("%s\n", m);
   }
*/
   delete [] m;
}

void idaapi get_command(void *obj, uint32 n, char *const *arrptr) {
   if (n) {
      qstrncpy(arrptr[0], getRunCommand(n - 1), MAXSTR);
   }
   else {
      qstrncpy(arrptr[0], "Command", MAXSTR);
   }
}

uint32 idaapi sizer(void *obj) {
   return numCommands();
}

int do_choose_command() {
   const char *format = "BUTTON YES* Ok\nBUTTON CANCEL Cancel\nSelect Command\n\n\n<Command:E:32:32::>\n";
//   const char *format = "BUTTON YES* Ok\nBUTTON CANCEL Cancel\nSelect Command\n\n\n<:E:32:32::>\n";
   intvec_t choices;
   chooser_info_t info;
   memset(&info, 0, sizeof(info));
   int widths[] = {32};
   char *popups[] = {NULL};
   info.cb = sizeof(info);
   info.flags = CH_MODAL;
   info.width = 0;
   info.height = 0;
   info.columns = 1;
   info.widths = widths;
   info.icon = -1;
   info.deflt = 5;
//   info.popup_names = popups;
   info.sizer = sizer;
   info.getl = get_command;
  
   int res = AskUsingForm_c(format, &info, &choices);
   if (res == ASKBTN_YES) {
      if (choices.size() == 1) {
//      ::saveAuthData(user, password);
         return choices[0] - 1;
      }
   }
   return -1;
}

bool do_choose_perms(json_object *json) {  //"pub" "sub", "pub_mask", "sub_mask", also "perms" list
   bool result = false;
   return result;
}
