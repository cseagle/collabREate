
#include <pro.h>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <loader.hpp>

#include <json-c/json.h>

#include "collabreate.h"
#include "collabreate_ui.h"

#if IDA_SDK_VERSION < 700
static TForm *collab_tform;
static TForm *cform;
#else
static TWidget *collab_tform;
static TWidget *cform;
#endif

static form_actions_t *dangerous;
static qvector<qstring> messages;
static qstring msg_text;

// Form actions for editor window
enum collab_form_actions
{
  TEXT_CHANGED  = 2,
  SEND = 3
};

#if IDA_SDK_VERSION < 700
static int idaapi send_cb(TView *[], int) {
#else
static int idaapi send_cb(TWidget *[], int) {
#endif
   return 0;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal editor form
static int idaapi collab_cb(int fid, form_actions_t &fa) {
   switch (fid) {
      case CB_INIT:
//         msg("init collab form\n");
         break;
      case CB_CLOSE:
//         msg("closing collab form\n");
         // mark the form as closed
         collab_tform = NULL;
         break;
      case TEXT_CHANGED:
//         msg("text has been changed\n");
         break;
      case SEND: {  // Send button pressed
         qstring val;
#if IDA_SDK_VERSION <= 650
         if (fa.get_field_value(2, &val)) {
#elif IDA_SDK_VERSION <= 670
         if (fa._get_field_value(2, &val)) {
#else
         if (fa.get_string_value(2, &val)) {
#endif
            msg("Sending: %s\n", val.c_str());

            //*** are next two lines necessary or should we wait
            //for message to get send back from the server following timestamping
            msgHistory.push_back(val.c_str());
            refresh_chooser("Collab form:1");

            do_send_user_message(val.c_str());
         }
         break;
      }
      default:
         break;
   }
   return 1;
}

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

   uint32_t numProjects = (uint32_t)json_object_array_length(jprojects);
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

   int numOptions = (int)json_object_array_length(options);
   numOptionsGlobal = numOptions;
   optLabels = (char**)qalloc(sizeof(char*) * numOptions);

   for (int i = 0; i < numOptions; i++) {
      json_object *label = json_object_array_get_idx(options, i);
      optLabels[i] = qstrdup(json_object_to_json_string(label));
   }

   int res = AskUsingForm_c(format, description, &projectList, &sel);
   if (res == ASKBTN_YES) {
      return sel ? projects[sel - 1] : 0;  //map selection index to associated project number
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

#if IDA_SDK_VERSION < 700
static void idaapi collab_getl(void *, uint32 n, char *const *arrptr) {
   qstrncpy(arrptr[0], n == 0 ? "Messages" : msgHistory[n-1].c_str(), MAXSTR);
}

static uint32 idaapi collab_sizer(void *) {
   return msgHistory.size();
}

void createCollabStatus() {
  static const char format[] =
    "BUTTON NO NONE\nBUTTON YES NONE\nBUTTON CANCEL NONE\n"
    "Collab form\n\n"
    "%/\n"        // placeholder for the form's callback
    "<Messages:E1:::::>\n<Send:B3:20:::>< :q2::100:::>\n";
   chooser_info_t ci;
   ci.columns = 1;
   ci.getl = collab_getl;
   ci.sizer = collab_sizer;
   static const int widths[] = { 128 };
   ci.widths = widths;
   // selection for chooser list view
   intvec_t ivec;
   collab_tform = OpenForm_c(format, FORM_QWIDGET | FORM_TAB, collab_cb, &ci, &ivec, send_cb, &msg_text);
}
#else
struct collab_msg_chooser : public chooser_t {
   static const int widths[];
   static const char* header[];
   collab_msg_chooser() : chooser_t(CH_KEEP, 1, widths, header, "Collab form") {};
   void idaapi get_row(qstrvec_t *cols, int * /*icon_*/, chooser_item_attrs_t * /*attrs*/, size_t n) const {
      qstrvec_t &cols_ = *cols;
      cols_[0] = msgHistory[n];
   };

   size_t idaapi get_count() const {
      return msgHistory.size();
   };
};

static collab_msg_chooser status;
// selection for chooser list view
static sizevec_t status_ivec;

const int collab_msg_chooser::widths[] = { 128 };
const char* collab_msg_chooser::header[] = { "Messages" };

void createCollabStatus() {
   static const char format[] =
      "BUTTON NO NONE\nBUTTON YES NONE\nBUTTON CANCEL NONE\n"
      "Collab form\n\n"
      "%/\n"        // placeholder for the form's callback
      "<Messages:E1:::::>\n<Send:B3:20:::>< :q2::100:::>\n";
   collab_tform = OpenForm_c(format, WOPN_TAB, collab_cb, &status, &status_ivec, send_cb, &msg_text);
}
#endif

bool sameDay(time_t t1, time_t t2) {
   tm *p_tm1 = localtime(&t1);
   if (p_tm1 == NULL) {
      return false;  //date error
   }
   tm tm1 = *p_tm1;
   tm *p_tm2 = localtime(&t2);
   if (p_tm2 == NULL) {
      return false;  //date error
   }
   tm tm2 = *p_tm2;
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
      ::qsnprintf(change, sizeof(change), "Day changed to %02d %s %4d", lt->tm_mday, months[lt->tm_mon], lt->tm_year + 1900); 
      msgHistory.push_back(change);
   }
   uint32_t len = 16 + (uint32_t)strlen(message);
   char *m = new char[len];
   ::qsnprintf(m, len, "%02d:%02d %s", lt->tm_hour, lt->tm_min, message);
   msgHistory.push_back(m);
   refresh_chooser("Collab form:1");
   delete [] m;
}

#if IDA_SDK_VERSION >= 700

struct cmd_chooser : public chooser_t {
   static const int widths[];
   static const char *header[];

   cmd_chooser() : chooser_t(CH_MODAL | CH_KEEP | CH_NOBTNS, 1, widths,
                             header, CHOOSER_NOMAINMENU CHOOSER_NOSTATUSBAR "Select Command") {
   };

   virtual void idaapi get_row(qstrvec_t *cols, int * /*icon_*/, chooser_item_attrs_t * /*attrs*/, size_t n) const {
      qstrvec_t &cols_ = *cols;
      cols_[0] = getRunCommand((int)n);
   };

   virtual size_t idaapi get_count() const {
      return numCommands();
   };
};

static sizevec_t cmd_choices;
static cmd_chooser cmd_info;

const int cmd_chooser::widths[] = { 32 };
const char *cmd_chooser::header[] = { "" };

int do_choose_command() {
   return cmd_info.choose();
}
#else
char* idaapi get_command(void *obj, uint32 n, char *buf) {
   if (n) {
      qstrncpy(buf, getRunCommand(n - 1), MAXSTR);
   }
   else {
      qstrncpy(buf, "Command", MAXSTR);
   }
   return buf;
}

uint32 idaapi sizer(void *obj) {
   return numCommands();
}

int do_choose_command() {
   int res = choose(CH_MODAL | CH_NOBTNS, -1, -1, -1, -1, (void*)NULL, 32, sizer, get_command, "Command", -1);
   if (res >= 1 && res <= numCommands()) {
      return res - 1;
   }
   return -1;
}
#endif

bool do_choose_perms(json_object *json) {  //"pub" "sub", "pub_mask", "sub_mask", also "perms" list
   bool result = false;
   return result;
}
