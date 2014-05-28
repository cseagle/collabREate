/*
    Collabreate GUI and communications layer
    Copyright (C) 2008-2010 Chris Eagle <cseagle at gmail d0t com>
    Copyright (C) 2008-2010 Tim Vidas <tvidas at gmail d0t com>


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

#include "collabreate.h"

#include <pro.h>
#include <kernwin.hpp>

#include <time.h>
#include <string.h>
#include <netnode.hpp>
#include <nalt.hpp>
#include <md5.h>

#include "collabreate_ui_qt.hpp"
#include "buffer.h"

#include <loader.hpp>

#include <QtGui>
#include <QApplication>
#include <QLabel>
#include <QPushButton>

using namespace QT;

QWidget *mainWindow;

static CollabLayout *cform;

//global pointer to the incoming project list buffer.  Used to fill
//the project list dialog
static Buffer *projectBuffer;

QWidget *getWidgetParent() {
   if (mainWindow == NULL) {
      mainWindow = QApplication::activeWindow();
   }
   return mainWindow;
}

void ConnectDlg::connectToServer() {
   QString host = hostLineEdit->text();
   QByteArray bytes = host.toAscii();
   char *chost = bytes.data();
   
   int port = portLineEdit->text().toInt();

   cnn.altset(LAST_PORT_ALTVAL, port);
   cnn.supset(LAST_SERVER_SUPVAL, chost);

   //connect to the server.
   if (!connect_to(chost, port, disp)) {
      //open failure dialog here, require user to use cancel button
      //to close the connect dialog
      //build a better error message including host:port
      QMessageBox::warning(NULL, "Error", "Error connection to database server failed");
   }            
   else {
      msg(PLUGIN_NAME": successfully connected to %s:%d\n", chost, port);
      accept();
   }
}

void AuthDlg::do_ok() {
   QString user = userLineEdit->text();
   QString pass = passLineEdit->text();

   QByteArray ubytes = user.toAscii();
   char *u = ubytes.data();

   QByteArray pbytes = pass.toAscii();
   char *p = pbytes.data();
#ifdef DEBUG
   msg(PLUGIN_NAME": saving auth data: %s/%s\n", u, p);
#endif
   ::saveAuthData(u, p);

   accept();
}

void ProjectDlg::projectChosen() {
   selected = projectsCombo->currentIndex();
   QString desc = descriptionLineEdit->text();            
   QByteArray bytes = desc.toAscii();
   char *d = bytes.data();
   if (selected == 0) {
      //new project, make sure that user hasn't tried to name the project using
      //an existing project name
      for (int n = 1; n < projectsCombo->count(); n++) {
         QString item = projectsCombo->itemText(n);
         int i = item.indexOf(']');
         if (i != -1) {
            i += 2;
            QString name = item.mid(i);
            if (name == desc) {
               QMessageBox::warning(NULL, "Error", "Project already exists. Join existing project or change name.");
               return;
            }
         }
      }
   }
   selected = chooseProject(selected, d);
   accept();
}

void ProjectDlg::projectChanged(int index) {
   selected = index;
   if (changeProject(index)) {
      descriptionLineEdit->setEnabled(true);
   }
   else if (numProjectsGlobal > 0) {
      descriptionLineEdit->setEnabled(false);
   }
}

void ProjectDlg::doOptions() {
#ifdef DEBUG
   msg(PLUGIN_NAME": calling showOptionsDlg\n");
#endif
   OptionsDlg optionsDlg(this, optLabels, numOptionsGlobal, &userOpts, &userOpts, &userOpts, selected);
   optionsDlg.exec();
}

void CommandDlg::commandSelected() {
   selected = commands->currentRow();
   accept();   
}

bool do_project_select(Buffer &b) {
   bool result = true;
   projects = NULL;
   snapUpdateIDs = NULL;
   projectBuffer = &b;
   ProjectDlg pd(getWidgetParent());
   if (pd.exec()) {
      selectProject(pd.getSelected());
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

int do_auth(unsigned char *challenge, int challenge_len) {
   int rval = 0;
   AuthDlg ad(getWidgetParent());
   if (ad.exec()) {
#ifdef DEBUG
      msg(PLUGIN_NAME": sending auth data\n");
#endif
      sendAuthData(challenge, challenge_len);
   }
   else {
      msg(PLUGIN_NAME": authentication cancelled.\n");
      rval = 1;
   }         
   return rval;
}

bool do_connect(Dispatcher d) {
   //if we are already connected then do nothing.
   if (is_connected()) return true;

   ConnectDlg cd(getWidgetParent(), d);
   return cd.exec() == QDialog::Accepted;
}

int do_choose_command() {
   CommandDlg cd(getWidgetParent());
   cd.exec();
   return cd.getSelected();
}

bool do_choose_perms(Buffer &b) {
   bool result = false;
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
   msg(PLUGIN_NAME":  P %x  S %x \n", tempOpts.pub.ii[0], tempOpts.sub.ii[0]);
#endif

   int numOptions = projectBuffer->readInt();
   numOptionsGlobal = numOptions;

   optLabels = (char**)qalloc(numOptions * sizeof(char*));
   for (int i = 0; i < numOptions; i++) {
      optLabels[i] = projectBuffer->readUTF8();
   }
   OptionsDlg optionsDlg(getWidgetParent(), optLabels, numOptionsGlobal, &tempOpts, &tempOpts, &mask);
   if (optionsDlg.exec()) {
      //detect any change in permissions
      result = memcmp(&current, &tempOpts, sizeof(Options)) != 0;      
   }

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;
   
   return result;
}

//message handler for the server connection dialog
ConnectDlg::ConnectDlg(QWidget *parent, Dispatcher d) : QDialog(parent) {
   setModal(true);
   disp = d;

   QLabel *hostLabel = new QLabel("Server:");
   QLabel *portLabel = new QLabel("Port:");
   
   char host[128];
   char sport[16];
   int port = cnn.altval(LAST_PORT_ALTVAL);
   if (port == 0) {
      port = 5042;
   }
         
   host[0] = 0;
   cnn.supstr(LAST_SERVER_SUPVAL, host, sizeof(host));

   ::qsnprintf(sport, sizeof(sport), "%d", port);
   
   hostLineEdit = new QLineEdit(host);
   portLineEdit = new QLineEdit(sport);
   portLineEdit->setValidator(new QIntValidator(1, 65535, this));
   
   hostLabel->setBuddy(hostLineEdit);
   portLabel->setBuddy(portLineEdit);
   
   QPushButton *okButton = new QPushButton("OK");
   okButton->setDefault(true);
   
   QPushButton *cancelButton = new QPushButton("Cancel");
   
   connect(okButton, SIGNAL(clicked()), this, SLOT(connectToServer()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
   
   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(cancelButton);
   buttonLayout->addStretch(1);
   
   QVBoxLayout *mainLayout = new QVBoxLayout;
   mainLayout->addWidget(hostLabel);
   mainLayout->addWidget(hostLineEdit);
   mainLayout->addWidget(portLabel);
   mainLayout->addWidget(portLineEdit);
   mainLayout->addLayout(buttonLayout);
   setLayout(mainLayout);
   
   setWindowTitle("Connect to collabREate server");
   hostLineEdit->setFocus();
}

//message handler for the server connection dialog
AuthDlg::AuthDlg(QWidget *parent) : QDialog(parent) {
   setModal(true);
   QLabel *userLabel = new QLabel("User Name:");
   QLabel *passLabel = new QLabel("Password:");
   
   char user[128];

   user[0] = 0;
   cnn.supstr(LAST_USER_SUPVAL, user, sizeof(user));

   userLineEdit = new QLineEdit(user);
   passLineEdit = new QLineEdit();
   passLineEdit->setEchoMode(QLineEdit::Password);
   
   userLabel->setBuddy(userLineEdit);
   passLabel->setBuddy(passLineEdit);
   
   QPushButton *okButton = new QPushButton("OK");
   okButton->setDefault(true);
   
   QPushButton *cancelButton = new QPushButton("Cancel");
   
   connect(okButton, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
   
   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(cancelButton);
   buttonLayout->addStretch(1);
   
   QVBoxLayout *mainLayout = new QVBoxLayout;
   mainLayout->addWidget(userLabel);
   mainLayout->addWidget(userLineEdit);
   mainLayout->addWidget(passLabel);
   mainLayout->addWidget(passLineEdit);
   mainLayout->addLayout(buttonLayout);
   setLayout(mainLayout);
   
   setWindowTitle("collabREate Login");
   userLineEdit->setFocus();
}

//message handler for the server connection dialog
CommandDlg::CommandDlg(QWidget *parent) : QDialog(parent) {
   setModal(true);
   selected = -1;
   commands = new QListWidget(this);
   commands->setViewMode(QListView::ListMode);
   commands->setSelectionBehavior(QAbstractItemView::SelectItems);
   commands->setSelectionMode(QAbstractItemView::SingleSelection);
   int i = 0;
   for (const char *cmd = getRunCommand(i); cmd; cmd = getRunCommand(i)) {
      QString s(cmd);
      commands->addItem(s);
      i++;
   }

   QPushButton *okButton = new QPushButton("OK");
   okButton->setDefault(true);
   
   QPushButton *cancelButton = new QPushButton("Cancel");
   
   connect(okButton, SIGNAL(clicked()), this, SLOT(commandSelected()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
   
   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(cancelButton);
   buttonLayout->addStretch(1);
   
   QVBoxLayout *mainLayout = new QVBoxLayout;
   mainLayout->addWidget(commands);
   mainLayout->addLayout(buttonLayout);
   setLayout(mainLayout);
   
   setWindowTitle("Select Command");
   commands->setFocus();
}

//The global projectBuffer pointer should be initialized to point to 
//the incoming buffer that contains the project list to be displayed in
//the project list dialog PRIOR to calling DialogBox
ProjectDlg::ProjectDlg(QWidget *parent) : QDialog(parent) {
   setModal(true);

   QLabel *projectsLabel = new QLabel("Select a project to join:");
   QLabel *descriptionLabel = new QLabel("Description (New project only):");

   selected = 0;
   
   projectsCombo = new QComboBox();

   int numProjects = projectBuffer->readInt();
   numProjectsGlobal = numProjects;
   
   projects = (int*)qalloc(numProjects * sizeof(int));
   snapUpdateIDs = (uint64_t*)qalloc(numProjects * sizeof(uint64_t));
   optMasks = (Options*)qalloc(numProjects * sizeof(Options));
   
   //the New project is always listed as the first option
   projectsCombo->addItem("<New project>");
   for (int i = 0; i < numProjects; i++) {
      projects[i] = projectBuffer->readInt();
      snapUpdateIDs[i] = projectBuffer->readLong();
      //if (snapUpdateIDs[i] > 0 ) {
      //   msg(PLUGIN_NAME": project %d is a snapshot\n", i+1);
      //}
      char *desc = projectBuffer->readUTF8();
#ifdef DEBUG
      int isSnapShot = 0;
      if (snapUpdateIDs[i] != 0) {
         isSnapShot = 1;
      }
      msg(PLUGIN_NAME": %d : %d - %s (%d) ", i, projects[i], desc, isSnapShot);
#endif
      QString s(desc);
      projectsCombo->addItem(s);
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

   descriptionLineEdit = new QLineEdit();
//   descriptionLineEdit->setEnabled(false);
   
   projectsLabel->setBuddy(projectsCombo);
   descriptionLabel->setBuddy(descriptionLineEdit);
   
   QPushButton *okButton = new QPushButton("OK");
   okButton->setDefault(true);
   
   QPushButton *optionsButton = new QPushButton("Options");

   QPushButton *cancelButton = new QPushButton("Cancel");
   
   connect(projectsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(projectChanged(int)));
   connect(okButton, SIGNAL(clicked()), this, SLOT(projectChosen()));
   connect(optionsButton, SIGNAL(clicked()), this, SLOT(doOptions()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
   
   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(optionsButton);
   buttonLayout->addWidget(cancelButton);
   buttonLayout->addStretch(1);
   
   QVBoxLayout *mainLayout = new QVBoxLayout;
   mainLayout->addWidget(projectsLabel);
   mainLayout->addWidget(projectsCombo);
   mainLayout->addWidget(descriptionLabel);
   mainLayout->addWidget(descriptionLineEdit);
   mainLayout->addLayout(buttonLayout);
   setLayout(mainLayout);
   
   setWindowTitle("Project Selection");
   projectsCombo->setFocus();
}

void CollabLayout::append(const char *line) {
   append(QString(line));
}

void CollabLayout::append(const QString &label) {
   list->addItem(label);
}

void CollabLayout::processEdit() {
//   append(input->text());
   if (input->text().length() == 0) {
      return;
   }
   QByteArray bytes = input->text().toAscii();
   char *d = bytes.data();
   char *end = strrchr(d, '\n');
   if (end != NULL) {
      *end = 0;
   }
   uint32_t len = strlen(d) + strlen(username) + 20;
   char *line = new char[len];
   ::qsnprintf(line, len, "< %s> %s", username, d);
   postCollabMessage(line);
   delete [] line;
   do_send_user_message(d);
   input->clear();
}

CollabLayout::CollabLayout() : QVBoxLayout() {
   list = new QListWidget();
   input = new QLineEdit();
   addWidget(list);
   addWidget(input);

   setSpacing(2);
   setContentsMargins(4, 4, 4, 4);
   
   connect(input, SIGNAL(editingFinished()), this, SLOT(processEdit()));
   
   idaview = find_tform("IDA View-A");

}

int idaapi ui_collab(void *user_data, int notification_code, va_list va) {
   if (notification_code == ui_tform_visible) {
      TForm *form = va_arg(va, TForm *);
      if (form == user_data) {
         QWidget *w = (QWidget *)form;
         cform = new CollabLayout();
         w->setLayout(cform);
         msg("CollabREate form is visible\n");
         switchto_tform(cform->idaview, true);
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
            cnn.setblob(msgHistory->get_buf(), msgHistory->size(), 1, COLLABREATE_MSGHISTORY_TAG);
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

void createCollabStatus() {
   HWND hwnd = NULL;
   TForm *form = create_tform("CollabREate", &hwnd);
   if (hwnd != NULL) {
      hook_to_notification_point(HT_UI, ui_collab, form);
      open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU|FORM_RESTORE|FORM_QWIDGET);
   }
   else {
      close_tform(form, FORM_SAVE);
   }
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
      ::qsnprintf(change, sizeof(change), "Day changed to %02d %s %4d", lt->tm_mday, months[lt->tm_mon], lt->tm_year + 1900); 
      if (msgHistory != NULL) {
         msgHistory->writeUTF8(change);
      }
   }
   uint32_t len = 16 + strlen(message);
   char *m = new char[len];
   ::qsnprintf(m, len, "%02d:%02d %s", lt->tm_hour, lt->tm_min, message);
   if (msgHistory != NULL) {
      msgHistory->writeUTF8(m);
   }
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
   delete [] m;
}
