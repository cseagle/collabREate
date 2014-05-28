/*
    Collabreate GUI and communications layer
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>

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

#ifndef __COLLABREATE_GUI_H__
#define __COLLABREATE_GUI_H__

#include "collabreate.h"
#include "idanet.hpp"
#include "buffer.h"

#include <pro.h>

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
#include "ms_stdint.h"
#endif
#else
#include <stdint.h>
#endif

#include <QtGui>
#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QButtonGroup>
#include <QVBoxLayout>

using namespace QT;

int do_choose_command();
bool do_project_select(Buffer &b);
bool do_connect(Dispatcher d);
int  do_auth(unsigned char *challenge, int challenge_len);
void do_set_req_perms(void);
void do_set_proj_perms(void);

void createCollabStatus();

extern QWidget *mainWindow;

class TForm;

class ConnectDlg : public QDialog {
   Q_OBJECT
   
public:
   ConnectDlg(QWidget *parent, Dispatcher d);
   //~ConnectDlg();
   
private slots:
   void connectToServer();
   
private:
   QLineEdit *hostLineEdit;
   QLineEdit *portLineEdit;
   Dispatcher disp;
};

class AuthDlg : public QDialog {
   Q_OBJECT
   
public:
   AuthDlg(QWidget *parent = 0);
   
private slots:
   void do_ok();
   
private:
   QLineEdit *userLineEdit;
   QLineEdit *passLineEdit;
};

class CommandDlg : public QDialog {
   Q_OBJECT
   
public:
   CommandDlg(QWidget *parent = 0);
   int getSelected() {return selected;}
   
private slots:
   void commandSelected();
   
private:
   QListWidget *commands;
   int selected;   
};

class ProjectDlg : public QDialog {
   Q_OBJECT
   
public:
   ProjectDlg(QWidget *parent = 0);
   int getSelected() {return selected;}
   
private slots:
   void projectChanged(int index);
   void projectChosen();
   void doOptions();
   
private:
   QComboBox *projectsCombo;
   QLineEdit *descriptionLineEdit;
   int selected;
};

class OptionsDlg : public QDialog {
   Q_OBJECT
   
public:
   OptionsDlg(QWidget *parent, char **optionLabels, int numOptions, 
              Options *in, Options *out, Options *mask, int projectIndex = 0);   
   
private slots:
   void chooseAll();
   void chooseOnly();
   void optionsDone();
   
private:
   QButtonGroup bg;
   QCheckBox *boxes;
   int selected;

   Options *optsIn, *optsOut, *optsMask;
   int numOpts;
};

class CollabLayout : public QVBoxLayout {
   Q_OBJECT
   
public:
   CollabLayout();
   void append(const char *line);  
   void append(const QString &label);

   TForm *idaview;
   
private slots:
   void processEdit();  
   
private:
   QListWidget *list;
   QLineEdit *input;

};

#endif
