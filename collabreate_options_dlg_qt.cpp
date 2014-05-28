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

#include "collabreate_ui_qt.hpp"
#include "buffer.h"

using namespace QT;

#define COLLAB_CB_BASE 2000
//#define DEBUG 1

void OptionsDlg::chooseAll() {
   #ifdef DEBUG
      msg(PLUGIN_NAME": sub all pressed\n");
   #endif
   for (int i = 0; i < numOpts; i++) {
      QCheckBox *cb = (QCheckBox *)bg.button(COLLAB_CB_BASE + i * 2 + 1);
      if (cb->isEnabled()) {
         cb->setCheckState(Qt::Checked);
      }
   }
}

void OptionsDlg::chooseOnly() {
   #ifdef DEBUG
      msg(PLUGIN_NAME": sub only pressed\n");
   #endif
   for (int i = 0; i < numOpts; i++) {
      QCheckBox *cb = (QCheckBox *)bg.button(COLLAB_CB_BASE + i * 2);
      cb->setCheckState(Qt::Unchecked);
   }
}

void OptionsDlg::optionsDone() {
   //we can only get here if dialog has been accepted
   //only then are the permissions copied to the output value
   //need to collect final checkbox states
   uint64_t bit = 1;
   for (int i = 0; i < numOpts; i++) {
      QAbstractButton *cb = bg.button(COLLAB_CB_BASE + i * 2);
      if (cb->isChecked()) {
         optsOut->pub.ll |= bit;
      }
      else {
         optsOut->pub.ll &= ~bit;
      }
      cb = bg.button(COLLAB_CB_BASE + i * 2 + 1);
      if (cb->isChecked()) {
         optsOut->sub.ll |= bit;
      }
      else {
         optsOut->sub.ll &= ~bit;
      }
      bit <<= 1;
   }
   accept();
}

/*
 * The purpose of this function is to layout and display the pub/sub options
 * dialog based on a variable number of input options.  The input option
 * mask dictates which options are enabled by default, while the output mask is
 * used to indicate which options were selected by the user (from the 
 * available options specified by in. Mask determines which options are available.  
 */
OptionsDlg::OptionsDlg(QWidget *parent, char **optionLabels, int numOptions, 
                       Options *in, Options *out, Options *mask, int projectIndex) : QDialog(parent) {   
   setModal(true);
   bg.setExclusive(false);
   optsIn = in;
   
   optsOut = out;
   optsMask = mask;
   numOpts = numOptions;
   
   QPushButton *allButton = new QPushButton("Subscribe All");
   QPushButton *onlyButton = new QPushButton("Subscribe Only");

   QPushButton *okButton = new QPushButton("OK");
   okButton->setDefault(true);
   
   QPushButton *cancelButton = new QPushButton("Cancel");

   connect(allButton, SIGNAL(clicked()), this, SLOT(chooseAll()));
   connect(onlyButton, SIGNAL(clicked()), this, SLOT(chooseOnly()));
   connect(okButton, SIGNAL(clicked()), this, SLOT(optionsDone()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(close()));
   
   QGridLayout *mainLayout = new QGridLayout;
   mainLayout->addWidget(new QLabel("Options"), 0, 0);
   mainLayout->addWidget(new QLabel("Pub"), 0, 1);
   mainLayout->addWidget(new QLabel("Sub"), 0, 2);
   
   //print all of the option labels and their checkboxes
   uint64_t bit = 1;
   int i;
   for (i = 0; i < numOptions; i++) {
      QString s(optionLabels[i]);
      mainLayout->addWidget(new QLabel(s), i + 1, 0);

      QCheckBox *cb = new QCheckBox(this);
      mainLayout->addWidget(cb, i + 1, 1);
      //test option bits to see if the publish bit is set
      if (optsMask->pub.ll & bit) {
         cb->setEnabled(true);
      }
      else {
         cb->setEnabled(false);
      }
      if (optsIn->pub.ll & bit) {
         cb->setCheckState(Qt::Checked);
      }
      bg.addButton(cb, COLLAB_CB_BASE + i * 2);
      
      cb = new QCheckBox(this);
      mainLayout->addWidget(cb, i + 1, 2);
      //test option bits to see if the subscribe bit is set
      if (optsMask->sub.ll & bit) {
         cb->setEnabled(true);
      }
      else {
         cb->setEnabled(false);
      }
      if (optsIn->sub.ll & bit) {
         cb->setCheckState(Qt::Checked);
      }
      bg.addButton(cb, COLLAB_CB_BASE + i * 2 + 1);

      bit <<= 1;
   }

   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(allButton);
   buttonLayout->addWidget(onlyButton);
   buttonLayout->addStretch(1);
   
   mainLayout->addLayout(buttonLayout, i + 1, 0, 1, 3);

   buttonLayout = new QHBoxLayout;
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(cancelButton);
   
   mainLayout->addLayout(buttonLayout, i + 2, 0, 1, 3);
   setLayout(mainLayout);   

   if (projectIndex == 0) {   //should be for snapshots too...
      setWindowTitle("Set Permissions");
   }
   else {
      setWindowTitle("Project Join Options");
   }
}
