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

#include <json-c/json.h>

#include "idanet.h"

int do_choose_command();
bool do_project_select(json_object *json);
bool do_connect(Dispatcher d);
int  do_auth(unsigned char *challenge, int challenge_len);
void do_set_req_perms(void);
void do_set_proj_perms(void);
bool do_auth(void);

void createCollabStatus();

//void showOptionsDlg(HWND parent, Options *in, Options *out, Options *mask, char * title);

#endif
