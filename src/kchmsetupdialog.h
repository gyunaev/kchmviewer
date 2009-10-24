/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#ifndef KCHMSETUPDIALOG_H
#define KCHMSETUPDIALOG_H

#include <QDialog>
#include <ui_dialog_setup.h>


class KCHMSetupDialog : public QDialog, public Ui::DialogSetup
{
	Q_OBJECT
			
	public:
    	KCHMSetupDialog( QWidget *parent = 0 );
    	~KCHMSetupDialog();
		
	public slots:
		void	browseExternalEditor();
		void	accept();
		
	private:
		int		m_numOfRecentFiles;
};

#endif
