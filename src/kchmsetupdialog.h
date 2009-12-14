/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

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
