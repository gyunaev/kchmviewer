/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#ifndef KCHMDIALOGCHOOSEURLFROMLIST_H
#define KCHMDIALOGCHOOSEURLFROMLIST_H

#include <QDialog>
#include "ui_dialog_topicselector.h"


class KCHMDialogChooseUrlFromList : public QDialog, public Ui::DialogTopicSelector
{
	Q_OBJECT
	
	public:
    	KCHMDialogChooseUrlFromList( QWidget* parent );
		
		// Shows the dialog with titles, and let the user to select the title.
		// Obviously urls.size() == titles.size(). Returns the appropriate URL
		// for the selected title, or empty string if no title selected, or dialog canceled.
		QString getSelectedItemUrl( const QStringList& urls, const QStringList& titles );

	private slots:
		void onDoubleClicked( QListWidgetItem * item );
};

#endif
