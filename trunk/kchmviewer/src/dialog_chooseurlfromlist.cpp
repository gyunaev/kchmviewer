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

#include "kde-qt.h"

#include "dialog_chooseurlfromlist.h"
#include "treeviewitem.h"


DialogChooseUrlFromList::DialogChooseUrlFromList( QWidget* parent )
	: QDialog( parent ), Ui::DialogTopicSelector()
{
	setupUi( this );
	
	// List doubleclick
	connect( list, 
			 SIGNAL( itemDoubleClicked ( QListWidgetItem * ) ),
			 this,
	         SLOT( onDoubleClicked( QListWidgetItem * ) ) );
}

void DialogChooseUrlFromList::onDoubleClicked( QListWidgetItem * item )
{
	if ( item )
		accept();
}


QString DialogChooseUrlFromList::getSelectedItemUrl( const QStringList & urls, const QStringList & titles )
{
	for ( int i = 0; i < urls.size(); i++ )
		list->addItem( titles[i] );
	
	if ( exec() == QDialog::Accepted && list->currentRow() != -1 )
		return urls[ list->currentRow() ];
	
	return QString::null;
}
