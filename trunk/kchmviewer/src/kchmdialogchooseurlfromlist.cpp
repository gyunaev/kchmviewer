/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "kde-qt.h"

#include "kchmdialogchooseurlfromlist.h"
#include "kchmtreeviewitem.h"


KCHMDialogChooseUrlFromList::KCHMDialogChooseUrlFromList( QWidget* parent )
	: QDialog( parent ), Ui::DialogTopicSelector()
{
	setupUi( this );
	
	// List doubleclick
	connect( list, 
			 SIGNAL( itemDoubleClicked ( QListWidgetItem * ) ),
			 this,
	         SLOT( onDoubleClicked( QListWidgetItem * ) ) );
}

void KCHMDialogChooseUrlFromList::onDoubleClicked( QListWidgetItem * item )
{
	if ( item )
		accept();
}


QString KCHMDialogChooseUrlFromList::getSelectedItemUrl( const QStringList & urls, const QStringList & titles )
{
	for ( int i = 0; i < urls.size(); i++ )
		list->addItem( titles[i] );
	
	if ( exec() == QDialog::Accepted && list->currentRow() != -1 )
		return urls[ list->currentRow() ];
	
	return QString::null;
}
