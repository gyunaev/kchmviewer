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

KCHMDialogChooseUrlFromList::KCHMDialogChooseUrlFromList(const QStringList& urls, const QStringList& titles, QWidget* parent)
	: QDialog(parent, 0, true)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	QListView * m_urlsList = new QListView (this);
	m_urlsList->addColumn( i18n( "Topics" ) );
	
	for ( unsigned int i = 0; i < urls.size(); i++ )
		new KCHMSingleTreeViewItem (m_urlsList, titles[i], urls[i]);

	layout->addWidget ( new QLabel( i18n( "Please select one of the topics below:"), this) );
	layout->addWidget ( m_urlsList );

	QHBoxLayout * hlayout = new QHBoxLayout (layout);
	QPushButton * bok = new QPushButton( i18n( "&Ok" ), this);
	QPushButton * bcancel = new QPushButton( i18n( "&Cancel" ), this);

	hlayout->addWidget (bok);
	hlayout->addWidget (bcancel);

	connect( m_urlsList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );
	connect( m_urlsList, SIGNAL( currentChanged ( QListViewItem *) ), this, SLOT( onCurrentChanged ( QListViewItem *) ) );
	
	connect( bok, SIGNAL( clicked () ), this, SLOT( accept() ) );
	connect( bcancel, SIGNAL( clicked () ), this, SLOT( reject() ) );
	m_acceptedurl = QString::null;
}

void KCHMDialogChooseUrlFromList::onDoubleClicked( QListViewItem * , const QPoint &, int )
{
	accept();
}

void KCHMDialogChooseUrlFromList::onCurrentChanged( QListViewItem * item )
{
	if ( item )
		m_acceptedurl = ((KCHMSingleTreeViewItem *) item)->getUrl();
	else
		m_acceptedurl = QString::null;
}

#include "kchmdialogchooseurlfromlist.moc"
