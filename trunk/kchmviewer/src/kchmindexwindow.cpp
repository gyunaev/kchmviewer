/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
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

#include <qlayout.h>
#include <qheader.h>

#include "kchmmainwindow.h"
#include "kchmindexwindow.h"
#include "xchmfile.h"

KCHMIndexWindow::KCHMIndexWindow ( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_indexFinder = new QLineEdit (this);
	m_indexFinder->setFocus();
	
	m_indexList = new QListView (this);
	m_indexList->addColumn( "idx" ); // it is hidden anyway
	m_indexList->header()->hide();
	
	layout->addWidget (m_indexFinder);
	layout->addSpacing (10);
	layout->addWidget (m_indexList);
	
	connect( m_indexFinder, SIGNAL( textChanged (const QString &) ), this, SLOT( onTextChanged(const QString &) ) );
	
	connect( m_indexFinder, SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_indexList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );
	
	m_indexListFilled = false;
	m_lastSelectedItem = 0;
}

void KCHMIndexWindow::onTextChanged ( const QString & newvalue)
{
	m_lastSelectedItem = m_indexList->findItem (newvalue, 0, Qt::BeginsWith);
	
	if ( m_lastSelectedItem )
	{
		m_indexList->ensureItemVisible (m_lastSelectedItem);
		m_indexList->setCurrentItem (m_lastSelectedItem);
	}
}

void KCHMIndexWindow::showEvent( QShowEvent * )
{
	if ( !::mainWindow->getChmFile() || m_indexListFilled )
		return;

	m_indexListFilled = true;
	::mainWindow->getChmFile()->ParseAndFillIndex (m_indexList);
	
	if ( m_indexList->childCount() == 0 )
		qWarning ("CHM index present but is empty; wrong parsing?");
}

void KCHMIndexWindow::onReturnPressed( )
{
	emit ::mainWindow->onTreeClicked ( m_lastSelectedItem );
}


void KCHMIndexWindow::invalidate( )
{
	m_indexList->clear();
	m_indexListFilled = false;
}

void KCHMIndexWindow::onDoubleClicked( QListViewItem *item, const QPoint &, int )
{
	if ( !item )
		return;
	
	KCHMMainTreeViewItem * treeitem = (KCHMMainTreeViewItem*) item;
	
	::mainWindow->openPage (treeitem->getUrl(), true);
}
