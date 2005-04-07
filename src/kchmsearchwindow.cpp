
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
#include <qlabel.h>
#include <qlineedit.h>
#include <qstatusbar.h>
#include <qmessagebox.h>
#include <qregexp.h>

#include "kchmmainwindow.h"
#include "kchmsearchwindow.h"
#include "kchmexternalsearch.h"
#include "kchmconfig.h"
#include "xchmfile.h"

#if defined (ENABLE_EXTERNAL_SEARCH)
	#include "kchmexternalsearchengine.h"
#endif

KCHMSearchWindow::KCHMSearchWindow( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_searchQuery = new QComboBox (TRUE, this);
	m_searchQuery->setFocus();
	m_searchQuery->setMaxCount (10);
	
	m_searchList = new QListView (this);
	m_searchList->addColumn( "Title" );
	m_searchList->addColumn( "Location" );
		
	connect( (m_searchQuery->lineEdit()), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_searchList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );

	m_matchSimilarWords = new QCheckBox (this);
	m_matchSimilarWords->setText (tr("Match similar words"));

#if defined (ENABLE_EXTERNAL_SEARCH)
	m_useExternalSearch = new QCheckBox (this);
	m_useExternalSearch->setText (tr("<b>Use external search</b>"));

	connect( m_useExternalSearch, SIGNAL( stateChanged ( int ) ), this, SLOT( onExternalSearchBoxStateChanged ( int ) ) );
	m_externalSearch = 0;
#endif

//FIXME: search in results	
//	m_searchInResult = new QCheckBox (this);
//	m_searchInResult->setText (tr("Search in result"));
	
	m_searchTitles = new QCheckBox (this);
	m_searchTitles->setText (tr("Search only titles"));

	layout->addWidget (new QLabel (tr("Type in word(s) to search for:"), this));	
	layout->addWidget (m_searchQuery);
	layout->addSpacing (10);
	layout->addWidget (m_searchList);
#if defined (ENABLE_EXTERNAL_SEARCH)
	layout->addWidget (m_useExternalSearch);
#endif
	layout->addWidget (m_matchSimilarWords);
//	layout->addWidget (m_searchInResult);
	layout->addWidget (m_searchTitles);
}

void KCHMSearchWindow::invalidate( )
{
	m_searchList->clear();
	m_searchQuery->clear();
	m_searchQuery->lineEdit()->clear();
}

void KCHMSearchWindow::onReturnPressed( )
{
	CHMSearchResults h1;
	QString text = m_searchQuery->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;

	m_searchList->clear();

	QStringList tokens = QStringList::split (QRegExp("\\s+"), text);
	
	if ( tokens.size() < 1 )
		abort();
	
	if ( !::mainWindow->getChmFile()->IndexSearch (tokens[0], !m_matchSimilarWords->isChecked(), m_searchTitles->isChecked(), &h1) )
	{
		::mainWindow->showInStatusBar( tr("Search failed") );
		return;
	}
//FIXME: search double words
//FIXME: search in our own database
/*
	for ( unsigned int j = 1; j < tokens.size(); j++ )
	{
		CHMSearchResults h2, tmp;
		
		::mainWindow->getChmFile()->IndexSearch (tokens[j], !m_matchSimilarWords->isChecked(), m_searchTitles->isChecked(), &h2);

		if ( !h2.isEmpty() )
		{
			for ( CHMSearchResults::iterator it = h2.begin(); it != h2.end(); it++ )
				if ( h1.find(it->first) != h1.end() )
					tmp[it->first] = it->second;
                h1 = tmp;
		}
		else
		{
			h1.clear();
			break;
		}
	}
*/
/*	if ( m_searchTitles->isChecked() && h1.isEmpty() )
	{
		PopulateList (_tcl->GetRootItem(), sr, !_partial->IsChecked());
        m_searchList->triggerUpdate();
        return;
	}
*/
	if ( !h1.empty() )
	{
		for ( CHMSearchResults::iterator it = h1.begin(); it != h1.end(); it++ )
		{
			new KCMSearchTreeViewItem (m_searchList, it.data(), it.key(), it.key());
		}
	} 
}

void KCHMSearchWindow::onDoubleClicked( QListViewItem *item, const QPoint &, int)
{
	if ( !item )
		return;
	
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
	
	::mainWindow->openPage(treeitem->getUrl(), false);
}

void KCHMSearchWindow::restoreSettings( const KCHMSettings::search_saved_settings_t & settings )
{
	for ( unsigned int i = 0; i < settings.size(); i++ )
		m_searchQuery->insertItem (settings[i]);
}

void KCHMSearchWindow::saveSettings( KCHMSettings::search_saved_settings_t & settings )
{
	for ( int i = 0; i < m_searchQuery->count(); i++ )
		settings.push_back (m_searchQuery->text(i));
}

#if defined (ENABLE_EXTERNAL_SEARCH)

void KCHMSearchWindow::onExternalSearchBoxStateChanged( int state )
{
	if ( state != QButton::On )
		return;

	if ( !m_externalSearch )
		m_externalSearch = new KCHMExternalSearch (new KCHMExternalSearchEngine);

	if ( !m_externalSearch->hasSearchIndex() )
	{
   		if ( QMessageBox::question(this,
			tr ("%1 - need to create the index") . arg(APP_NAME),
           	tr ("This file has not been indexed yet.\nExternal search engine needs to create the index on this file.\n\nDo you want to proceed?"),
           	tr("&Yes"), tr("&No"),
           	QString::null, 0, 1 ) == 0 )
		{
			if ( m_externalSearch->createSearchIndex() )
				return;
		}

		m_useExternalSearch->setChecked (false);
	}
}
#endif
