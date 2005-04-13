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

#ifndef KCHMSEARCHWINDOW_H
#define KCHMSEARCHWINDOW_H

#include <qwidget.h>
#include <qcombobox.h>
#include <qlistview.h>
#include <qcheckbox.h>

#include "kchmsettings.h"
#include "forwarddeclarations.h"
#include "xchmfile.h"


/**
@author Georgy Yunaev
*/
class KCHMSearchWindow : public QWidget
{
Q_OBJECT
public:
    KCHMSearchWindow ( QWidget * parent = 0, const char * name = 0, WFlags f = 0 );

	void	invalidate();
	void	restoreSettings (const KCHMSettings::search_saved_settings_t& settings);
	void	saveSettings (KCHMSettings::search_saved_settings_t& settings);

private slots:
	void 	onReturnPressed ();
	void	onDoubleClicked ( QListViewItem *, const QPoint &, int);
//	void	onCurrentChanged ( QListBoxItem *);

private:
	enum SearchType_t
	{
		TYPE_OR,	// just add
		TYPE_AND,	// remove others
		TYPE_PHRASE	// not supported yet
	};

	bool	searchQuery (const QString& query, KCHMSearchResults_t& results, unsigned int limit_results = 100);
	bool	searchWord (const QString& word, KCHMSearchResults_t& results, unsigned int limit_results, SearchType_t type);

	QString			m_lastQuery; // for 'Search in results' option
 	QComboBox 	*	m_searchQuery;
	QListView	*	m_searchList;
	QCheckBox	*	m_matchSimilarWords;
	QCheckBox	*	m_searchInResult;
};

#endif
