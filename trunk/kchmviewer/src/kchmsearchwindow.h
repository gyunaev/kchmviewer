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

#ifndef KCHMSEARCHWINDOW_H
#define KCHMSEARCHWINDOW_H

#include "kde-qt.h"
#include "kchmsettings.h"
#include "ui_tab_search.h"

#include "libchmsearchengine.h"


class KCHMSearchWindow : public QWidget, public Ui::TabSearch
{
	Q_OBJECT
	public:
		KCHMSearchWindow ( QWidget * parent = 0 );
	
		void	invalidate();
		void	restoreSettings (const KCHMSettings::search_saved_settings_t& settings);
		void	saveSettings( KCHMSettings::search_saved_settings_t& settings );
		void	execSearchQueryInGui( const QString& query );
		bool	searchQuery( const QString& query, QStringList * results );
		
	private slots:
		void	onContextMenuRequested ( const QPoint &point );
		void	onHelpClicked( const QString & );
		void 	onReturnPressed ();
		void	onDoubleClicked( QTreeWidgetItem * item, int );
		
		// For index generation
		void	onProgressStep( int value, const QString& stepName );
	
	private:
		bool	initSearchEngine();
		
	private:
		QMenu			* 	m_contextMenu;
		LCHMSearchEngine*	m_searchEngine;
		bool				m_searchEngineInitDone;
		
		// For index generation
		QProgressDialog *	m_genIndexProgress;
};

#endif
