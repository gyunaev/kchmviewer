/***************************************************************************
 *   Copyright (C) 2004-2006 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#ifndef INCLUDE_KCHMNAVHISTORY_H
#define INCLUDE_KCHMNAVHISTORY_H

#include "forwarddeclarations.h"

class KCHMNavToolbar : public QToolBar
{
Q_OBJECT
public:
	KCHMNavToolbar( KCHMMainWindow *parent );
	~KCHMNavToolbar();

	void	invalidate();
	
	void	setHistoryMaxSize (unsigned int size) { m_historyMaxSize = size; }
	void	addNavigationHistory( const QString & url, int scrollpos );

public slots:
	void	navigateBack();
	void	navigateHome();
	void	navigateForward();

private:
	void	updateIconStatus();
	
	QToolButton	*	m_toolbarIconBackward;
	QToolButton	*	m_toolbarIconForward;

	//! History
	class KCHMUrlHistory
	{
		public:
			KCHMUrlHistory() { scrollbarpos = 0; }
			KCHMUrlHistory( const QString& _url, int _scrollbarpos )
			: url(_url), scrollbarpos(_scrollbarpos) {};
		
			const QString&  getUrl() const { return url; }
			int 			getScrollPosition() const { return scrollbarpos; }
			
		private:
			QString  	url;
			int 		scrollbarpos;
	};

	unsigned int	m_historyMaxSize;
	unsigned int	m_historyCurrentPos;
	
	QValueList<KCHMUrlHistory>				m_history;
};

#endif /* INCLUDE_KCHMNAVHISTORY_H */
