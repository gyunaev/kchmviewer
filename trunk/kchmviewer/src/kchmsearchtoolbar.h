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

#ifndef KCHMSEARCHTOOLBAR_H
#define KCHMSEARCHTOOLBAR_H

#include "kde-qt.h"
#include "forwarddeclarations.h"

#include "libchmtextencoding.h"


class KCHMSearchAndViewToolbar : public QToolBar
{
	Q_OBJECT
	public:
		KCHMSearchAndViewToolbar (KCHMMainWindow *parent);
	
		void	setEnabled (bool enable);
		void	setChosenEncodingInMenu( const LCHMTextEncoding * encoding );
	
	private slots:
		void	onReturnPressed();
		void	onBtnPrevSearchResult();
		void	onBtnNextSearchResult();
		void	onAccelFocusSearchField();
		
		/*
		void	onBtnFontInc();
		void	onBtnFontDec();
		void	onBtnViewSource();
		void	onBtnAddBookmark();
		void	onBtnNextPageInToc();
		void	onBtnPrevPageInToc();
		*/
		void	onMenuActivated ( int id );
		
	private:
		void	search (bool forward);
		
		QMenu 				*	m_MenuView;
		QComboBox			*	m_findBox;
		QToolButton			*	m_buttonPrev;
		QToolButton			*	m_buttonNext;
		QToolButton			*	m_buttonFontInc;
		QToolButton			*	m_buttonFontDec;
		QToolButton			*	m_buttonViewSource;
		QToolButton			*	m_buttonAddBookmark;
		QToolButton			*	m_buttonNextPageInTOC;
		QToolButton			*	m_buttonPrevPageInTOC;
		QToolButton			*	m_buttonLocateInContent;
		
		int						m_checkedLanguageInMenu;
		int						m_checkedEncodingInMenu;
		
		int						m_menuShowFullscreenMenuID;
		int						m_menuShowContentWindowMenuID;
		

};


#endif
