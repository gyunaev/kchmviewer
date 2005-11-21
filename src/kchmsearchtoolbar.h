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
#ifndef KCHMSEARCHTOOLBAR_H
#define KCHMSEARCHTOOLBAR_H

#include <qtoolbar.h>
#include <qstring.h>
#include <qmap.h>

#include "forwarddeclarations.h"

#include "kchmtextencoding.h"

/**
@author Georgy Yunaev
*/
class KCHMSearchAndViewToolbar : public QToolBar
{
Q_OBJECT
public:
    KCHMSearchAndViewToolbar (KCHMMainWindow *parent);

	void	setEnabled (bool enable);
	void	setChosenEncodingInMenu( const KCHMTextEncoding::text_encoding_t * enc );

private slots:
	void	onReturnPressed();
	void	onBtnPrevSearchResult();
	void	onBtnNextSearchResult();

	void	onBtnFontInc();
	void	onBtnFontDec();
	void	onBtnViewSource();
	void	onBtnAddBookmark();
	void	onBtnNextPageInToc();
	void	onBtnPrevPageInToc();
	void	onMenuActivated ( int id );
	
private:
	void	search (bool forward);
	
	QComboBox			*	m_findBox;
	QToolButton			*	m_buttonPrev;
	QToolButton			*	m_buttonNext;
	QToolButton			*	m_buttonFontInc;
	QToolButton			*	m_buttonFontDec;
	QToolButton			*	m_buttonViewSource;
	QToolButton			*	m_buttonAddBookmark;
	QToolButton			*	m_buttonNextPageInTOC;
	QToolButton			*	m_buttonPrevPageInTOC;
	
	const KCHMTextEncoding::text_encoding_t * m_checkedEncodingInMenu;
};

#endif
