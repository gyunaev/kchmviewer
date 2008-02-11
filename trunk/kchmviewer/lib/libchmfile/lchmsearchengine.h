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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#ifndef KCHMSEARCHENGINE_H
#define KCHMSEARCHENGINE_H

#include "kde-qt.h"
#include "libchmfile.h"

namespace QtAs { class Index; };


class LCHMSearchEngine : public QObject
{
	Q_OBJECT
			
	public:
		LCHMSearchEngine();
		~LCHMSearchEngine();
		
		//! Loads the search index from the data stream \param stream. 
		//! The index should be previously saved with generateIndex().
		bool	loadIndex( QDataStream& stream );
		
		//! Generates the search index, and saves it to the data stream \param stream 
		//! which should be writeable.
		//!
		//! To show the progress, this procedure emits two signals.
		//!  * The progressSetup() will be emitted before the index generation started,
		//!    and sets up the maximum value the progressStep() will use;
		//!  * The progressStep() will be emitted periodically to update the progress. The 
		//!    value will be increased linearly until reaching the maximal value set in progressSetup().
		//!  * After signal emission, the following event processing function will be called:
		//!         qApp->processEvents( QEventLoop::ExcludeUserInputEvents )
		//!    to make sure the dialogs (if any) are properly updated.
		
		//! If \param progressDls is not null, it will be used to display progress.
		//! Returns true if the index has been generated and saved, or false if internal
		//! error occurs, or (most likely) the "Cancel" button has been pressed.
		bool	generateIndex( QDataStream& stream );
		
		//! Executes the search query. The \param query is a string like <i>"C++ language" class</i>,
		//! \param results is a pointer to empty QStringList, and \param limit limits the number of
		//! results in case the query is too generic (like \a "a" ).
		//! The return value is false only if the index is not generated or loaded. If search returns
		//! no results, the return value is true, but the \param results list will be empty.
		bool	searchQuery ( const QString& query, QStringList * results, unsigned int limit = 100 );
		
	signals:
		void	progressSetup( int max );
		void	progressStep( int value );
		
	public slots:
		void	cancelIndexGeneration();
		
	private:
		void	processEvents();

		// Used during the index generation
		QProgressDialog			*	m_progressDlg;
		QStringList 				m_keywordDocuments;
		QtAs::Index 			*	m_Index;
};

#endif
