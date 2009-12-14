/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#ifndef LCHMSEARCHENGINE_H
#define LCHMSEARCHENGINE_H

#include <QDataStream>

// forward declaration
class LCHMFile;
class LCHMSearchEngineImpl;

class LCHMSearchEngine : public QObject
{
	Q_OBJECT
			
	public:
		LCHMSearchEngine();
		~LCHMSearchEngine();
		
		//! Loads the search index from the data stream \param stream. 
		//! The index should be previously saved with generateIndex().
		bool	loadIndex( QDataStream& stream );
		
		//! Generates the search index from the opened CHM file \param chmFile,
		//! and saves it to the data stream \param stream which should be writeable.
		//!
		//! To show the progress, this procedure emits a progressStep() signal periodically 
		//! with the value showing current progress in percentage (i.e. from 0 to 100)
		//! After signal emission, the following event processing function will be called:
		//!         qApp->processEvents( QEventLoop::ExcludeUserInputEvents )
		//!    to make sure the dialogs (if any) are properly updated.
		//!
		//! If \param progressDls is not null, it will be used to display progress.
		//! Returns true if the index has been generated and saved, or false if internal
		//! error occurs, or (most likely) the cancelIndexGeneration() slot has been called.
		bool	generateIndex( LCHMFile * chmFile, QDataStream& stream );
		
		//! Executes the search query. The \param query is a string like <i>"C++ language" class</i>,
		//! \param results is a pointer to QStringList, and \param limit limits the number of
		//! results in case the query is too generic (like \a "a" ).
		//! The \param chmFile is used to get the current encoding information.
		//! The return value is false only if the index is not generated, or if a closing quote character 
		//! is missing. Call hasIndex() to clarify. If search returns no results, the return value is 
		//! true, but the \param results list will be empty.
		//!
		//! Note that the function does not clear \param results before adding search results, so if you are
		//! not merging search results, make sure it's empty.
		bool	searchQuery ( const QString& query, QStringList * results, LCHMFile * chmFile, unsigned int limit = 100 );
		
		//! Returns true if a valid search index is present, and therefore search could be executed
		bool	hasIndex() const;
		
	signals:
		void	progressStep( int value, const QString& stepName );
		
	public slots:
		void	cancelIndexGeneration();
		
	private slots:
		void	updateProgress( int value, const QString& stepName );
		
	private:
		LCHMSearchEngineImpl * impl;
};

#endif
