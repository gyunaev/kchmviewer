#if 0



QMenu * ViewWindow_QtWebKit::createPopupMenu( const QPoint & pos )
{
	QMenu * menu = getContextMenu( anchorAt( pos ), this );
	menu->exec( pos );

	return 0;
}


void ViewWindow_QtWebKit::find(const QString & text, int flags)
{
	m_searchText = text;
	m_flags = flags;
	
	find( false, false );
}

void ViewWindow_QtWebKit::onFindNext()
{
	find( true, false );
}

void ViewWindow_QtWebKit::onFindPrevious()
{
	find( false, true );
}

void ViewWindow::find( bool , bool backward )
{
	QWebPage::FindFlags flags = QWebPage::FindWrapsAroundDocument;
	
	if ( backward )
		flags |= QWebPage::FindBackward;
	
	if ( m_flags & SEARCH_CASESENSITIVE )
		flags |= QWebPage::FindCaseSensitively;
	
	if ( findText( m_searchText, flags ) )
		::mainWindow->viewWindowMgr()->indicateFindResultStatus( ViewWindowMgr::SearchResultFound );
	else
		::mainWindow->viewWindowMgr()->indicateFindResultStatus( ViewWindowMgr::SearchResultNotFound );
}




#endif // #if defined (QT_WEBKIT_LIB)

