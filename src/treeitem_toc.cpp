//FIXME: copyright
#include "ebook.h"
#include "mainwindow.h"
#include "treeitem_toc.h"

TreeItem_TOC::TreeItem_TOC(QTreeWidgetItem *parent, QTreeWidgetItem *after, const QString &name, const QUrl &url, int image)
	: QTreeWidgetItem( parent, after )
{
	m_name = name;
	m_url = url;
	m_image = image;
}

TreeItem_TOC::TreeItem_TOC(QTreeWidget *parent, QTreeWidgetItem *after, const QString &name, const QUrl &url, int image)
	: QTreeWidgetItem( parent, after )
{
	m_name = name;
	m_url = url;
	m_image = image;
}

QUrl TreeItem_TOC::getUrl() const
{
	return m_url;
}

bool TreeItem_TOC::containstUrl(const QUrl &url, bool ignorefragment ) const
{
	if ( ignorefragment )
	{
		// This appears to be a bug in Qt: the url.path() returns a proper path starting with /,
		// but m_url.path() returns a relative URL starting with no / - so we make sure both are.
		QString urlpath = url.path();
		QString ourpath = m_url.path();

		// Memory allocation-wise this must really suck :( however this code is rarely used,
		// and only for buggy epub/chms.
		if ( !urlpath.startsWith( '/') )
			urlpath.prepend( '/' );

		if ( !ourpath.startsWith( '/') )
			ourpath.prepend( '/' );

		return urlpath == ourpath;
	}
	else
	{
		return url == m_url;
	}
}

int TreeItem_TOC::columnCount() const
{
	return 1;
}

QVariant TreeItem_TOC::data(int column, int role) const
{
	int imagenum;

	if ( column != 0 )
		return QVariant();

	switch( role )
	{
		// Item name
		case Qt::DisplayRole:
			return m_name;

		// Item image
		case Qt::DecorationRole:
			if ( m_image != EBookTocEntry::IMAGE_NONE )
			{
				// If the item has children, we change the book image to "open book", or next image automatically
				if ( childCount() )
				{
					if ( isExpanded() )
						imagenum = (m_image == EBookTocEntry::IMAGE_AUTO) ? 1 : m_image;
					else
						imagenum = (m_image == EBookTocEntry::IMAGE_AUTO) ? 0 : m_image + 1;
				}
				else
					imagenum = (m_image == EBookTocEntry::IMAGE_AUTO) ? 10 : m_image;

				const QPixmap *pix = ::mainWindow->getEBookIconPixmap( (EBookTocEntry::Icon) imagenum );

				if ( !pix || pix->isNull() )
					abort();

				return *pix;
			}
			break;

		case Qt::ToolTipRole:
		case Qt::WhatsThisRole:
			return m_name;
	}

	return QVariant();
}
