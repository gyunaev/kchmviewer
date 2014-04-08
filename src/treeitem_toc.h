#ifndef TREEITEM_TOC_H
#define TREEITEM_TOC_H

#include <QTreeWidgetItem>

class TreeItem_TOC : public QTreeWidgetItem
{
	public:
		TreeItem_TOC( QTreeWidgetItem* parent, QTreeWidgetItem* after, const QString& name, const QUrl& url, int image );
		TreeItem_TOC( QTreeWidget* parent, QTreeWidgetItem* after, const QString& name, const QUrl& url, int image );

		QUrl		getUrl() const;
		bool		containstUrl(const QUrl& url , bool ignorefragment ) const;

		// Overridden methods
		int 		columnCount () const;
		QVariant 	data ( int column, int role ) const;

	private:
		QString		m_name;
		QUrl		m_url;
		int 		m_image;
};

#endif // TREEITEM_TOC_H
