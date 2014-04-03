#ifndef TREEITEM_INDEX_H
#define TREEITEM_INDEX_H

#include <QTreeWidgetItem>

class TreeItem_Index : public QTreeWidgetItem
{
	public:
		TreeItem_Index( QTreeWidgetItem* parent, QTreeWidgetItem* after, const QString& name, const QList<QUrl>& urls, bool seealso );
		TreeItem_Index( QTreeWidget* parent, QTreeWidgetItem* after, const QString& name, const QList<QUrl>& urls, bool seealso );

		QUrl		getUrl() const;
		bool		containstUrl( const QUrl& url ) const;

		// Overridden methods
		int 		columnCount () const;
		QVariant 	data ( int column, int role ) const;

	private:
		QString		m_name;
		QList<QUrl>	m_urls;
		bool		m_seealso;

};

#endif // TREEITEM_INDEX_H
