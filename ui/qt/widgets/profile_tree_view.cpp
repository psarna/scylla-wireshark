/* profile_tree_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/url_link_delegate.h>
#include <ui/qt/models/profile_model.h>
#include <ui/qt/widgets/profile_tree_view.h>

#include <QDesktopServices>
#include <QDir>
#include <QItemDelegate>
#include <QLineEdit>
#include <QUrl>

ProfileUrlLinkDelegate::ProfileUrlLinkDelegate(QObject *parent) : UrlLinkDelegate (parent) {}

void ProfileUrlLinkDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    if ( index.column() != ProfileModel::COL_PATH )
        QStyledItemDelegate::paint(painter, option, index);

    /* Only paint links for valid paths */
    if ( index.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() )
        UrlLinkDelegate::paint(painter, option, index);
    else
        QStyledItemDelegate::paint(painter, option, index);

}

ProfileTreeEditDelegate::ProfileTreeEditDelegate(QWidget *parent) : QItemDelegate(parent) {}

void ProfileTreeEditDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (qobject_cast<QLineEdit *>(editor))
    {
        QLineEdit * ql = qobject_cast<QLineEdit *>(editor);
        ql->setText(index.data().toString());
    }
}

ProfileTreeView::ProfileTreeView(QWidget *parent) :
    QTreeView (parent)
{
    setItemDelegateForColumn(ProfileModel::COL_NAME, new ProfileTreeEditDelegate());
    setItemDelegateForColumn(ProfileModel::COL_PATH, new ProfileUrlLinkDelegate());

    resizeColumnToContents(ProfileModel::COL_NAME);

    connect(this, &QAbstractItemView::clicked, this, &ProfileTreeView::clicked);
}

void ProfileTreeView::selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    if ( selected.count() == 0 && deselected.count() > 0 )
    {
        QItemSelection newSelection;
        newSelection << deselected.at(0);
        selectionModel()->select(newSelection, QItemSelectionModel::ClearAndSelect);
    }
    else if ( selected.count() > 1 )
    {
        /* If more then one item is selected, only accept the new item, deselect everything else */
        QSet<QItemSelectionRange> intersection = selected.toSet().intersect(deselected.toSet());
        QItemSelection newSelection;
        newSelection << intersection.toList().at(0);
        selectionModel()->select(newSelection, QItemSelectionModel::ClearAndSelect);
    }
    else
        QTreeView::selectionChanged(selected, deselected);
}

void ProfileTreeView::currentChanged(const QModelIndex &, const QModelIndex &)
{
    emit currentItemChanged();
}

void ProfileTreeView::clicked(const QModelIndex &index)
{
    if ( !index.isValid() || index.column() != ProfileModel::COL_PATH )
        return;

    /* Only paint links for valid paths */
    if ( index.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() )
    {
        QString path = QDir::toNativeSeparators(index.data().toString());
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    }
}

void ProfileTreeView::selectRow(int row)
{
    if ( row < 0 )
        return;

    setCurrentIndex(model()->index(row, 0));

    selectionModel()->select(
                QItemSelection(model()->index(row, 0), model()->index(row, model()->columnCount() -1)),
                QItemSelectionModel::ClearAndSelect);

}
