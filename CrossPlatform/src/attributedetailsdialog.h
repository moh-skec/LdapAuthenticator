#ifndef ATTRIBUTEDETAILSDIALOG_H
#define ATTRIBUTEDETAILSDIALOG_H

#include <QDialog>

class AttributeDetailsDialog : public QDialog
{
public:
    AttributeDetailsDialog(const QString &attr, const QString &value, const QString &desc, QWidget *parent = nullptr);
};

#endif // ATTRIBUTEDETAILSDIALOG_H
