#include "attributedetailsdialog.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QFrame>

AttributeDetailsDialog::AttributeDetailsDialog(const QString &attr, const QString &value, const QString &desc, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Attribute Details"));

    // Fix the dialog size (you can tweak these numbers as needed)
    const int dialogWidth = 405;
    const int dialogHeight = 250;
    setFixedSize(dialogWidth, dialogHeight);

    // Main layout
    auto layout = new QVBoxLayout(this); // NOSONAR

    // Attribute and value labels
    auto attrLabel = new QLabel(tr("Attribute: %1").arg(attr), this); // NOSONAR
    auto valueLabel = new QLabel(tr("Value: %1").arg(value), this); // NOSONAR
    layout->addWidget(attrLabel);
    layout->addWidget(valueLabel);

    // Description box
    auto descEdit = new QTextEdit(this); // NOSONAR
    descEdit->setPlainText(desc);
    descEdit->setReadOnly(true);
    descEdit->setFrameStyle(QFrame::Box | QFrame::Plain);
    descEdit->setLineWrapMode(QTextEdit::WidgetWidth);
    descEdit->setMinimumHeight(120);
    layout->addWidget(new QLabel(tr("Description:"), this));
    layout->addWidget(descEdit);

    // Close button
    auto closeButton = new QPushButton(tr("Close"), this); // NOSONAR
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(closeButton);

    layout->addStretch();
}
