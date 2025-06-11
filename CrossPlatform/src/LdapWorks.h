#pragma once
#include <QObject>
#include <QString>
#include <QTreeWidget>
#include <ldap.h>

class LdapWorks
{
public:
    LdapWorks();
    ~LdapWorks();

    bool connect(const QString &host, int port, const QString &caFilePath, QWidget *parent);
    bool authenticate(const QString &userPN, const QString &password, QWidget *parent, QString &upn, QString &user_dn, QTreeWidget *treeWidget);
    bool changePassword(const std::string &uri, const QString &userPN, const QString &user_dn, QWidget *parent);

private:
    LDAP *m_ld;
    // ...other helpers and members as needed...
};
