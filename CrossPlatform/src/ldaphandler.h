#ifndef LDAPHANDLER_H
#define LDAPHANDLER_H

#include "messageviewer.h"

#include <ldap.h>

class LdapHandler
{
public:
    LdapHandler();

    void setUri(const QString &uri);
    void setUpn(const QString &upn);
    void setUserDn(const QString &user_dn);
    void setCaFilePath(const QString &caFilePath);

    QString getUri() const;
    QString getUpn() const;
    QString getUserDn() const;
    QString getCaFilePath() const;

    LDAP *getLdapHandle();
    MessageViewer &getMessageViewer();

    int ldapInit();
    int ldapConnect();
    int ldapBind(const QString &password);
    int ldapSearch(const QString &base_dn, int scope, const QString &filter, const QVector<QString> &attrs, LDAPMessage **msg);
    int ldapUnbind();
    
    int ldapModify(const QVector<std::tuple<int, QString, QString>> &modifications);
    int ldapPasswd(QWidget *parent);

    QString fetchSchemaNamingContext();
    bool fetchAttributeDescriptions(const QString &subschemaDN, const QSet<QString> &attrNames, QVariantMap &descMap);

protected:
private:
    LDAP *m_ld;
    QString m_uri;
    QString m_upn;
    QString m_user_dn;
    QString m_caFilePath;

    MessageViewer m_messageViewer;
};

#endif // LDAPHANDLER_H
