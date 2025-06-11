// LdapAuthenticator.h
#ifndef LDAPAUTHENTICATOR_H
#define LDAPAUTHENTICATOR_H

#include <QMainWindow>
#include <QSettings>
#include <QTreeWidgetItem>

#include "ldaphandler.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class LdapAuthenticator;
}
QT_END_NAMESPACE

class LdapAuthenticator : public QMainWindow, public LdapHandler
{
    Q_OBJECT

public:
    LdapAuthenticator(QWidget *parent = nullptr);
    ~LdapAuthenticator();

    static QString upnToBaseDN(const QString &upn);

private slots:
    void onCAClicked();

    void togglePasswordVisibility();
    
    void onLoginClicked();

    void onLogoutClicked();
    
    void onChangePasswordClicked();
    
    void onTreeWidgetAttributesItemDoubleClicked(const QTreeWidgetItem *item, int column);


private:
    void initializeUi();

    void showHomeAndGrow();
    void restoreOriginalSize();

    bool authenticate(const QString &userSam, const QString &password);
    bool searchAndDisplay(const QString &sAMAccountName);
    bool displayLdapProperties(LDAPMessage *msg);

    void collectAttributesAndCheckPassword(LDAPMessage *msg, QSet<QString> &attrNames, bool &mustPwdChange, QString &newExpireStr);
    void handleAttributeValue(const QString &attribute, const QString &value, bool &mustPwdChange);
    bool handlePasswordChange(const QString &newExpireStr);
    void populateAttributeTree(LDAPMessage *msg, const QVariantMap &descMap, const QString &newExpireStr);

    static constexpr auto KEY_HOST = "host";
    static constexpr auto KEY_CA_FILE_PATH = "caFilePath";
    static constexpr auto KEY_USERPN = "userPN";

    static constexpr auto KEY_SUBSCHEMA_DN = "subschemaDN";
    static constexpr auto KEY_DESC_MAP = "descMap";

    enum
    {
        DescriptionRole = Qt::UserRole + 1
    };


    void loadSettings();
    void saveSettings();

    Ui::LdapAuthenticator *ui; // RAII for UI

    int m_port;

    QSettings m_settings; // application settings
    
    bool m_passwordVisible;

    QRect m_originalGeometry;
};

#endif // LDAPAUTHENTICATOR_H
