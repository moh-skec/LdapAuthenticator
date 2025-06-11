#include "ldaphandler.h"

#include <QInputDialog>

LdapHandler::LdapHandler() = default;

void LdapHandler::setUri(const QString &uri)
{
    m_uri = uri;
}

void LdapHandler::setUpn(const QString &upn)
{
    m_upn = upn;
}

void LdapHandler::setUserDn(const QString &user_dn)
{
    m_user_dn = user_dn;
}

void LdapHandler::setCaFilePath(const QString &caFilePath)
{
    m_caFilePath = caFilePath;
    ldap_set_option(nullptr, LDAP_OPT_X_TLS_CACERTFILE, m_caFilePath.toStdString().c_str());
}

QString LdapHandler::getUri() const
{
    return m_uri;
}

QString LdapHandler::getUpn() const
{
    return m_upn;
}

QString LdapHandler::getUserDn() const
{
    return m_user_dn;
}

QString LdapHandler::getCaFilePath() const
{
    return m_caFilePath;
}

LDAP *LdapHandler::getLdapHandle()
{
    return m_ld;
}

MessageViewer &LdapHandler::getMessageViewer()
{
    return m_messageViewer;
}

int LdapHandler::ldapInit()
{
    // Initialize LDAP library
    if (int rc = ldap_initialize(&m_ld, m_uri.toStdString().c_str());
        rc != LDAP_SUCCESS)
    {
        m_messageViewer.showError("Initialization Error",
                                  QString("Could not initialize LDAP: %1").arg(ldap_err2string(rc)));
        return rc;
    }

    // Set protocol version
    int version = LDAP_VERSION3;
    ldap_set_option(m_ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Disable referrals
    auto referrals = LDAP_OPT_OFF;
    ldap_set_option(m_ld, LDAP_OPT_REFERRALS, &referrals);

    return LDAP_SUCCESS;
}

int LdapHandler::ldapConnect()
{
    m_ld = nullptr;
    ldap_set_option(nullptr, LDAP_OPT_X_TLS_CACERTFILE, m_caFilePath.toStdString().c_str());

    // Initialize LDAP connection
    if (int rc = ldap_initialize(&m_ld, m_uri.toStdString().c_str());
        rc != LDAP_SUCCESS)
    {
        m_messageViewer.showError("Connection Error",
                                  QString("Could not initialize LDAP: %1").arg(ldap_err2string(rc)));
        return rc;
    }

    // Set protocol version
    int version = LDAP_VERSION3;
    ldap_set_option(m_ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Disable referrals
    auto referrals = LDAP_OPT_OFF;
    ldap_set_option(m_ld, LDAP_OPT_REFERRALS, &referrals);
    // Connect (optional for OpenLDAP, but explicit here)
    if (!m_ld)
    {
        m_messageViewer.showError("Connection Error", "LDAP handle is not initialized.");
        return LDAP_PARAM_ERROR;
    }
    int rc = ldap_connect(m_ld);
    if (rc != LDAP_SUCCESS)
    {
        m_messageViewer.showError("Connect Error",
                                  QString("ldap_connect failed to %1: %2").arg(m_uri, ldap_err2string(rc)));
    }

    return rc;
}

int LdapHandler::ldapBind(const QString &password)
{
    // Prepare credentials
    QByteArray pwUtf8 = password.toUtf8();
    struct berval cred;
    cred.bv_val = pwUtf8.data();
    cred.bv_len = static_cast<ber_len_t>(pwUtf8.size());

    int rc = ldap_sasl_bind_s(m_ld,
                              m_upn.toUtf8().constData(),
                              LDAP_SASL_SIMPLE,
                              &cred,
                              nullptr, nullptr, nullptr);
    if (rc != LDAP_SUCCESS)
        m_messageViewer.showError("Bind Error",
                                  QString("Could not bind to LDAP as %1: %2").arg(m_upn, ldap_err2string(rc)));

    return rc;
}

int LdapHandler::ldapUnbind()
{
    if (m_ld)
    {
        if (int rc = ldap_unbind_ext_s(m_ld, nullptr, nullptr);
            rc != LDAP_SUCCESS)
            m_messageViewer.showError("Unbind Error",
                                      QString("Could not unbind from LDAP: %1").arg(ldap_err2string(rc)));

        m_ld = nullptr;
    }
    return LDAP_SUCCESS;
}

int LdapHandler::ldapSearch(const QString &base_dn, int scope, const QString &filter, const QVector<QString> &attrs, LDAPMessage **msg)
{
    // Prepare attributes for search
    QVector<char *> attrList;
    for (const auto &attr : attrs)
        attrList.append(attr.toUtf8().data());
    attrList.append(nullptr); // Null-terminate the list

    // Perform the LDAP search operation
    int rc = ldap_search_ext_s(m_ld, base_dn.toUtf8().constData(), scope,
                               filter.toUtf8().constData(), attrList.data(), 0, nullptr, nullptr, nullptr, 0, msg);
    if (rc != LDAP_SUCCESS)
        m_messageViewer.showError("Search Error",
                                  QString("Could not perform LDAP search for %1: %2").arg(filter, ldap_err2string(rc)));

    return rc;
}

int LdapHandler::ldapModify(const QVector<std::tuple<int, QString, QString>> &modifications)
{
    if (modifications.isEmpty())
        return LDAP_PARAM_ERROR;

    // Storage for the actual name/value bytes:
    QVector<QByteArray> nameBlobs;
    QVector<QByteArray> valueBlobs;
    // Storage for the null-terminated “char*” lists:
    QVector<QVector<char *>> valueLists;
    // Storage for the LDAPMod structs themselves:
    QVector<LDAPMod> modStructs;

    // Reserve space so we don’t reallocate and invalidate pointers:
    const qsizetype n = modifications.size();
    nameBlobs.reserve(n);
    valueBlobs.reserve(n);
    valueLists.reserve(n);
    modStructs.reserve(n + 1);

    // Build each LDAPMod *and* its char*[] counterpart:
    for (auto const &[modOp, attrName, attrValue] : modifications)
    {
        nameBlobs.push_back(attrName.toUtf8());
        valueBlobs.push_back(attrValue.toUtf8());

        // Build the null-terminated list of C-strings for this mod
        valueLists.push_back({valueBlobs.back().data(), nullptr});

        LDAPMod m = {modOp, nameBlobs.back().data(), {.modv_strvals = valueLists.back().data()}};

        modStructs.push_back(m);
    }

    // Now build an array of pointers to each LDAPMod:
    QVector<LDAPMod *> mods;
    mods.reserve(n + 1);
    for (LDAPMod &mod : modStructs)
        mods.append(&mod);
    mods.append(nullptr);

    // Finally call LDAP:
    int rc = ldap_modify_ext_s(
        m_ld,
        m_user_dn.toUtf8().constData(),
        mods.data(),
        nullptr,
        nullptr);

    if (rc != LDAP_SUCCESS)
        m_messageViewer.showError(
            "Modification Error",
            QString("Could not modify LDAP entry: %1").arg(ldap_err2string(rc)));

    return rc;
}

int LdapHandler::ldapPasswd(QWidget *parent)
{
    ldapConnect();

    bool ok = false;
    QString oldPw = QInputDialog::getText(
        parent, QString("Enter Password"), QString("Enter old password:"),
        QLineEdit::Password, QString(), &ok);
    if (!ok || oldPw.isEmpty())
        return LDAP_AUTH_METHOD_NOT_SUPPORTED;

    QString newPw = QInputDialog::getText(
        parent, QString("Enter Password"), QString("Enter new password:"),
        QLineEdit::Password, QString(), &ok);
    if (!ok || newPw.isEmpty())
    {
        m_messageViewer.showError(QString("Password Change"), QString("Password change canceled"));
        return LDAP_AUTH_METHOD_NOT_SUPPORTED;
    }
    if (QString confirm = QInputDialog::getText(parent, QString("Confirm Password"), QString("Re-enter new password:"),
                                                QLineEdit::Password, QString(), &ok);
        !ok || newPw != confirm)
    {
        m_messageViewer.showError(QString("Password Change"), QString("Passwords did not match"));
        return LDAP_AUTH_METHOD_NOT_SUPPORTED;
    }

    if (int rc = ldapBind(oldPw);
        rc != LDAP_SUCCESS)
    {
        m_messageViewer.showError("Password Change Failed",
                                  QString("Failed to bind with old password: %1").arg(ldap_err2string(rc)));
        return LDAP_AUTH_METHOD_NOT_SUPPORTED;
    }

    // Prepare old and new passwords in UTF-16LE, quoted
    auto toQuotedUtf16 = [](const QString &pw)
    {
        QString quoted = "\"" + pw + "\"";
        const ushort *u16 = quoted.utf16();
        qsizetype len = quoted.size();
        return QVector<std::byte>(
            reinterpret_cast<const std::byte *>(u16),
            reinterpret_cast<const std::byte *>(u16 + len));
    };

    QVector<std::byte> oldPwdBytes = toQuotedUtf16(oldPw);
    QVector<std::byte> newPwdBytes = toQuotedUtf16(newPw);

    berval oldPwdBv{static_cast<ber_len_t>(oldPwdBytes.size()), static_cast<char *>(static_cast<void *>(oldPwdBytes.data()))};
    berval newPwdBv{static_cast<ber_len_t>(newPwdBytes.size()), static_cast<char *>(static_cast<void *>(newPwdBytes.data()))};

    QByteArray unicodePwdStr("unicodePwd");
    QVector<berval *> delVals = {&oldPwdBv, nullptr};
    QVector<berval *> addVals = {&newPwdBv, nullptr};

    LDAPMod delMod = {LDAP_MOD_DELETE | LDAP_MOD_BVALUES, unicodePwdStr.data(), {.modv_bvals = delVals.data()}};
    LDAPMod addMod = {LDAP_MOD_ADD | LDAP_MOD_BVALUES, unicodePwdStr.data(), {.modv_bvals = addVals.data()}};

    QVector<LDAPMod *> mods = {&delMod, &addMod, nullptr};

    // Modify password
    int rc = ldap_modify_ext_s(
        m_ld, 
        m_user_dn.toStdString().c_str(), 
        mods.data(), 
        nullptr, 
        nullptr);

    if (rc != LDAP_SUCCESS)
        m_messageViewer.showError("Password Change Failed",
                                  QString("Failed to modify LDAP entry: %1").arg(ldap_err2string(rc)));
    else
        m_messageViewer.showInfo("Success",
                                 "Password changed successfully, you can logon using your new password.");

    return rc;
}

QString LdapHandler::fetchSchemaNamingContext()
{
    static QString schemaDN;
    if (!schemaDN.isEmpty())
        return schemaDN;

    QString filter = "(objectClass=*)";
    QVector<QString> attrs = {"schemaNamingContext"};

    LDAPMessage *dseMsg = nullptr;
    if (int rc = ldapSearch("", LDAP_SCOPE_BASE, filter, attrs, &dseMsg);
        rc != LDAP_SUCCESS || !dseMsg)
    {
        if (dseMsg)
            ldap_msgfree(dseMsg);
        return {};
    }

    BerElement *ber = nullptr;
    if (char *attr = ldap_first_attribute(m_ld, dseMsg, &ber))
    {
        berval **vals = ldap_get_values_len(m_ld, dseMsg, attr);
        if (vals && vals[0])
            schemaDN = QString::fromUtf8(vals[0]->bv_val, vals[0]->bv_len);
        ldap_value_free_len(vals);
        ldap_memfree(attr);
    }
    if (ber)
        ber_free(ber, 0);
    ldap_msgfree(dseMsg);

    return schemaDN;
}

bool LdapHandler::fetchAttributeDescriptions(const QString &subschemaDN, const QSet<QString> &attrNames, QVariantMap &descMap)
{
    QString filter = "(|";
    for (const QString &name : attrNames)
        filter += "(lDAPDisplayName=" + name + ")";
    filter += ")";

    QVector<QString> schemaAttrs = {"lDAPDisplayName", "adminDescription", nullptr};

    LDAPMessage *schemaMsg = nullptr;
    if (int rc = ldapSearch(subschemaDN, LDAP_SCOPE_ONELEVEL, filter, schemaAttrs, &schemaMsg);
        rc != LDAP_SUCCESS)
    {
        m_messageViewer.showError("Schema Search Failed", QString("Targeted schema search failed: %1").arg(ldap_err2string(rc)));
        if (schemaMsg)
            ldap_msgfree(schemaMsg);
        return false;
    }

    for (LDAPMessage *e = ldap_first_entry(m_ld, schemaMsg);
         e != nullptr;
         e = ldap_next_entry(m_ld, e))
    {
        BerElement *ber2 = nullptr;
        QString name;
        QString desc;
        for (char *a = ldap_first_attribute(m_ld, e, &ber2);
             a != nullptr;
             a = ldap_next_attribute(m_ld, e, ber2))
        {
            berval **vals = ldap_get_values_len(m_ld, e, a);
            if (!vals)
            {
                ldap_memfree(a);
                continue;
            }

            QString v = QString::fromUtf8(vals[0]->bv_val, vals[0]->bv_len);
            if (QString(a).compare("lDAPDisplayName", Qt::CaseInsensitive) == 0)
                name = v.toLower();
            else if (QString(a).compare("adminDescription", Qt::CaseInsensitive) == 0)
                desc = v;
            ldap_value_free_len(vals);
            ldap_memfree(a);
        }
        if (ber2)
            ber_free(ber2, 0);
        if (!name.isEmpty())
            descMap.insert(name, desc.isEmpty() ? QString("<no description>") : desc);
    }
    ldap_msgfree(schemaMsg);
    return true;
}
