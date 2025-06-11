# LDAP Authenticator

LDAP Authenticator is a cross-platform Qt application for authenticating users against an LDAP directory. It supports both Windows and Unix-like systems, providing a modern UI for login, attribute viewing, and password management.

## Features

- **LDAP Authentication**: Connect and authenticate using LDAP or LDAPS.
- **Attribute Viewer**: Browse user/group attributes in a tree view.
- **Password Management**: Change expired or first-login passwords.
- **CA Certificate Support**: Specify custom CA certificates for LDAPS.
- **Cross-Platform**: Builds and runs on Windows and Linux/macOS.

## Project Structure

```plaintext
CrossPlatform/
    src/
        ldapauthenticator.cpp
        ldapauthenticator.h
        ldaphandler.cpp
        ldaphandler.h
        LdapWorks.cpp
        LdapWorks.h
        attributedetailsdialog.cpp
        attributedetailsdialog.h
        messageviewer.cpp
        messageviewer.h
        main.cpp
        ldapauthenticator.ui
        userproperties.ui
        resources.qrc
        icons/
Windows/
    src/
        ldapauthenticator.cpp
        ldapauthenticator.h
        main.cpp
        ldapauthenticator.ui
        resourses.qrc
        icons/
```

## Building

### Prerequisites

- [Qt 6.x](https://www.qt.io/download)
- C++17 compatible compiler
- OpenLDAP development libraries (for Unix-like systems)
- MinGW-w64 (for Windows, if not using MSVC)
- CMake or qmake

### Windows

1. Open `Windows/src/LdapAuthenticator.pro` in Qt Creator.
2. Configure the project with your preferred kit (e.g., MinGW 64-bit).
3. Build and run.

### Cross-Platform (Linux/macOS/Windows)

1. Open `CrossPlatform/src/LdapAuthenticator.pro` in Qt Creator.
2. Ensure OpenLDAP development libraries are installed:
   - **Ubuntu**: `sudo apt install libldap2-dev`
   - **macOS**: `brew install openldap`
3. Build and run.

## Usage

1. Launch the application.
2. Enter the LDAP server host (e.g., `ldap.example.com`).
3. (Optional) Choose a CA certificate for LDAPS.
4. Enter your user principal name (e.g., `user@example.com`) and password.
5. Click **Login**.
6. View your LDAP attributes and groups.
7. Use **Change Password** if prompted or needed.

## Customization

- **Icons**: Place your custom icons in the `icons/` directory.
- **UI**: Modify `.ui` files with Qt Designer for layout changes.

## Troubleshooting

- Ensure the correct CA certificate is provided for LDAPS.
- For Windows, the app uses `wldap32`; for Unix-like systems, it uses OpenLDAP.
- Check your LDAP server logs for authentication errors.

## License

This project is provided under the MIT License.

---

**Maintainer:** [Mohammad-Hossein-Shahpoori]

For issues or contributions, please open an issue or pull request on GitHub.
