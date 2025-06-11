QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    ldaphandler.cpp \
    main.cpp \
    ldapauthenticator.cpp \
    attributedetailsdialog.cpp \
    messageviewer.cpp

HEADERS += \
    ldapauthenticator.h \
    attributedetailsdialog.h \
    ldaphandler.h \
    messageviewer.h

FORMS += \
    ldapauthenticator.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

INCLUDEPATH += C:\msys64\mingw64\include
LIBS        += -LC:\msys64\mingw64\bin -lldap -llber

win32: RC_ICONS = $$PWD/icons/ldap_auth_icon.ico    # path to your .ico file :contentReference[oaicite:0]{index=0}

macx: ICON = $$PWD/icons/ldap_auth_icon.icns       # path to your .icns file :contentReference[oaicite:1]{index=1}

RESOURCES += \
    resources.qrc

