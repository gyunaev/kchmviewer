#
# Option:
# -DQT4_ONLY=ON - build with Qt4, not use KDE
# -DQT5_ONLY=ON - build with Qt5, not use KDE
################################################

cmake_minimum_required(VERSION 3.0)

# Project name
project(kchmviewer)

# Init cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

# Necessary packages
# libzip
find_package(libzip REQUIRED)
if (${QT4_ONLY})
    find_package(Qt4 REQUIRED QtCore QtDBus QtNetwork QtWebKit QtGui QtXml)
elseif (${QT5_ONLY})
    find_package(Qt5 REQUIRED Core DBus Network PrintSupport WebKit WebKitWidgets Widgets Xml)
else ()
    find_package(KDE4 REQUIRED)
    add_definitions(${KDE4_DEFINITIONS})
    add_definitions(-DUSE_KDE)
    include_directories(${KDE4_INCLUDES})
endif ()

# Run in those subdirectories
add_subdirectory(lib/libchm)
add_subdirectory(lib/libebook)
add_subdirectory(src)
add_subdirectory(po)
add_subdirectory(packages)
