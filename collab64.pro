
#your Ida SDK location either relative to collabreate/trunk
#or absolute
win32:SDK = ../../..
unix:SDK = ../../..

OBJECTS_DIR = p64

#Need to change the following to your Ida install location
linux-g++:IDA_APP = /opt/ida-$$(IDA_VERSION)
macx:IDA_APP = "/Applications/IDA\ Pro\ $$(IDA_VERSION)/idaq.app/Contents"

#Need to change the following to your Qt install location
macx:QT_LOC = /usr/local/qt/lib
macx:QT_TAIL = .framework/Versions/4/Headers
#create our own list of Qt modules
macx:MODS = QtGui QtCore

defineReplace(makeIncludes) {
   variable = $$1
   modules = $$eval($$variable)
   dirs =   
   for(module, modules) {
      dir = $${QT_LOC}/$${module}$${QT_TAIL}
      dirs += $$dir
   }
   return($$dirs)
}

TEMPLATE = lib

CONFIG += qt dll

win32-msvc2008:INCLUDEPATH += $${SDK}/include
linux-g++|macx|win32-g++:INCLUDEPATH += $${SDK}/include

DESTDIR = $${SDK}/bin/plugins

DEFINES += __IDP__ __QT__ __EA64__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32:DEFINES += _CRT_SECURE_NO_WARNINGS
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32-msvc2008: {
   exists( $${SDK}/lib/vc.w64/ida.lib ) {
      LIBS += $${SDK}/lib/vc.w64/ida.lib
   } else {
      LIBS += $${SDK}/lib/x86_win_vc_64/ida.lib
   }
}
win32:LIBS += ws2_32.lib
linux-g++:LIBS += -L$${IDA_APP} -lida64 -lpthread
macx:LIBS += -L$${IDA_APP}/MacOs -lida64 -lpthread

#don't let qmake force search for any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT = 

macx:QMAKE_INCDIR = $$makeIncludes(MODS)
#use Idas QT LIBS unfortuantely this is also added as an include directory
#macx:QMAKE_LIBDIR_QT = $${IDA_APP}/Frameworks
#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -F$${QT_LOC}

linux-g++|macx: {
   QMAKE_CXXFLAGS += -m32
   QMAKE_CFLAGS += -m32
   QMAKE_LFLAGS += -m32
}

macx:QMAKE_LFLAGS += -F$${IDA_APP}/Frameworks
macx:QMAKE_LIBDIR_QT =

SOURCES = collabreate.cpp \
          collabreate_common.cpp \
          collabreate_ui_qt.cpp \
          collabreate_options_dlg_qt.cpp \
          idanet.cpp \
          buffer.cpp
          
HEADERS = collabreate_ui_qt.hpp \
          buffer.h \
          idanet.hpp \
          collabreate.h

win32:TARGET_EXT=.p64
linux-g++:TARGET_EXT=.plx64
macx:TARGET_EXT=.pmc64
          
TARGET = collab_qt
