#ifndef BUDDY_GLOBAL_H
#define BUDDY_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(BUDDY_LIBRARY)
#  define BUDDY_EXPORT Q_DECL_EXPORT
#else
#  define BUDDY_EXPORT Q_DECL_IMPORT
#endif

#endif // BUDDY_GLOBAL_H
