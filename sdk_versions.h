#ifndef __SDK_VERSIONS_H
#define __SDK_VERSIONS_H

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <segment.hpp>

/*
//Ida 4.3
#define IDP_INTERFACE_VERSION 61

//Ida 4.4
#define IDP_INTERFACE_VERSION 62

//Ida 4.5
#define IDP_INTERFACE_VERSION 63

//Ida 4.6
#define IDP_INTERFACE_VERSION 66

//Ida 4.6sp1
#define IDP_INTERFACE_VERSION 67

//Ida 4.7
#define IDP_INTERFACE_VERSION 70

//Ida 4.8
#define IDP_INTERFACE_VERSION 75

//Ida 4.9, 4.9sp, 5.0, 5.1
#define IDP_INTERFACE_VERSION 76
*/

#define SDK_VERSION_430 61
#define SDK_VERSION_440 62
#define SDK_VERSION_450 63
#define SDK_VERSION_460 66
#define SDK_VERSION_460sp1 67
#define SDK_VERSION_470 70
#define SDK_VERSION_480 75
#define SDK_VERSION_490 76
#define SDK_VERSION_500 76
#define SDK_VERSION_510 76

//prior to SDK490, SDK versions can be mapped to IDP_INTERFACE_VERSION
#if IDP_INTERFACE_VERSION == SDK_VERSION_430
#define IDA_SDK_VERSION 430
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_440
#define IDA_SDK_VERSION 440
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_450
#define IDA_SDK_VERSION 450
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_460
#define IDA_SDK_VERSION 460
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_460sp1
#define IDA_SDK_VERSION 461
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_470
#define IDA_SDK_VERSION 470
#endif
#if IDP_INTERFACE_VERSION == SDK_VERSION_480
#define IDA_SDK_VERSION 480
#endif

/* beginning with SDK520, IDA_SDK_VERSION is defined in pro.h */
#ifndef IDA_SDK_VERSION            //SDK520 and later
#if IDP_INTERFACE_VERSION == 76    //SDK490 and later

#ifdef DOUNK_SIMPLE  //defined in bytes.hpp in SDK510
#define IDA_SDK_VERSION 510
#else   //DOUNK_SIMPLE

#ifdef SEGDEL_PERM //defined in segment.hpp in SDK500
#define IDA_SDK_VERSION 500
#else   //SEGDEL_PERM
#define IDA_SDK_VERSION 490
#endif  //SEGDEL_PERM

#endif  //DOUNK_SIMPLE

#endif  //IDP_INTERFACE_VERSION == 76
#endif  //IDA_SDK_VERSION

#endif
