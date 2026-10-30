#include "convert.h"

wchar_t* charToWchar(const char* charString) {
    if (!charString) return NULL;

    int len = MultiByteToWideChar(CP_UTF8, 0, charString, -1, NULL, 0);
    if (len == 0) return NULL;

    wchar_t* wcharString = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wcharString) return NULL;

    MultiByteToWideChar(CP_UTF8, 0, charString, -1, wcharString, len);
    return wcharString;
}

char* WideCharToChar(wchar_t* wideString) {
    if (!wideString) return NULL;

    int bufSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, NULL, 0, NULL, NULL);
    if (bufSize == 0) return NULL;

    char* charString = (char*)malloc(bufSize);
    if (!charString) return NULL;

    if (WideCharToMultiByte(CP_UTF8, 0, wideString, -1, charString, bufSize, NULL, NULL) == 0) {
        free(charString);
        return NULL;
    }
    return charString;
}
