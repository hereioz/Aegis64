// Aegis64SDK.h
#pragma once

#ifdef AEGIS64_EXPORTS
#define AEGIS_API __declspec(dllexport)
#else
#define AEGIS_API __declspec(dllimport)
#endif

extern "C" {
    AEGIS_API void Aegis64_Begin();
    AEGIS_API void Aegis64_End();
}