#include "pch.h"
#include <stdlib.h>
#include <stdio.h>
#include <Psapi.h>
#include <stdint.h>
#include "SigScan.h"

void* sigClampAndSetDisplayScale1 = sigScan(
	"\x83\xfa\x32\x7d\x07\xbb\x32\x00\x00\x00\xeb\x0a\xb8\x64\x00\x00\x00\x3b\xd8\x0f\x4f\xd8",
	"xxxxxxxxxxxxxxxxxxxxxx"
);

void* sigClampAndSetDisplayScale2 = sigScan(
	"\x83\xf8\x32\x7d\x07\xb8\x32\x00\x00\x00\xeb\x0a\xba\x64\x00\x00\x00\x3b\xc2\x0f\x4f\xc2",
	"xxxxxxxxxxxxxxxxxxxxxx"
);

void* sigSettingsMenuInitValues = sigScan(
	"\x83\xf8\x32\x7d\x07\xb8\x32\x00\x00\x00\xeb\x0d\x41\xb8\x64\x00\x00\x00\x41\x3b\xc0\x41\x0f\x4f\xc0",
	"xxxxxxxxxxxxxxxxxxxxxxxxx"
);

void* sigCustomizeMenuInitValues = sigScan(
	"\xc7\x05\xa2\x1a\x18\xef\x00\x00\x80\x3f",
	"xxxxxxxxxx"
);

void* sigSettingsMenuUserChangedSomething = sigScan(
	"\xb8\xa1\xa0\xa0\xa0\xff\xc1\xf7\xe9\x03\xd1\xc1\xfa\x05\x8b\xc2\xc1\xe8\x1f\x03\xd0\x6b\xc2\x33\x2b\xc8\x83\xc1\x32",
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
);

void writeMemory(void* location, const char* data, int size) {
	DWORD oldProtect;
	VirtualProtect((void*)(location), size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void*)(location), data, size);
	VirtualProtect((void*)(location), size, oldProtect, &oldProtect);
}

extern "C" __declspec(dllexport) void Init() {
	writeMemory(sigClampAndSetDisplayScale1, "\x83\xfa\x01\x7d\x07\xbb\x01", 7);
	writeMemory(sigClampAndSetDisplayScale2, "\x83\xf8\x01\x7d\x07\xb8\x01", 7);
	writeMemory(sigSettingsMenuInitValues,   "\x83\xf8\x01\x7d\x07\xb8\x01", 7);
	writeMemory(sigCustomizeMenuInitValues,  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", 10);
	writeMemory(sigSettingsMenuUserChangedSomething, "\x83\xf9\x64\x7e\x07\xb9\x01\x00\x00\x00\xeb\x11\x83\xf9\x00\x7f\x0c\xb9\x64\x00\x00\x00\x90\x90\x90\x90\x90\x90\x90", 29);
}