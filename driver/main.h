#pragma once

#include <ntifs.h>

NTSTATUS driverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path);

NTSTATUS unloadDriver(PDRIVER_OBJECT driver_object);
