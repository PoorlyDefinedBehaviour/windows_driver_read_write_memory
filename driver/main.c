#pragma once

#include "main.h"
#include "log.h"

#define IO_READ_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT g_device_object;
UNICODE_STRING dev;
UNICODE_STRING dos;

NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS source_process,
	PVOID source_address,
	PEPROCESS target_process,
	PVOID target_address,
	SIZE_T buffer_size,
	KPROCESSOR_MODE previous_mode,
	PSIZE_T return_size
);

typedef struct _KERNEL_READ_REQUEST {
	ULONG process_id;
	ULONG address;
	PVOID buffer_address;
	ULONG size;
	SIZE_T return_size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
	ULONG process_id;
	ULONG address;
	PVOID buffer_address;
	ULONG size;
	SIZE_T return_size;
} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

NTSTATUS kernel_read_virtual_memory(PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size, PSIZE_T return_size) {
	return MmCopyVirtualMemory(process, source_address, PsGetCurrentProcess(), target_address, size, KernelMode, return_size);
}

NTSTATUS kernel_write_virtual_memory(PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size, PSIZE_T return_size) {
	return MmCopyVirtualMemory(PsGetCurrentProcess(), source_address, process, target_address, size, KernelMode, return_size);
}

/*
PLOAD_IMAGE_NOTIFY_ROUTINE image_load_notify_routine(PUNICODE_STRING full_image_name, HANDLE process_id, PIMAGE_INFO image_info) {

}
*/

NTSTATUS createCall(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS closeCall(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ioControl(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG control_code = (ULONG)stack->Parameters.DeviceIoControl.IoControlCode;

	switch (control_code) {
	case IO_READ_PROCESS_MEMORY: {
		PKERNEL_READ_REQUEST input = (PKERNEL_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;

		PEPROCESS process;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)input->process_id, &process))) {			
			kernel_read_virtual_memory(process, (PVOID)input->address, input->buffer_address, input->size, &input->return_size);
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(KERNEL_READ_REQUEST);
		}
			
		break;
	}
		
	case IO_WRITE_PROCESS_MEMORY: {
		PKERNEL_WRITE_REQUEST input = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;

		PEPROCESS process;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)input->process_id, &process))) {
			kernel_write_virtual_memory(process, input->buffer_address, (PVOID)input->address, input->size, &input->return_size);
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(PKERNEL_WRITE_REQUEST);
		}
		break;
	}

	default:
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		irp->IoStatus.Information = 0;
		break;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	driver_object->DriverUnload = unloadDriver;

	// PsSetLoadImageNotifyRoutine(image_load_notify_routine);

	RtlInitUnicodeString(&dev, L"\\Device\\mydriver");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\mydriver");

	IoCreateDevice(driver_object, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	IoCreateSymbolicLink(&dos, &dev);

	driver_object->MajorFunction[IRP_MJ_CREATE] = createCall;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = closeCall;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioControl;

	if (g_device_object != NULL) {
		g_device_object->Flags |= DO_DIRECT_IO;
		g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	dbg("hello world");

	return STATUS_SUCCESS;
}


NTSTATUS unloadDriver(PDRIVER_OBJECT driver_object) {
	UNREFERENCED_PARAMETER(driver_object);

	// PsRemoveLoadImageNotifyRoutine(image_load_notify_routine);

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(driver_object->DeviceObject);

	dbg("bye world");

	return STATUS_SUCCESS;
}
