#include <ntddk.h>
#include "PoolVulnDrv.h"

PVOID g_PoolPointer = nullptr;

void PoolVulnDrvUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS PoolVulnDrvCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS PoolVulnDrvDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS AllocateOverflowBufferHandler(_In_ PVOID UserBuffer, _In_ SIZE_T Size);
NTSTATUS FreeOverflowBufferHandler();
NTSTATUS TriggerOverflowHandler(_In_ PVOID UserBuffer, _In_ SIZE_T Size);

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING)
{
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PoolVulnDrv");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\PoolVulnDrv");
	PDEVICE_OBJECT DeviceObject = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("Failed to create device (ntstatus = 0x%08X).\n", status);
			break;
		}

		status = IoCreateSymbolicLink(&symLink, &devName);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("Failed to create symbolic link (ntstatus = 0x%08X).\n", status);
			break;
		}
	} while (false);

	if (!NT_SUCCESS(status))
	{
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);

		return status;
	}

	DriverObject->DriverUnload = PoolVulnDrvUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = PoolVulnDrvCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = PoolVulnDrvCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PoolVulnDrvDeviceControl;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrint("PoolVulnDrv is loaded successfully.\n");

	return STATUS_SUCCESS;
}


void PoolVulnDrvUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\PoolVulnDrv");

	if (g_PoolPointer)
		ExFreePoolWithTag(g_PoolPointer, (ULONG)VULN_POOL_TAG);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("PoolVulnDrv is unloaded.\n");
}


NTSTATUS PoolVulnDrvCreateClose(_In_ PDEVICE_OBJECT, _Inout_ PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS PoolVulnDrvDeviceControl(_In_ PDEVICE_OBJECT, _Inout_ PIRP Irp)
{
	auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
	auto IoctlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	auto UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	auto Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG info = 0;

	switch (IoctlCode)
	{
	case IOCTL_ALLOC_OVERFLOW_BUFFER:
		status = AllocateOverflowBufferHandler(UserBuffer, Size);

		if (NT_SUCCESS(status))
			info = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

		break;

	case IOCTL_FREE_OVERFLOW_BUFFER:
		status = FreeOverflowBufferHandler();
		break;

	case IOCTL_TRIGGER_OVERFLOW:
		status = TriggerOverflowHandler(UserBuffer, Size);

		if (NT_SUCCESS(status))
			info = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS AllocateOverflowBufferHandler(_In_ PVOID UserBuffer, _In_ SIZE_T Size)
{
	NTSTATUS status;

	if (g_PoolPointer)
	{
		DbgPrint("Buffer is already allocated.\n");

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	__try
	{
		ProbeForRead(UserBuffer, Size, (ULONG)__alignof(UCHAR));
		g_PoolPointer = ExAllocatePoolWithTag(PagedPool, Size, (ULONG)VULN_POOL_TAG);

		if (g_PoolPointer == nullptr)
		{
			DbgPrint("Failed to allocate paged pool.\n");

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DbgPrint("Allocated buffer @ 0x%p.\n", g_PoolPointer);
		RtlCopyMemory(g_PoolPointer, UserBuffer, Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		DbgPrint("Exception : 0x%08X\n", status);

		return status;
	}

	return STATUS_SUCCESS;
}


NTSTATUS FreeOverflowBufferHandler()
{
	if (g_PoolPointer == nullptr)
	{
		DbgPrint("Buffer have not been allocated.\n");

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	PVOID pFree = g_PoolPointer;

	ExFreePoolWithTag(g_PoolPointer, (ULONG)VULN_POOL_TAG);
	g_PoolPointer = nullptr;
	DbgPrint("Free'd buffer @ 0x%p.\n", pFree);

	return STATUS_SUCCESS;
}


NTSTATUS TriggerOverflowHandler(_In_ PVOID UserBuffer, _In_ SIZE_T Size)
{
	NTSTATUS status;

	__try
	{
		ProbeForRead(UserBuffer, Size, (ULONG)__alignof(UCHAR));
		RtlCopyMemory(g_PoolPointer, UserBuffer, Size);
		DbgPrint("Triggered overflow.\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		DbgPrint("Exception : 0x%08X\n", status);

		return status;
	}

	return STATUS_SUCCESS;
}