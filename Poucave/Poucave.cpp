#include <ntifs.h>

#define IOCTL_GET_DATA_32 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DATA_64 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


struct MyProcessInfo {
	HANDLE PID;
	WCHAR processName[256];
};
struct MyProcessInfo processInfo;

UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\AgentDriver");
UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\AgentDriverLnk");
KSPIN_LOCK processInfoLock;

void DriverAgentUnload(PDRIVER_OBJECT DriverObject);

BOOLEAN IsProcess32Bit(HANDLE PID, NTSTATUS *status) {
	PEPROCESS Process;
	*status = PsLookupProcessByProcessId(PID, &Process);
	if (!NT_SUCCESS(*status)) {
		return FALSE;
	}

	PVOID Wow64Process = *(PVOID*)((PUCHAR)Process + 0x580); 
	ObDereferenceObject(Process);
	if (Wow64Process != NULL) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create) {
	UNREFERENCED_PARAMETER(ppid);
	if (create) {
		KIRQL oldIrql;
		PEPROCESS process = NULL;
		UNICODE_STRING* processImageName = NULL;

		KeAcquireSpinLock(&processInfoLock, &oldIrql);
		RtlZeroMemory(&processInfo, sizeof(processInfo));
		processInfo.PID = pid;

		if (NT_SUCCESS(PsLookupProcessByProcessId(processInfo.PID, &process))) {
			if (NT_SUCCESS(SeLocateProcessImageName(process, &processImageName)) && processImageName != NULL) {
				size_t length = min(processImageName->Length / sizeof(WCHAR), 255);
				wcsncpy_s(processInfo.processName, sizeof(processInfo.processName) / sizeof(WCHAR), processImageName->Buffer, length);
				processInfo.processName[length] = L'\0';
			}
		}
		ObDereferenceObject(process);
		KeReleaseSpinLock(&processInfoLock, oldIrql);
	}
}


NTSTATUS DriverAgentSendData(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

	if (buffer == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}

	if (processInfo.PID != 0) {
		KIRQL oldIrql;
		KeAcquireSpinLock(&processInfoLock, &oldIrql);
		struct MyProcessInfo localProcessInfo = processInfo;
		KeReleaseSpinLock(&processInfoLock, oldIrql);

		BOOLEAN is32Bit = IsProcess32Bit(localProcessInfo.PID, &status);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return FALSE;
		}

		if (is32Bit && pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_DATA_32) {
			DbgPrint("[+] 32 bits :: New process --> %ws \n\t\tArch --> x64\n\t\tPID --> %d\n\n",
				localProcessInfo.processName,
				localProcessInfo.PID
			);
			RtlCopyMemory(buffer, &localProcessInfo, sizeof(struct MyProcessInfo));
			Irp->IoStatus.Information = sizeof(struct MyProcessInfo);
			RtlZeroMemory(&processInfo, sizeof(processInfo));
		} 
		else if (!is32Bit && pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_DATA_64) {
			DbgPrint("[+] 64 bits :: New process --> %ws\n\t\tArch --> x64\n\t\tPID --> %d\n\n",
				localProcessInfo.processName,
				localProcessInfo.PID
			);
			RtlCopyMemory(buffer, &localProcessInfo, sizeof(struct MyProcessInfo));
			Irp->IoStatus.Information = sizeof(struct MyProcessInfo);
			RtlZeroMemory(&processInfo, sizeof(processInfo));
		}
		else {
			DbgPrint("[+] ELSE :: New process --> %ws\n\t\tArch --> x64\n\t\tPID --> %d\n\n",
				localProcessInfo.processName,
				localProcessInfo.PID
			);
		}
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverAgentCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject;

	DbgPrint("[*] Sample driver init success !\n");

	KeInitializeSpinLock(&processInfoLock);

	DriverObject->DriverUnload = DriverAgentUnload;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverAgentSendData;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverAgentCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverAgentCreateClose;

	status = PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] Failed to set process notify routine (0x%08X)\n", status);
		return status;
	}
	else {
		DbgPrint("[+] Process notify routine set\n");
	}

	status = IoCreateDevice(
		DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] Failed to create device object (0x%08X)\n", status);
		return status;
	}
	else {
		DbgPrint("[+] Device object created : %s\n", devName);
	}

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}
	else {
		DbgPrint("[+] Symbolic link created : %s\n", symLink);
	}

	return STATUS_SUCCESS;
}


void DriverAgentUnload(PDRIVER_OBJECT DriverObject) {
	PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, TRUE);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("[*] Driver AgentDriver unload !\n");
}