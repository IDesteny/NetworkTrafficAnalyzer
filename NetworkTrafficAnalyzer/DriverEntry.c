#define NDIS630
#include <ndis.h>

#define FILTER_MAJOR_NDIS_VERSION 6
#define FILTER_MINOR_NDIS_VERSION 30

#define FILTER_UNIQUE_NAME L"{009f4c24-6c17-43ad-885f-ed6cb50e8d5a}"
#define FILTER_SERVICE_NAME L"NetworkTrafficAnalyzer"
#define FILTER_FRIENDLY_NAME L"NetworkTrafficAnalyzer NDIS Filter"

#define LINKNAME_STRING L"\\DosDevices\\NetworkTrafficAnalyzer"
#define NTDEVICE_STRING L"\\Device\\NetworkTrafficAnalyzer"

#define LOG(t, m) DbgPrint("%ws: %ws", t, m)

struct _FILTER_DEVICE_EXTENSION
{
	NDIS_HANDLE hFilterDriver;
	NDIS_HANDLE hNdisDevice;
};

typedef struct _FILTER_DEVICE_EXTENSION FILTER_DEVICE_EXTENSION;
typedef FILTER_DEVICE_EXTENSION *PFILTER_DEVICE_EXTENSION;

NDIS_STATUS
FilterAttach(
	NDIS_HANDLE NdisFilterHandle,
	NDIS_HANDLE FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
	UNREFERENCED_PARAMETER(NdisFilterHandle);
	UNREFERENCED_PARAMETER(FilterDriverContext);
	UNREFERENCED_PARAMETER(AttachParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	
	return status;
}

VOID
FilterDetach(
	NDIS_HANDLE FilterModuleContext)
{
	UNREFERENCED_PARAMETER(FilterModuleContext);
}

NDIS_STATUS
FilterRestart(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(RestartParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	
	return status;
}

NDIS_STATUS
FilterPause(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(PauseParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	
	return status;
}

VOID
NTADeregisterDevice(
	NDIS_HANDLE hFilterDriver)
{
	NdisDeregisterDeviceEx(hFilterDriver);
}

VOID
FilterUnload(
	PDRIVER_OBJECT pDriverObject)
{
	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension = pDriverObject->DeviceObject->DeviceExtension;

	NTADeregisterDevice(pFilterDeviceExtension->hNdisDevice);
	NdisFDeregisterFilterDriver(pFilterDeviceExtension->hFilterDriver);
}

NTSTATUS
NTADispatch(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NDIS_STATUS
NTARegisterDevice(
	NDIS_HANDLE hNdisFilterDriver)
{
	PDRIVER_OBJECT pDriverObject;
	PDEVICE_OBJECT pDeviceObject;

	NDIS_STATUS status;
	NDIS_HANDLE hNdisDevice;
	
	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension;

	UNICODE_STRING DeviceName;
	UNICODE_STRING DeviceLinkUnicodeString;

	NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);
	NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);

	PDRIVER_DISPATCH pDriverDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
	NdisZeroMemory(&pDriverDispatch, sizeof(pDriverDispatch));

	pDriverDispatch[IRP_MJ_CREATE] = NTADispatch;
	pDriverDispatch[IRP_MJ_CLOSE] = NTADispatch;

	NDIS_DEVICE_OBJECT_ATTRIBUTES pDeviceObjectAttributes;
	NdisZeroMemory(&pDeviceObjectAttributes, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

	pDeviceObjectAttributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	pDeviceObjectAttributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	pDeviceObjectAttributes.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

	pDeviceObjectAttributes.DeviceName = &DeviceName;
	pDeviceObjectAttributes.SymbolicName = &DeviceLinkUnicodeString;
	pDeviceObjectAttributes.MajorFunctions = pDriverDispatch;
	pDeviceObjectAttributes.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);

	status = NdisRegisterDeviceEx(
		hNdisFilterDriver,
		&pDeviceObjectAttributes,
		&pDeviceObject,
		&hNdisDevice);

	if (status != NDIS_STATUS_SUCCESS)
	{
		LOG(L"E", L"NdisRegisterDeviceEx");
		return status;
	}

	pFilterDeviceExtension = NdisGetDeviceReservedExtension(pDeviceObject);
	pFilterDeviceExtension->hFilterDriver = hNdisFilterDriver;
	pFilterDeviceExtension->hNdisDevice = hNdisDevice;

	pDriverObject = hNdisFilterDriver;

	return status;
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NDIS_STATUS status;

	NDIS_HANDLE hFilterDriverContext;
	NDIS_HANDLE hNdisFilterDriver;

	NDIS_STRING friendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
	NDIS_STRING serviceName = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
	NDIS_STRING uniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);

	NDIS_FILTER_DRIVER_CHARACTERISTICS filterDriverCharacteristics;
	NdisZeroMemory(&filterDriverCharacteristics, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));

	filterDriverCharacteristics.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
	filterDriverCharacteristics.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
	filterDriverCharacteristics.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);

	filterDriverCharacteristics.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
	filterDriverCharacteristics.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;

	filterDriverCharacteristics.FriendlyName = friendlyName;
	filterDriverCharacteristics.ServiceName = serviceName;
	filterDriverCharacteristics.UniqueName = uniqueName;

	filterDriverCharacteristics.MajorDriverVersion = 1;

	filterDriverCharacteristics.RestartHandler = FilterRestart;
	filterDriverCharacteristics.AttachHandler = FilterAttach;
	filterDriverCharacteristics.DetachHandler = FilterDetach;
	filterDriverCharacteristics.PauseHandler = FilterPause;

	hFilterDriverContext = pDriverObject;

	pDriverObject->DriverUnload = FilterUnload;
	
	status = NdisFRegisterFilterDriver(
		pDriverObject,
		hFilterDriverContext,
		&filterDriverCharacteristics,
		&hNdisFilterDriver);

	if (status != NDIS_STATUS_SUCCESS)
	{
		LOG(L"E", L"NdisFRegisterFilterDriver()");
		return status;
	}

	status = NTARegisterDevice(hNdisFilterDriver);

	if (status != NDIS_STATUS_SUCCESS)
	{
		LOG(L"E", L"NTARegisterDevice()");
		NdisFDeregisterFilterDriver(hNdisFilterDriver);
		return status;
	}

	return status;
}