/*
* Tasks:
* - Get rid of global variables
*/

#define NDIS630
#include <ndis.h>
#include <stdarg.h>

#define FILTER_UNIQUE_NAME \
	L"{009f4c24-6c17-43ad-885f-ed6cb50e8d5a}"

#define FILTER_SERVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define FILTER_FRIENDLY_NAME \
	L"NetworkTrafficAnalyzer NDIS Filter"

#define LINKNAME_STRING \
	L"\\DosDevices\\" FILTER_SERVICE_NAME

#define NTDEVICE_STRING \
	L"\\Device\\" FILTER_SERVICE_NAME

#ifdef DBG

#define DL_INFO	3
#define DL_TRACE	2
#define DL_WARN	1
#define DL_ERROR	0

#define DEBUG_LVL DL_INFO

VOID
DbgPrintExWithPrefix(
	PCCH pref,
	ULONG ComponentId,
	ULONG Level,
	PCCH Fmt,
	...)
{
	va_list arglist;
	va_start(arglist, Fmt);
	vDbgPrintExWithPrefix(pref, ComponentId, Level, Fmt, arglist);
	va_end(arglist);
}

#define DEBUGP(lvl, ...)													\
{																	\
	if ((lvl) <= DEBUG_LVL)												\
	{																\
		DbgPrintExWithPrefix("NTA: ", DPFLTR_IHVNETWORK_ID, lvl, __VA_ARGS__);	\
	}																\
}

#else // DBG

#define DEBUGP(lev, ...)

#endif // DBG

#define ETH_ALEN 6
#define ETH_TYPE_IP 0x0800

#define ntohs(x) \
	((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))

#define NB_SIZE \
	sizeof(ETH_HEADER) + sizeof(IP_HEADER)

struct _ETH_HEADER
{
	UCHAR h_dest[ETH_ALEN];
	UCHAR h_source[ETH_ALEN];
	UCHAR h_proto;
};

typedef struct _ETH_HEADER ETH_HEADER;
typedef ETH_HEADER *PETH_HEADER;

struct _IP_HEADER
{
	UCHAR ip_hl : 4;
	UCHAR ip_v : 4;
	UCHAR ip_tos;
	SHORT ip_len;
	UCHAR ip_id;
	SHORT ip_off;
	UCHAR ip_ttl;
	UCHAR ip_p;
	USHORT ip_sum;
	UINT ip_src;
	UINT ip_dst;
};

typedef struct _IP_HEADER IP_HEADER;
typedef IP_HEADER *PIP_HEADER;

struct _FILTER_DEVICE_EXTENSION
{
	NDIS_HANDLE hNdisFilterDevice;
	UINT ipAddresses[128];
	INT numberOfAddresses;
};

typedef struct _FILTER_DEVICE_EXTENSION FILTER_DEVICE_EXTENSION;
typedef FILTER_DEVICE_EXTENSION* PFILTER_DEVICE_EXTENSION;

NDIS_HANDLE hNdisFilterDriver;
NDIS_HANDLE hNdisDevice;

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath);

VOID
IoCompleteIrp(
	PIRP pIrp,
	NTSTATUS status,
	ULONG infoLen);

NTSTATUS
DriverAccessControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp);

NTSTATUS
DeviceIoControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp);

NDIS_STATUS
RegisteringDevice(
	VOID);

NDIS_STATUS
FilterAttach(
	NDIS_HANDLE NdisFilterHandle,
	NDIS_HANDLE FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters);

NDIS_STATUS
FilterRestart(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters);

VOID
FilterReceiveNetBufferLists(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferLists,
	NDIS_PORT_NUMBER PortNumber,
	ULONG NumberOfNetBufferLists,
	ULONG ReceiveFlags);

NDIS_STATUS
FilterPause(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters);

VOID
FilterDetach(
	NDIS_HANDLE FilterModuleContext);

VOID
DeregisteringDevice(
	NDIS_HANDLE hFilterDriver);

VOID
DriverUnload(
	PDRIVER_OBJECT pDriverObject);


NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	DEBUGP(DL_TRACE, "==> DriverEntry");

	UNREFERENCED_PARAMETER(pRegistryPath);

	NDIS_STATUS status;

	NDIS_STRING friendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
	NDIS_STRING serviceName = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
	NDIS_STRING uniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);

	NDIS_FILTER_DRIVER_CHARACTERISTICS filterDriverCharacteristics;
	NdisZeroMemory(&filterDriverCharacteristics, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));

	filterDriverCharacteristics.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
	filterDriverCharacteristics.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
	filterDriverCharacteristics.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);

	filterDriverCharacteristics.MajorNdisVersion = 6;
	filterDriverCharacteristics.MinorNdisVersion = 30;

	filterDriverCharacteristics.FriendlyName = friendlyName;
	filterDriverCharacteristics.ServiceName = serviceName;
	filterDriverCharacteristics.UniqueName = uniqueName;

	filterDriverCharacteristics.MajorDriverVersion = 1;

	filterDriverCharacteristics.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
	filterDriverCharacteristics.RestartHandler = FilterRestart;
	filterDriverCharacteristics.AttachHandler = FilterAttach;
	filterDriverCharacteristics.DetachHandler = FilterDetach;
	filterDriverCharacteristics.PauseHandler = FilterPause;

	pDriverObject->DriverUnload = DriverUnload;

	do
	{
		status = NdisFRegisterFilterDriver(
			pDriverObject,
			NULL,
			&filterDriverCharacteristics,
			&hNdisFilterDriver);

		if (status != NDIS_STATUS_SUCCESS)
		{
			break;
		}

		status = RegisteringDevice();

		if (status != NDIS_STATUS_SUCCESS)
		{
			NdisFDeregisterFilterDriver(hNdisFilterDriver);
			break;
		}
	} while (FALSE);

	DEBUGP(DL_TRACE, "<== DriverEntry - status: %i", status);
	return status;
}

VOID
IoCompleteIrp(
	PIRP pIrp,
	NTSTATUS status,
	ULONG infoLen)
{
	DEBUGP(DL_TRACE, "==> IoCompleteIrp");

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = infoLen;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<== IoCompleteIrp");
}

NTSTATUS
DriverAccessControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	DEBUGP(DL_TRACE, "==> DriverAccessControlRoutine");

	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	switch (pIoStackLocation->MajorFunction)
	{
		case IRP_MJ_CREATE:
			break;

		case IRP_MJ_CLEANUP:
			break;

		case IRP_MJ_CLOSE:
			break;

		default:
			break;
	}

	IoCompleteIrp(pIrp, status, 0);

	DEBUGP(DL_TRACE, "<== DriverAccessControlRoutine - status: %i", status);
	return status;
}

NTSTATUS
DeviceIoControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	DEBUGP(DL_TRACE, "==> DeviceIoControlRoutine");

	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	
	ULONG infoLen = 0;
	ULONG ioControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	switch (ioControlCode)
	{
		default:
			status = NDIS_STATUS_INVALID_PARAMETER;
			break;
	}

	IoCompleteIrp(pIrp, status, infoLen);

	DEBUGP(DL_TRACE, "<== DeviceIoControlRoutine - status: %i", status);
	return status;
}

NDIS_STATUS
RegisteringDevice(
	VOID)
{
	DEBUGP(DL_TRACE, "==> RegisteringDevice");

	NDIS_STATUS status;

	PDEVICE_OBJECT pDeviceObject;

	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLinkUnicodeString;

	NdisInitUnicodeString(&deviceLinkUnicodeString, LINKNAME_STRING);
	NdisInitUnicodeString(&deviceName, NTDEVICE_STRING);

	PDRIVER_DISPATCH pDriverDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
	NdisZeroMemory(pDriverDispatch, sizeof(pDriverDispatch));

	pDriverDispatch[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlRoutine;
	pDriverDispatch[IRP_MJ_CLEANUP] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_CREATE] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_CLOSE] = DriverAccessControlRoutine;

	NDIS_DEVICE_OBJECT_ATTRIBUTES pDeviceObjectAttributes;
	NdisZeroMemory(&pDeviceObjectAttributes, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

	pDeviceObjectAttributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	pDeviceObjectAttributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	pDeviceObjectAttributes.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

	pDeviceObjectAttributes.DeviceName = &deviceName;
	pDeviceObjectAttributes.SymbolicName = &deviceLinkUnicodeString;
	pDeviceObjectAttributes.MajorFunctions = pDriverDispatch;

	do
	{
		status = NdisRegisterDeviceEx(
			hNdisFilterDriver,
			&pDeviceObjectAttributes,
			&pDeviceObject,
			&hNdisDevice);

		if (status != NDIS_STATUS_SUCCESS)
		{
			break;
		}
	} while (FALSE);
	
	DEBUGP(DL_TRACE, "<== RegisteringDevice - status: %i", status);
	return status;
}

NDIS_STATUS
FilterAttach(
	NDIS_HANDLE NdisFilterHandle,
	NDIS_HANDLE FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
	DEBUGP(DL_TRACE, "==> FilterAttach");

	UNREFERENCED_PARAMETER(FilterDriverContext);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;

	do
	{
		if (AttachParameters->MiniportMediaType != NdisMedium802_3
			&& AttachParameters->MiniportMediaType != NdisMediumWan
			&& AttachParameters->MiniportMediaType != NdisMediumWirelessWan)
		{
			status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}
		
		PFILTER_DEVICE_EXTENSION pFilterDeviceExtension = NdisAllocateMemoryWithTagPriority(
			NdisFilterHandle,
			sizeof(FILTER_DEVICE_EXTENSION),
			'NTA',
			LowPoolPriority);

		if (!pFilterDeviceExtension)
		{
			status = STATUS_BUFFER_ALL_ZEROS;
			break;
		}

		pFilterDeviceExtension->hNdisFilterDevice = NdisFilterHandle;

		NDIS_FILTER_ATTRIBUTES filterAttributes;
		NdisZeroMemory(&filterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));

		filterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		filterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
		filterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
		filterAttributes.Flags = 0;

		status = NdisFSetAttributes(
			NdisFilterHandle,
			pFilterDeviceExtension,
			&filterAttributes);

		if (status != NDIS_STATUS_SUCCESS)
		{
			break;
		}

	} while (FALSE);
	
	DEBUGP(DL_TRACE, "<== FilterAttach - status: %i", status);
	return status;
}

NDIS_STATUS
FilterRestart(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
	DEBUGP(DL_TRACE, "==> FilterRestart");

	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(RestartParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;

	DEBUGP(DL_TRACE, "<== FilterRestart - status %i", status);
	return status;
}

BOOLEAN
Find(
	PUINT ips,
	INT size,
	UINT newIp)
{
	for (INT i = 0; i < size; ++i)
	{
		if (ips[i] == newIp)
		{
			return TRUE;
		}
	}

	return FALSE;
}

VOID
FilterReceiveNetBufferLists(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferLists,
	NDIS_PORT_NUMBER PortNumber,
	ULONG NumberOfNetBufferLists,
	ULONG ReceiveFlags)
{
	DEBUGP(DL_TRACE, "==> FilterReceiveNetBufferLists");

	UNREFERENCED_PARAMETER(FilterModuleContext);

	PUCHAR headerBuffer;
	PIP_HEADER ipHeader;
	PETH_HEADER ethHeader;
	UCHAR localBuffer[NB_SIZE];

	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension = FilterModuleContext;
	INT numberOfAddresses = pFilterDeviceExtension->numberOfAddresses;
	PUINT ipAddresses = pFilterDeviceExtension->ipAddresses;

	for (
		PNET_BUFFER_LIST netBufferList = NetBufferLists; 
		netBufferList; 
		netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList))
	{
		for (
			PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
			netBuffer;
			netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
		{
			headerBuffer = NdisGetDataBuffer(netBuffer, NB_SIZE, localBuffer, 1, 1);

			if (!headerBuffer)
			{
				continue;
			}

			ethHeader = (PETH_HEADER)headerBuffer;

			if (ntohs(ethHeader->h_proto) != ETH_TYPE_IP)
			{
				continue;
			}

			ipHeader = (PIP_HEADER)((ULONG_PTR)ethHeader + sizeof(ETH_HEADER));

			if (ipHeader->ip_p != IPPROTO_ICMP)
			{
				continue;
			}

			if (!Find(ipAddresses, numberOfAddresses, ipHeader->ip_dst))
			{
				ipAddresses[numberOfAddresses++] = ipHeader->ip_dst;
			}

			if (!Find(ipAddresses, numberOfAddresses, ipHeader->ip_src))
			{
				ipAddresses[numberOfAddresses++] = ipHeader->ip_src;
			}

			PUINT8 ipDst = (PUINT8)&ipHeader->ip_dst;
			PUINT8 ipSrc = (PUINT8)&ipHeader->ip_src;

			DEBUGP(DL_INFO, "IP - %hhu.%hhu.%hhu.%hhu < %hhu.%hhu.%hhu.%hhu",
				ipDst[0], ipDst[1], ipDst[2], ipDst[3],
				ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3]);
		}
	}

	NdisFIndicateReceiveNetBufferLists(
		pFilterDeviceExtension->hNdisFilterDevice,
		NetBufferLists,
		PortNumber,
		NumberOfNetBufferLists,
		ReceiveFlags);

	DEBUGP(DL_TRACE, "<== FilterReceiveNetBufferLists");
}

NDIS_STATUS
FilterPause(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
	DEBUGP(DL_TRACE, "==> FilterPause");

	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(PauseParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;

	DEBUGP(DL_TRACE, "<== FilterPause - status %i", status);
	return status;
}

VOID
FilterDetach(
	NDIS_HANDLE FilterModuleContext)
{
	DEBUGP(DL_TRACE, "==> FilterDetach");

	UNREFERENCED_PARAMETER(FilterModuleContext);

	DEBUGP(DL_TRACE, "<== FilterDetach");
}

VOID
DeregisteringDevice(
	NDIS_HANDLE hFilterDriver)
{
	DEBUGP(DL_TRACE, "==> DeregisteringDevice");

	NdisDeregisterDeviceEx(hFilterDriver);

	DEBUGP(DL_TRACE, "<== DeregisteringDevice");
}

VOID
DriverUnload(
	PDRIVER_OBJECT pDriverObject)
{
	DEBUGP(DL_TRACE, "==> DriverUnload");

	UNREFERENCED_PARAMETER(pDriverObject);

	DeregisteringDevice(hNdisDevice);
	NdisFDeregisterFilterDriver(hNdisFilterDriver);

	DEBUGP(DL_TRACE, "<== DriverUnload");
}