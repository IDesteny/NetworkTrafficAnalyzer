/*
* Tasks:
* - Add read request processing
* - Add null checks
* - Try adding asynchronous deserialization
* - Add comments
* - CLeanup
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

#define FILTER_TAG \
	'NTA'

#define FILTER_MAJOR_NDIS_VERSION 6
#define FILTER_MINOR_NDIS_VERSION 30

#define FILTER_MAJOR_DRIVER_VERSION 1

#ifdef DBG

#define DL_INFO	3
#define DL_TRACE	2
#define DL_WARN	1
#define DL_ERROR	0

#define DEBUG_LVL DL_WARN

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

#pragma warning(disable: 4127)

#define DEBUGP(lvl, ...)				\
{								\
	if ((lvl) <= DEBUG_LVL)			\
	{							\
		DbgPrintExWithPrefix("NTA: ",	\
			DPFLTR_IHVNETWORK_ID,	\
			lvl,					\
			__VA_ARGS__);			\
	}							\
}

#else // DBG

#define DEBUGP(lev, ...)

#endif // DBG

#define ETH_ALEN 6
#define ETH_TYPE_IP 0x0800

#define ntohs(x) \
	((((x) & 0x00ff) << 8) | \
	(((x) & 0xff00) >> 8))

#define NORMALIZATION_OF_ADDRESS(ip) \
	(PUINT8)&(ip);

#define SIZE_OF_ADDRESS_ARRAY 128


struct _ETH_HEADER
{
	UCHAR h_dest[ETH_ALEN];
	UCHAR h_source[ETH_ALEN];
	USHORT h_proto;
};

struct _IP_HEADER
{
	UCHAR ip_hl : 4;
	UCHAR ip_v : 4;
	UCHAR ip_tos;
	SHORT ip_len;
	USHORT ip_id;
	SHORT ip_off;
	UCHAR ip_ttl;
	UCHAR ip_p;
	USHORT ip_sum;
	UINT ip_src;
	UINT ip_dst;
};

struct _IP_ADDRESS
{
	UINT dst;
	UINT src;
};

struct _FILTER_EXTENSION
{
	NDIS_HANDLE hNdisFilterDevice;
	UINT arrayOfAddresses[SIZE_OF_ADDRESS_ARRAY];
	INT numberOfUniqueAddresses;
	INT numberOfFilteredPackets;
};

struct _FILTER_DEVICE_EXTENSION
{
	NDIS_HANDLE hNdisFilterDriver;
	NDIS_HANDLE hNdisDevice;
};


typedef struct _ETH_HEADER ETH_HEADER;
typedef struct _IP_HEADER IP_HEADER;
typedef struct _IP_ADDRESS IP_ADDRESS;
typedef struct _FILTER_EXTENSION FILTER_EXTENSION;
typedef struct _FILTER_DEVICE_EXTENSION FILTER_DEVICE_EXTENSION;

typedef ETH_HEADER *PETH_HEADER;
typedef IP_HEADER *PIP_HEADER;
typedef IP_ADDRESS *PIP_ADDRESS;
typedef FILTER_EXTENSION *PFILTER_EXTENSION;
typedef FILTER_DEVICE_EXTENSION *PFILTER_DEVICE_EXTENSION;

typedef 
VOID
(CALLBACK_IP)(
	PIP_ADDRESS,
	PVOID);


FILTER_PAUSE FilterPause;
FILTER_STATUS FilterStatus;
FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
DRIVER_UNLOAD DriverUnload;
FILTER_RESTART FilterRestart;
DRIVER_INITIALIZE DriverEntry;
FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;


NTSTATUS
DriverAccessControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp);

NDIS_STATUS
RegisteringDevice(
	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension);

VOID
DeregisteringDevice(
	NDIS_HANDLE hFilterDriver);

VOID
DeserializationNetBufferLists(
	PNET_BUFFER_LIST netBufferLists,
	CALLBACK_IP CallbackGettingIP,
	PVOID pContext);

BOOLEAN
CheckForUniq(
	PUINT ips,
	INT size,
	UINT newIp);

VOID
FixingIP(
	PIP_ADDRESS pIpAddress,
	PFILTER_EXTENSION pFilterExtension);


NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	DEBUGP(DL_TRACE, "==> DriverEntry\n");

	UNREFERENCED_PARAMETER(pRegistryPath);

	NDIS_STATUS status;

	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension;

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

	filterDriverCharacteristics.MajorDriverVersion = FILTER_MAJOR_DRIVER_VERSION;
	
	filterDriverCharacteristics.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
	filterDriverCharacteristics.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
	filterDriverCharacteristics.RestartHandler = FilterRestart;
	filterDriverCharacteristics.AttachHandler = FilterAttach;
	filterDriverCharacteristics.DetachHandler = FilterDetach;
	filterDriverCharacteristics.StatusHandler = FilterStatus;
	filterDriverCharacteristics.PauseHandler = FilterPause;

	pDriverObject->DriverUnload = DriverUnload;

	do
	{
		status = IoAllocateDriverObjectExtension(
			pDriverObject,
			(PVOID)DriverEntry,
			sizeof(FILTER_DEVICE_EXTENSION),
			&pFilterDeviceExtension);

		if (status != STATUS_SUCCESS)
		{
			DEBUGP(DL_ERROR, "Function 'IoAllocateDriverObjectExtension' failed\n");
			break;
		}

		status = NdisFRegisterFilterDriver(
			pDriverObject,
			NULL,
			&filterDriverCharacteristics,
			&pFilterDeviceExtension->hNdisFilterDriver);

		if (status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_ERROR, "Function 'NdisFRegisterFilterDriver' failed\n");
			break;
		}

		status = RegisteringDevice(pFilterDeviceExtension);

		if (status != NDIS_STATUS_SUCCESS)
		{
			NdisFDeregisterFilterDriver(pFilterDeviceExtension->hNdisFilterDriver);

			DEBUGP(DL_ERROR, "Function 'RegisteringDevice' failed\n");
			break;
		}

	} while (FALSE);

	DEBUGP(DL_TRACE, "<== DriverEntry - status: %i\n", status);
	return status;
}

NTSTATUS
DriverAccessControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	DEBUGP(DL_TRACE, "==> DriverAccessControlRoutine\n");

	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	ULONG infoLen = 0;

	switch (pIoStackLocation->MajorFunction)
	{
		case IRP_MJ_CREATE:
		{
			DEBUGP(DL_TRACE, "Driver handle has been opened\n");
			break;
		}

		case IRP_MJ_READ:
		{
			DEBUGP(DL_TRACE, "Request to read data\n");
			break;
		}

		case IRP_MJ_CLEANUP:
		{
			DEBUGP(DL_TRACE, "Driver handle has been cleared\n");
			break;
		}

		case IRP_MJ_CLOSE:
		{
			DEBUGP(DL_TRACE, "Driver handle has been closed\n");
			break;
		}
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = infoLen;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DEBUGP(DL_TRACE, "<== DriverAccessControlRoutine - status: %i\n", status);
	return status;
}

NDIS_STATUS
RegisteringDevice(
	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension)
{
	DEBUGP(DL_TRACE, "==> RegisteringDevice\n");

	NDIS_STATUS status;
	PDEVICE_OBJECT pDeviceObject;

	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLinkUnicodeString;

	NdisInitUnicodeString(&deviceLinkUnicodeString, LINKNAME_STRING);
	NdisInitUnicodeString(&deviceName, NTDEVICE_STRING);

	PDRIVER_DISPATCH pDriverDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
	NdisZeroMemory(pDriverDispatch, sizeof(pDriverDispatch));

	pDriverDispatch[IRP_MJ_CLEANUP] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_CREATE] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_CLOSE] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_READ] = DriverAccessControlRoutine;

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
			pFilterDeviceExtension->hNdisFilterDriver,
			&pDeviceObjectAttributes,
			&pDeviceObject,
			&pFilterDeviceExtension->hNdisDevice);

		if (status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_ERROR, "Function 'NdisRegisterDeviceEx' failed\n");
			break;
		}

		//pDeviceObject->Flags |= DO_BUFFERED_IO;

	} while (FALSE);

	DEBUGP(DL_TRACE, "<== RegisteringDevice - status: %i\n", status);
	return status;
}

NDIS_STATUS
FilterAttach(
	NDIS_HANDLE NdisFilterHandle,
	NDIS_HANDLE FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
	DEBUGP(DL_TRACE, "==> FilterAttach\n");

	UNREFERENCED_PARAMETER(FilterDriverContext);
	UNREFERENCED_PARAMETER(AttachParameters);

	NDIS_STATUS status;

	do
	{	
		PFILTER_EXTENSION pFilterExtension;

		pFilterExtension = NdisAllocateMemoryWithTagPriority(
			NdisFilterHandle,
			sizeof(FILTER_EXTENSION),
			FILTER_TAG,
			LowPoolPriority);

		if (!pFilterExtension)
		{
			status = STATUS_BUFFER_ALL_ZEROS;

			DEBUGP(DL_ERROR, "Function 'NdisAllocateMemoryWithTagPriority' failed\n");
			break;
		}

		NdisZeroMemory(pFilterExtension, sizeof(FILTER_EXTENSION));
		pFilterExtension->hNdisFilterDevice = NdisFilterHandle;

		NDIS_FILTER_ATTRIBUTES filterAttributes;
		NdisZeroMemory(&filterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));

		filterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		filterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
		filterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;

		status = NdisFSetAttributes(
			NdisFilterHandle,
			pFilterExtension,
			&filterAttributes);

		if (status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_ERROR, "Function 'NdisFSetAttributes' failed\n");
			break;
		}

	} while (FALSE);
	
	DEBUGP(DL_TRACE, "<== FilterAttach - status: %i\n", status);
	return status;
}

NDIS_STATUS
FilterRestart(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
	DEBUGP(DL_TRACE, "==> FilterRestart\n");

	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(RestartParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;

	DEBUGP(DL_TRACE, "<== FilterRestart - status %i\n", status);
	return status;
}

VOID
DeserializationNetBufferLists(
	PNET_BUFFER_LIST netBufferLists,
	CALLBACK_IP CallbackGettingIP,
	PVOID pContext)
{
	PUCHAR headerBuffer;
	PIP_HEADER ipHeader;
	PETH_HEADER ethHeader;

	for (
		PNET_BUFFER_LIST netBufferList = netBufferLists;
		netBufferList;
		netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList))
	{
		for (
			PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
			netBuffer;
			netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
		{
			headerBuffer = NdisGetDataBuffer(
				netBuffer,
				sizeof(ETH_HEADER) + sizeof(IP_HEADER),
				NULL, 1, 0);

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

			IP_ADDRESS ipAddress;
			ipAddress.dst = ipHeader->ip_dst;
			ipAddress.src = ipHeader->ip_src;

			CallbackGettingIP(&ipAddress, pContext);
		}
	}
}

BOOLEAN
CheckForUniq(
	PUINT ips,
	INT size,
	UINT newIp)
{
	for (INT i = 0; i < size; ++i)
	{
		if (ips[i] == newIp)
		{
			return FALSE;
		}
	}

	return TRUE;
}

VOID
SetIP(
	PFILTER_EXTENSION pFilterExtension,
	UINT ip)
{
	BOOLEAN status = CheckForUniq(
		pFilterExtension->arrayOfAddresses,
		pFilterExtension->numberOfUniqueAddresses,
		ip);

	if (status)
	{
		pFilterExtension->arrayOfAddresses[
			pFilterExtension->numberOfUniqueAddresses++] = ip;
	}
}

VOID
FixingIP(
	PIP_ADDRESS pIpAddress,
	PFILTER_EXTENSION pFilterExtension)
{
	SetIP(pFilterExtension, pIpAddress->dst);
	SetIP(pFilterExtension, pIpAddress->src);

	++pFilterExtension->numberOfFilteredPackets;

	PUINT8 ipDst = NORMALIZATION_OF_ADDRESS(pIpAddress->dst);
	PUINT8 ipSrc = NORMALIZATION_OF_ADDRESS(pIpAddress->src);

	DEBUGP(DL_WARN, "IP - %hhu.%hhu.%hhu.%hhu > %hhu.%hhu.%hhu.%hhu\n",
		ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3],
		ipDst[0], ipDst[1], ipDst[2], ipDst[3]);
}

VOID
FilterReturnNetBufferLists(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferLists,
	ULONG ReturnFlags)
{
	DEBUGP(DL_TRACE, "==> FilterReturnNetBufferLists\n");

	PFILTER_EXTENSION pFilterExtension = FilterModuleContext;

	DeserializationNetBufferLists(
		NetBufferLists,
		FixingIP,
		pFilterExtension);

	NdisFReturnNetBufferLists(
		pFilterExtension->hNdisFilterDevice,
		NetBufferLists,
		ReturnFlags);

	DEBUGP(DL_TRACE, "<== FilterReturnNetBufferLists\n");
}

VOID
FilterSendNetBufferListsComplete(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferList,
	ULONG SendCompleteFlags)
{
	DEBUGP(DL_TRACE, "==> FilterSendNetBufferListsComplete\n");

	PFILTER_EXTENSION pFilterExtension = FilterModuleContext;

	DeserializationNetBufferLists(
		NetBufferList,
		FixingIP,
		pFilterExtension);

	NdisFSendNetBufferListsComplete(
		pFilterExtension->hNdisFilterDevice,
		NetBufferList,
		SendCompleteFlags);

	DEBUGP(DL_TRACE, "<== FilterSendNetBufferListsComplete\n");
}

VOID
FilterStatus(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_STATUS_INDICATION StatusIndication)
{
	DEBUGP(DL_TRACE, "==> FilterStatus\n");

	PFILTER_EXTENSION pFilterExtension = FilterModuleContext;

	NdisFIndicateStatus(
		pFilterExtension->hNdisFilterDevice,
		StatusIndication);

	DEBUGP(DL_TRACE, "<== FilterStatus\n");
}

NDIS_STATUS
FilterPause(
	NDIS_HANDLE FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
	DEBUGP(DL_TRACE, "==> FilterPause\n");

	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(PauseParameters);

	NDIS_STATUS status = NDIS_STATUS_SUCCESS;

	DEBUGP(DL_TRACE, "<== FilterPause - status %i\n", status);
	return status;
}

VOID
FilterDetach(
	NDIS_HANDLE FilterModuleContext)
{
	DEBUGP(DL_TRACE, "==> FilterDetach\n");

	NdisFreeMemory(FilterModuleContext, sizeof(FILTER_EXTENSION), 0);

	DEBUGP(DL_TRACE, "<== FilterDetach\n");
}

VOID
DeregisteringDevice(
	NDIS_HANDLE hFilterDriver)
{
	DEBUGP(DL_TRACE, "==> DeregisteringDevice\n");

	NdisDeregisterDeviceEx(hFilterDriver);

	DEBUGP(DL_TRACE, "<== DeregisteringDevice\n");
}

VOID
DriverUnload(
	PDRIVER_OBJECT pDriverObject)
{
	DEBUGP(DL_TRACE, "==> DriverUnload\n");

	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension
		= IoGetDriverObjectExtension(pDriverObject, (PVOID)DriverEntry);

	DeregisteringDevice(pFilterDeviceExtension->hNdisDevice);
	NdisFDeregisterFilterDriver(pFilterDeviceExtension->hNdisFilterDriver);

	DEBUGP(DL_TRACE, "<== DriverUnload\n");
}
