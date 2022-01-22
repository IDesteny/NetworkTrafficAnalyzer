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

#define BASE_MINIPORT_NAME \
	L"Intel(R) 82574L Gigabit Network Connection"

#define FILTER_FRIENDLY_NAME \
	FILTER_SERVICE_NAME L" NDIS Filter"

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

	vDbgPrintExWithPrefix(
		pref,
		ComponentId,
		Level,
		Fmt,
		arglist);

	va_end(arglist);
}

INT
GetDebugLevel(
	VOID)
{
	return DEBUG_LVL;
}

#define DEBUGP(lvl, ...)				\
{								\
	if ((lvl) <= GetDebugLevel())		\
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

#define ntohs(x)			\
	((((x) & 0x00ff) << 8) | \
	(((x) & 0xff00) >> 8))

#define NORMALIZATION_OF_ADDRESS(addr) \
	(PUINT8)&(addr);

#define DRIVER_POOL_ID \
	(PVOID)DriverEntry

#define SIZEOF_FILTER_DEVICE_EXTENSION \
	sizeof(FILTER_DEVICE_EXTENSION)

#define SIZEOF_FILTER_EXTENSION \
	sizeof(FILTER_EXTENSION)

#define SIZEOF_IP_ADDRESS_LIST_ENTRY \
	sizeof(IP_ADDRESS_LIST_ENTRY)

#define SIZEOF_BASE_MINIPORT \
	sizeof(BASE_MINIPORT_NAME)

#define LIST_ENTRY_FOR_EACH(Entry, ListHead)			\
	for(										\
		PLIST_ENTRY (Entry) = (ListHead)->Flink;	\
		(Entry) != (ListHead);					\
		(Entry) = (Entry)->Flink)

#define NET_BUFFER_LISTS_FOR_EACH(Entry, ListHead)	\
	for (									\
		PNET_BUFFER_LIST (Entry) = ListHead;		\
		(Entry);								\
		(Entry) = NET_BUFFER_LIST_NEXT_NBL(Entry))

#define NET_BUFFER_LIST_FOR_EACH(Entry, ListHead)					\
	for (												\
		PNET_BUFFER (Entry) = NET_BUFFER_LIST_FIRST_NB(ListHead);	\
		(Entry);											\
		(Entry) = NET_BUFFER_NEXT_NB(Entry))


typedef struct _ETH_HEADER
{
	UCHAR h_dest[ETH_ALEN];
	UCHAR h_source[ETH_ALEN];
	USHORT h_proto;

} ETH_HEADER, *PETH_HEADER;

typedef struct _IP_HEADER
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

} IP_HEADER, *PIP_HEADER;

typedef struct _DESERIALIZATION_INFO
{
	UINT ipDst;
	UINT ipSrc;

} DESERIALIZATION_INFO, *PDESERIALIZATION_INFO;

typedef struct _IP_ADDRESS_LIST_ENTRY
{
	LIST_ENTRY listEntry;
	UINT ip;

} IP_ADDRESS_LIST_ENTRY, *PIP_ADDRESS_LIST_ENTRY;

typedef struct _FILTER_EXTENSION
{
	NDIS_HANDLE hNdisFilterDevice;
	IP_ADDRESS_LIST_ENTRY ipAddressListEntry;

} FILTER_EXTENSION, *PFILTER_EXTENSION;

typedef struct _FILTER_DEVICE_EXTENSION
{
	NDIS_HANDLE hNdisFilterDriver;
	NDIS_HANDLE hNdisDevice;

} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


FILTER_PAUSE FilterPause;
FILTER_STATUS FilterStatus;
FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
DRIVER_UNLOAD DriverUnload;
FILTER_RESTART FilterRestart;
DRIVER_INITIALIZE DriverEntry;
FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;

PLIST_ENTRY pGlobalHeadListEntry;

INT
GetListLength(
	PLIST_ENTRY pHeadList)
{
	INT listLen = 0;
	LIST_ENTRY_FOR_EACH(entry, pHeadList)
	{
		++listLen;
	}

	return listLen;
}

VOID
IoCompleteIrp(
	PIRP pIrp,
	NTSTATUS status,
	ULONG infoLen)
{
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = infoLen;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
}

NTSTATUS
DriverAccessControlRoutine(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	DEBUGP(DL_TRACE, "==> DriverAccessControlRoutine\n");

	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG infoLen = 0;

	do
	{
		if (!pGlobalHeadListEntry)
		{
			DEBUGP(DL_WARN, "Invalid base miniport name\n");
			break;
		}

		PIO_STACK_LOCATION pIoStackLocation;
		pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

		INT listLen = GetListLength(pGlobalHeadListEntry);
		infoLen = listLen * sizeof(UINT);

		ULONG userBuffLen;
		userBuffLen = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

		if (userBuffLen < infoLen)
		{
			DEBUGP(DL_WARN, "Not enough buffer size. User Buffer: %lu, Necessary: %lu\n", userBuffLen, infoLen);

			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PUINT outBuffer = pIrp->UserBuffer;
		NdisZeroMemory(outBuffer, infoLen);

		INT iterList = 0;
		PIP_ADDRESS_LIST_ENTRY pIp;

		LIST_ENTRY_FOR_EACH(entry, pGlobalHeadListEntry)
		{
			pIp = CONTAINING_RECORD(
				entry,
				IP_ADDRESS_LIST_ENTRY,
				listEntry);

			outBuffer[iterList++] = pIp->ip;
		}

	} while (FALSE);

	IoCompleteIrp(pIrp, status, infoLen);

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

	pDriverDispatch[IRP_MJ_CREATE] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_CLOSE] = DriverAccessControlRoutine;
	pDriverDispatch[IRP_MJ_READ] = DriverAccessControlRoutine;

	NDIS_DEVICE_OBJECT_ATTRIBUTES deviceObjectAttributes;
	NdisZeroMemory(&deviceObjectAttributes, NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1);

	deviceObjectAttributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	deviceObjectAttributes.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	deviceObjectAttributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;

	deviceObjectAttributes.MajorFunctions = pDriverDispatch;
	deviceObjectAttributes.DeviceName = &deviceName;
	deviceObjectAttributes.SymbolicName = &deviceLinkUnicodeString;

	do
	{
		status = NdisRegisterDeviceEx(
			pFilterDeviceExtension->hNdisFilterDriver,
			&deviceObjectAttributes,
			&pDeviceObject,
			&pFilterDeviceExtension->hNdisDevice);

		if (status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_ERROR, "Function 'NdisRegisterDeviceEx' failed\n");
			break;
		}

	} while (FALSE);

	DEBUGP(DL_TRACE, "<== RegisteringDevice - status: %i\n", status);
	return status;
}

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
	NdisZeroMemory(&filterDriverCharacteristics, NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2);

	filterDriverCharacteristics.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
	filterDriverCharacteristics.Header.Size = NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;
	filterDriverCharacteristics.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;

	filterDriverCharacteristics.MajorDriverVersion = FILTER_MAJOR_DRIVER_VERSION;

	filterDriverCharacteristics.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
	filterDriverCharacteristics.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;

	filterDriverCharacteristics.FriendlyName = friendlyName;
	filterDriverCharacteristics.ServiceName = serviceName;
	filterDriverCharacteristics.UniqueName = uniqueName;

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
			DRIVER_POOL_ID,
			SIZEOF_FILTER_DEVICE_EXTENSION,
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
			NdisFDeregisterFilterDriver(
				pFilterDeviceExtension->hNdisFilterDriver);

			DEBUGP(DL_ERROR, "Function 'RegisteringDevice' failed\n");
			break;
		}

	} while (FALSE);

	DEBUGP(DL_TRACE, "<== DriverEntry - status: %i\n", status);
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
	NDIS_STATUS status;

	do
	{
		NDIS_MEDIUM mediaType = AttachParameters->MiniportMediaType;

		if (mediaType != NdisMedium802_3 &&
			mediaType != NdisMediumWan &&
			mediaType != NdisMediumWirelessWan)
		{
			DEBUGP(DL_ERROR, "Unsupported media type\n");

			status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		PFILTER_EXTENSION pFilterExtension;
		pFilterExtension = NdisAllocateMemoryWithTagPriority(
			NdisFilterHandle,
			SIZEOF_FILTER_EXTENSION,
			FILTER_TAG,
			LowPoolPriority);

		if (!pFilterExtension)
		{
			DEBUGP(DL_ERROR, "Function 'NdisAllocateMemoryWithTagPriority' failed\n");

			status = STATUS_BUFFER_ALL_ZEROS;
			break;
		}

		NdisZeroMemory(pFilterExtension, SIZEOF_FILTER_EXTENSION);
		pFilterExtension->hNdisFilterDevice = NdisFilterHandle;
		
		PLIST_ENTRY pHeadListEntry;
		pHeadListEntry = &pFilterExtension->ipAddressListEntry.listEntry;
		InitializeListHead(pHeadListEntry);

		SIZE_T result = RtlCompareMemory(
			AttachParameters->BaseMiniportInstanceName->Buffer,
			BASE_MINIPORT_NAME,
			SIZEOF_BASE_MINIPORT);

		if (result == SIZEOF_BASE_MINIPORT)
		{
			pGlobalHeadListEntry = &pFilterExtension->ipAddressListEntry.listEntry;
		}

		NDIS_FILTER_ATTRIBUTES filterAttributes;
		NdisZeroMemory(&filterAttributes, NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1);

		filterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		filterAttributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
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

BOOLEAN
CheckForUniq(
	PIP_ADDRESS_LIST_ENTRY pIpAddressListEntry,
	UINT newIp)
{
	PLIST_ENTRY pHeadListEntry = &pIpAddressListEntry->listEntry;
	PIP_ADDRESS_LIST_ENTRY pCurrentIpAddressListEntry;

	LIST_ENTRY_FOR_EACH(entry, pHeadListEntry)
	{
		pCurrentIpAddressListEntry = CONTAINING_RECORD(
			entry,
			IP_ADDRESS_LIST_ENTRY,
			listEntry);

		if (pCurrentIpAddressListEntry->ip == newIp)
		{
			return FALSE;
		}
	}

	return TRUE;
}

VOID
InsertIp(
	PIP_ADDRESS_LIST_ENTRY pIpAddressListEntry,
	UINT ip)
{
	do
	{
		if (!CheckForUniq(pIpAddressListEntry, ip))
		{
			break;
		}

		PIP_ADDRESS_LIST_ENTRY pNewIpAddressListEntry;
		pNewIpAddressListEntry = ExAllocatePool2(
			POOL_FLAG_NON_PAGED,
			SIZEOF_IP_ADDRESS_LIST_ENTRY,
			FILTER_TAG);

		if (!pNewIpAddressListEntry)
		{
			DEBUGP(DL_ERROR, "Function 'ExAllocatePool2' failed\n");
			break;
		}

		pNewIpAddressListEntry->ip = ip;

		InsertHeadList(
			&pIpAddressListEntry->listEntry,
			&pNewIpAddressListEntry->listEntry);

	} while (FALSE);
}

VOID
IpAddressHandler(
	PIP_ADDRESS_LIST_ENTRY pIpAddressListEntry,
	PDESERIALIZATION_INFO pDeserealizationInfo)
{
	InsertIp(pIpAddressListEntry, pDeserealizationInfo->ipDst);
	InsertIp(pIpAddressListEntry, pDeserealizationInfo->ipSrc);

	PUINT8 pIpDst = NORMALIZATION_OF_ADDRESS(pDeserealizationInfo->ipDst);
	PUINT8 pIpSrc = NORMALIZATION_OF_ADDRESS(pDeserealizationInfo->ipSrc);

	DEBUGP(DL_INFO,
		"IP - %hhu.%hhu.%hhu.%hhu > %hhu.%hhu.%hhu.%hhu\n",

		pIpSrc[0], pIpSrc[1], pIpSrc[2], pIpSrc[3],
		pIpDst[0], pIpDst[1], pIpDst[2], pIpDst[3]);
}

VOID
DeserializationNetBufferLists(
	PIP_ADDRESS_LIST_ENTRY pIpAddressListEntry,
	PNET_BUFFER_LIST netBufferLists)
{
	PUCHAR headerBuffer;
	PIP_HEADER ipHeader;
	PETH_HEADER ethHeader;
	DESERIALIZATION_INFO deserealizationInfo;

	NET_BUFFER_LISTS_FOR_EACH(netBufferList, netBufferLists)
	{
		NET_BUFFER_LIST_FOR_EACH(netBuffer, netBufferList)
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

			deserealizationInfo.ipDst = ipHeader->ip_dst;
			deserealizationInfo.ipSrc = ipHeader->ip_src;

			IpAddressHandler(pIpAddressListEntry, &deserealizationInfo);
		}
	}
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
		&pFilterExtension->ipAddressListEntry,
		NetBufferLists);

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
		&pFilterExtension->ipAddressListEntry,
		NetBufferList);

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

	PFILTER_EXTENSION pFilterExtension = FilterModuleContext;
	PIP_ADDRESS_LIST_ENTRY pIpAddressListEntry;

	PLIST_ENTRY pHeadListEntry;
	pHeadListEntry = &pFilterExtension->ipAddressListEntry.listEntry;

	PLIST_ENTRY delEntry;
	while (pHeadListEntry->Flink != pHeadListEntry)
	{
		delEntry = RemoveHeadList(pHeadListEntry);

		pIpAddressListEntry = CONTAINING_RECORD(
			delEntry,
			IP_ADDRESS_LIST_ENTRY,
			listEntry);

		ExFreePoolWithTag(pIpAddressListEntry, FILTER_TAG);
	}

	NdisFreeMemoryWithTagPriority(
		pFilterExtension->hNdisFilterDevice,
		FilterModuleContext,
		FILTER_TAG);

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

	PFILTER_DEVICE_EXTENSION pFilterDeviceExtension;
	pFilterDeviceExtension = IoGetDriverObjectExtension(pDriverObject, DRIVER_POOL_ID);

	DeregisteringDevice(pFilterDeviceExtension->hNdisDevice);
	NdisFDeregisterFilterDriver(pFilterDeviceExtension->hNdisFilterDriver);

	DEBUGP(DL_TRACE, "<== DriverUnload\n");
}