#include <windows.h>
#include <stdio.h>

#define HEADER									\
	"+------------------------------------------+\n"	\
	"|         Network Traffic Analyzer         |\n"	\
	"+----+-----------------+-------------------+\n"	\
	"| #  |       IP        |        MAC        |\n"	\
	"+----+-----------------+-------------------+\n"

#define FOOTER									\
	"+----+-----------------+-------------------+\n"

#define DEVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define DEVICE_PATH \
	L"\\\\.\\" DEVICE_NAME

#define BUFF_SIZE 64
#define ETH_ALEN 6

typedef struct _OUTPUT_DATA_EXTENSION
{
	UINT8 mac[ETH_ALEN];
	UINT ip;

} OUTPUT_DATA_EXTENSION, *POUTPUT_DATA_EXTENSION;

VOID
SetPos(
	INT x,
	INT y)
{
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), (COORD){ x, y });
}

COORD
GetConsoleCursorPosition(
	VOID)
{
	CONSOLE_SCREEN_BUFFER_INFO cbsi;
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cbsi);
	return cbsi.dwCursorPosition;
}

INT
main(
	VOID)
{
	HANDLE hDevice = CreateFile(
		DEVICE_PATH,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Function 'CreateFile' failed - status: %d", GetLastError());
		return -1;
	}

	OUTPUT_DATA_EXTENSION ipAddresses[BUFF_SIZE] = { 0 };

	DWORD r;
	BOOL status = ReadFile(
		hDevice,
		ipAddresses,
		sizeof(ipAddresses),
		&r,
		NULL);

	if (!status)
	{
		CloseHandle(hDevice);
		printf("Function 'ReadFile' failed - status: %d", GetLastError());
		return -1;
	}

	printf(HEADER);

	PUINT8 ip;
	PUINT8 mac;
	INT count = r / sizeof(OUTPUT_DATA_EXTENSION);
	COORD nowCoords = GetConsoleCursorPosition();

	for (INT i = 0; i < count; ++i)
	{
		ip = (PUINT8)&ipAddresses[i].ip;
		mac = ipAddresses[i].mac;

		printf("|");
		SetPos(2, nowCoords.Y + i);
		printf("%u", i + 1);
		SetPos(5, nowCoords.Y + i);
		printf("| %hhu.%hhu.%hhu.%hhu ", ip[0], ip[1], ip[2], ip[3]);
		SetPos(23, nowCoords.Y + i);
		printf("| %02x:%02x:%02x:%02x:%02x:%02x ", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		SetPos(43, nowCoords.Y + i);
		printf("|\n");
	}

	printf(FOOTER);

	CloseHandle(hDevice);
	return 0;
}