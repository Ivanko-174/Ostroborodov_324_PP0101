#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <stdio.h>
#include <strsafe.h>
#include <shellapi.h>
#include <winioctl.h>
#include <dbt.h>
#include <vds.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <ntdddisk.h>
#include <winioctl.h>
#include <fileapi.h>
#include <virtdisk.h>
#include <diskguid.h>
#include <tchar.h>
#include <shlobj_core.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <inttypes.h>
#include <ntddstor.h>
#include <tlhelp32.h>
#include "resourse.h"


#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "VirtDisk.lib")
#pragma comment(lib, "shell32.lib")

#define MAX_DISKS 16
#define MAX_PARTITIONS 32

#define SHFMT_ERROR     (-1)
#define SHFMT_CANCEL    (-2)
#define SHFMT_NOFORMAT  (-3)

// информация о диске
typedef struct {
    TCHAR diskName[32];
    TCHAR diskSize[32];
    TCHAR diskModel[128];
    TCHAR driveLetters[64];
    DWORD diskNumber;
    DWORD bytesPerSector;
    ULONGLONG diskSizeBytes;
} DISK_INFO;

// информация о партиции
typedef struct {
    TCHAR partitionName[32];
    TCHAR partitionSize[32];
    TCHAR partitionType[32];
    TCHAR driveLetter;
    DWORD partitionNumber;
    ULONGLONG partitionStart;
    ULONGLONG partitionSizeBytes;
    PARTITION_STYLE partitionStyle;
    GUID partitionTypeGuid;
} PARTITION_INFO;

// данные для приложения (и интерфейса в частности)
typedef struct {
    HWND hMainDlg;
    HWND hDiskList;
    HWND hPartitionList;
    HWND hStatusBar;
    HWND hPartitionSize;
    HWND hPartitionLetter;
    HWND hPartitionType;

    DISK_INFO disks[MAX_DISKS];
    PARTITION_INFO partitions[MAX_PARTITIONS];

    int diskCount;
    int partitionCount;
    int selectedDisk;
    int selectedPartition;
} APP_DATA;

// Методы, которые пригодятся в дальнейшем
BOOL CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
void InitializeApp(APP_DATA* pAppData, HWND hDlg);
void RefreshDiskList(APP_DATA* pAppData);
void RefreshPartitionList(APP_DATA* pAppData);
void UpdateStatusBar(APP_DATA* pAppData, LPCTSTR szText);
BOOL GetDiskInfo(APP_DATA* pAppData);
BOOL GetPartitionInfo(APP_DATA* pAppData);
void ShowErrorMessage(LPCTSTR szMessage);
BOOL CreatePartition(APP_DATA* pAppData, DWORD sizeMB, TCHAR driveLetter, LPCTSTR fileSystem);
BOOL DeletePartition(APP_DATA* pAppData);
BOOL GetDriveLetterFromDevice(HANDLE hVolume, TCHAR* driveLetter);
BOOL FormatPartition(TCHAR driveLetter, LPCTSTR fileSystem, LPCTSTR volumeLabel);
BOOL ChangeDriveLetter(TCHAR oldLetter, TCHAR newLetter);
BOOL IsValidDriveLetter(TCHAR letter);
BOOL IsDriveLetterAvailable(TCHAR letter);
void BytesToHumanReadable(ULONGLONG bytes, LPTSTR output, size_t outputSize);


//проверка на права администратора
bool IsRunningAsAdmin() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return fIsElevated != 0;
}



// инициализация приложения
void InitializeApp(APP_DATA* pAppData, HWND hDlg)
{
    pAppData->hMainDlg = hDlg;
    pAppData->hDiskList = GetDlgItem(hDlg, IDC_DISK_LIST);
    pAppData->hPartitionList = GetDlgItem(hDlg, IDC_PARTITION_LIST);
    pAppData->hStatusBar = GetDlgItem(hDlg, IDC_STATUS_BAR);
    pAppData->hPartitionSize = GetDlgItem(hDlg, IDC_PARTITION_SIZE);
    pAppData->hPartitionLetter = GetDlgItem(hDlg, IDC_PARTITION_LETTER);
    pAppData->hPartitionType = GetDlgItem(hDlg, IDC_PARTITION_TYPE);

    // комбо бокс для файловых систем
    SendMessage(pAppData->hPartitionType, CB_ADDSTRING, 0, (LPARAM)TEXT("NTFS"));
    SendMessage(pAppData->hPartitionType, CB_ADDSTRING, 0, (LPARAM)TEXT("FAT32"));
    SendMessage(pAppData->hPartitionType, CB_ADDSTRING, 0, (LPARAM)TEXT("exFAT"));
    SendMessage(pAppData->hPartitionType, CB_SETCURSEL, 0, 0);


    // стандартный размер партиций
    SetWindowText(pAppData->hPartitionSize, TEXT("1024"));

    // прогресс
    UpdateStatusBar(pAppData, TEXT("Ready"));

    // инфа о диске и партициях
    RefreshDiskList(pAppData);
}

//Обновить список дисков
void RefreshDiskList(APP_DATA* pAppData)
{
    SendMessage(pAppData->hDiskList, LB_RESETCONTENT, 0, 0);
    pAppData->diskCount = 0;
    pAppData->selectedDisk = -1;    

    if (!GetDiskInfo(pAppData))
    {
        ShowErrorMessage(TEXT("Failed to get disk information"));
        return;
    }

    for (int i = 0; i < pAppData->diskCount; i++)
    {
        TCHAR szDisplay[256];
        StringCchPrintf(szDisplay, 256, TEXT("Disk %d (%s) - %s"),
            pAppData->disks[i].diskNumber,
            pAppData->disks[i].diskSize,
            pAppData->disks[i].diskModel);
        SendMessage(pAppData->hDiskList, LB_ADDSTRING, 0, (LPARAM)szDisplay);
    }

    MessageBox(NULL, L"success!", L"Error", MB_ICONASTERISK);

    if (pAppData->diskCount > 0)
    {
        SendMessage(pAppData->hDiskList, LB_SETCURSEL, 0, 0);
        pAppData->selectedDisk = 0;
        RefreshPartitionList(pAppData);
    }

    

    UpdateStatusBar(pAppData, TEXT("Disk list refreshed"));
}

std::vector<std::wstring> GetUSBDrives() {
    std::vector<std::wstring> usbDrives;
    WCHAR driveStrings[1024];
    GetLogicalDriveStringsW(1024, driveStrings);
    WCHAR* p = driveStrings;

    while (*p) {
        std::wstring drive = p;
        std::wstring volumePath = L"\\\\.\\" + drive.substr(0, 2);
        HANDLE hVol = CreateFileW(volumePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (hVol != INVALID_HANDLE_VALUE) {
            VOLUME_DISK_EXTENTS extents;
            DWORD bytesReturned;
            if (DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &extents, sizeof(extents), &bytesReturned, NULL)) {
                if (extents.NumberOfDiskExtents > 0) {
                    WCHAR diskPath[64];
                    swprintf(diskPath, 64, L"\\\\.\\PhysicalDrive%d", extents.Extents[0].DiskNumber);
                    HANDLE hDisk = CreateFileW(diskPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

                    if (hDisk != INVALID_HANDLE_VALUE) {
                        STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty, PropertyStandardQuery };
                        STORAGE_DESCRIPTOR_HEADER header;
                        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &header, sizeof(header), &bytesReturned, NULL)) {
                            PSTORAGE_DEVICE_DESCRIPTOR pDescriptor = (PSTORAGE_DEVICE_DESCRIPTOR)malloc(header.Size);
                            if (pDescriptor == NULL) {
                                ShowErrorMessage(TEXT("Failed to allocate memory for device descriptor"));
                                CloseHandle(hDisk);
                                continue;
                            }
                            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), pDescriptor, header.Size, &bytesReturned, NULL)) {
                                if (pDescriptor->BusType == BusTypeUsb) {
                                    usbDrives.push_back(drive.substr(0, 2));
                                }
                            }
                            free(pDescriptor);
                        }
                        CloseHandle(hDisk);
                    }
                }
            }
            CloseHandle(hVol);
        }
        p += drive.length() + 1;
    }
    return usbDrives;
}

//чтобы было видно, что за диск
void GetDriveLettersForDisk(DWORD diskNumber, LPTSTR output, size_t outputSize) {
    TCHAR physicalDrive[MAX_PATH];
    StringCchPrintf(physicalDrive, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), diskNumber);

    TCHAR volumeName[MAX_PATH];
    HANDLE hFind = FindFirstVolume(volumeName, MAX_PATH);
    output[0] = 0; // пусто

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            TCHAR deviceName[MAX_PATH];
            DWORD charCount = MAX_PATH;

            if (GetVolumePathNamesForVolumeName(volumeName, deviceName, charCount, &charCount)) {
                if (deviceName[0] != 0) {
                    TCHAR physicalPath[MAX_PATH];
                    DWORD pathLength = MAX_PATH;

                    if (QueryDosDevice(&deviceName[0], physicalPath, pathLength)) {
                        if (_tcsstr(physicalPath, physicalDrive) != NULL) {
                            
                            if (output[0] != 0) {
                                StringCchCat(output, outputSize, TEXT(","));
                            }
                            
                            TCHAR driveLetter[3] = { deviceName[0], ':', 0 };
                            StringCchCat(output, outputSize, driveLetter);
                        }
                    }
                }
            }
        } while (FindNextVolume(hFind, volumeName, MAX_PATH));

        FindVolumeClose(hFind);
    }

    if (output[0] == 0) {
        StringCchCopy(output, outputSize, TEXT("No letters"));
    }
}

// Обновление списка партиций
void RefreshPartitionList(APP_DATA* pAppData)
{
    SendMessage(pAppData->hPartitionList, LB_RESETCONTENT, 0, 0);
    pAppData->partitionCount = 0;
    pAppData->selectedPartition = -1;

    if (pAppData->selectedDisk < 0)
        return;

    if (!GetPartitionInfo(pAppData))
    {
        ShowErrorMessage(TEXT("Failed to get partition information"));
        return;
    }

    for (int i = 0; i < pAppData->partitionCount; i++)
    {
        TCHAR szDisplay[256];

        TCHAR driveLetters[MAX_PATH] = TEXT("");
        GetDriveLettersForDisk(pAppData->disks[i].diskNumber, driveLetters, MAX_PATH);

        StringCchPrintf(szDisplay, 256, TEXT("Disk %d (%s) - %s - %s"),
            pAppData->partitions[i].partitionName,
            pAppData->partitions[i].partitionSize,
            pAppData->partitions[i].driveLetter,
            pAppData->partitions[i].partitionType);
        SendMessage(pAppData->hPartitionList, LB_ADDSTRING, 0, (LPARAM)szDisplay);
    }

    if (pAppData->partitionCount > 0)
    {
        SendMessage(pAppData->hPartitionList, LB_SETCURSEL, 0, 0);
        pAppData->selectedPartition = 0;
    }

    UpdateStatusBar(pAppData, TEXT("Partition list refreshed"));
}

// информация о диске (windows.API)
BOOL GetDiskInfo(APP_DATA* pAppData) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_DISK, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        MessageBox(NULL, L"SetupDiGetClassDevs failed", L"Error", MB_ICONERROR);
        return FALSE;
    }

    SP_DEVINFO_DATA DeviceInfoData = { sizeof(SP_DEVINFO_DATA) };
    DWORD deviceIndex = 0;

    while (SetupDiEnumDeviceInfo(hDevInfo, deviceIndex++, &DeviceInfoData)) {
        TCHAR deviceID[MAX_PATH];
        if (!SetupDiGetDeviceInstanceId(hDevInfo, &DeviceInfoData, deviceID, MAX_PATH, NULL)) {
            continue;
        }

        // Открыть физ диск
        TCHAR diskPath[MAX_PATH];
        StringCchPrintf(diskPath, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), pAppData->diskCount);

        HANDLE hDisk = CreateFile(diskPath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hDisk == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            continue;
        }

        // размер диска
        DISK_GEOMETRY_EX diskGeometry = { 0 };
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            NULL, 0, 
            &diskGeometry, 
            sizeof(diskGeometry),
            &bytesReturned, NULL)) {
            CloseHandle(hDisk);
            continue;
        }

        // основная информация
        pAppData->disks[pAppData->diskCount].diskNumber = pAppData->diskCount;
        pAppData->disks[pAppData->diskCount].diskSizeBytes = diskGeometry.DiskSize.QuadPart;
        CloseHandle(hDisk);
        pAppData->diskCount++;
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return (pAppData->diskCount > 0);
}


// отобразить информацию о партициях с помощью Windows API
BOOL GetPartitionInfo(APP_DATA* pAppData)
{
    if (pAppData->selectedDisk < 0 || pAppData->selectedDisk >= pAppData->diskCount)
        return FALSE;

    TCHAR diskPath[MAX_PATH];
    HANDLE hDisk = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    DRIVE_LAYOUT_INFORMATION_EX* pLayout = NULL;
    DWORD layoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (MAX_PARTITIONS * sizeof(PARTITION_INFORMATION_EX));

    StringCchPrintf(diskPath, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), pAppData->selectedDisk);

    hDisk = CreateFile(diskPath, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    pLayout = (DRIVE_LAYOUT_INFORMATION_EX*)malloc(layoutSize);
    if (!pLayout)
    {
        CloseHandle(hDisk);
        return FALSE;
    }

    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, pLayout, layoutSize, &bytesReturned, NULL))
    {
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    pAppData->partitionCount = 0;

    for (DWORD i = 0; i < pLayout->PartitionCount && pAppData->partitionCount < MAX_PARTITIONS; i++)
    {
        if (pLayout->PartitionEntry[i].PartitionNumber == 0)
            continue;

        if (pLayout->PartitionEntry[i].PartitionLength.QuadPart == 0)
            continue;

        // о партициях
        PARTITION_INFORMATION_EX partInfo = pLayout->PartitionEntry[i];
        PARTITION_INFO* pPart = &pAppData->partitions[pAppData->partitionCount];

        pPart->partitionNumber = partInfo.PartitionNumber;
        pPart->partitionStart = partInfo.StartingOffset.QuadPart;
        pPart->partitionSizeBytes = partInfo.PartitionLength.QuadPart;
        pPart->partitionStyle = partInfo.PartitionStyle;

        BytesToHumanReadable(pPart->partitionSizeBytes, pPart->partitionSize, 32);

        // тип ФС
        if (partInfo.PartitionStyle == PARTITION_STYLE_MBR)
        {
            switch (partInfo.Mbr.PartitionType)
            {
            case PARTITION_IFS: // NTFS, FAT, exFAT...
                StringCchCopy(pPart->partitionType, 32, TEXT("NTFS"));
                break;
            case PARTITION_FAT32:
                StringCchCopy(pPart->partitionType, 32, TEXT("FAT32"));
                break;
            case PARTITION_FAT32_XINT13:
                StringCchCopy(pPart->partitionType, 32, TEXT("FAT32 (XINT13)"));
                break;
            case PARTITION_EXTENDED:
                StringCchCopy(pPart->partitionType, 32, TEXT("Extended"));
                break;
            default:
                StringCchPrintf(pPart->partitionType, 32, TEXT("Type 0x%02X"), partInfo.Mbr.PartitionType);
                break;
            }
        }
        /*else if (partInfo.PartitionStyle == PARTITION_STYLE_GPT)
        {
            if (IsEqualGUID(partInfo.Gpt.PartitionType, PARTITION_BASIC_DATA_GUID))
                StringCchCopy(pPart->partitionType, 32, TEXT("Basic Data"));
            else if (IsEqualGUID(partInfo.Gpt.PartitionType, PARTITION_MSFT_RESERVED_GUID))
                StringCchCopy(pPart->partitionType, 32, TEXT("MS Reserved"));
            else if (IsEqualGUID(partInfo.Gpt.PartitionType, PARTITION_SYSTEM_GUID))
                StringCchCopy(pPart->partitionType, 32, TEXT("EFI System"));
            else
                StringCchCopy(pPart->partitionType, 32, TEXT("GPT Unknown"));
        }*/
        else
        {
            StringCchCopy(pPart->partitionType, 32, TEXT("Unknown"));
        }

        // Имя партиции
        StringCchPrintf(pPart->partitionName, 32, TEXT("Partition %d"), partInfo.PartitionNumber);

        //Буква
        pPart->driveLetter = 0;
        TCHAR volumeName[MAX_PATH];
        HANDLE hFind = FindFirstVolume(volumeName, MAX_PATH);

        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                TCHAR deviceName[MAX_PATH];
                DWORD dwCharCount = MAX_PATH;

                if (GetVolumePathNamesForVolumeName(volumeName, deviceName, dwCharCount, &dwCharCount))
                {
                    if (deviceName[0] != 0)
                    {
                        TCHAR physicalPath[MAX_PATH];
                        DWORD pathLength = MAX_PATH;

                        if (QueryDosDevice(&deviceName[0], physicalPath, pathLength))
                        {
                            if (_tcsstr(physicalPath, diskPath) != NULL)
                            {
                                pPart->driveLetter = deviceName[0];
                                break;
                            }
                        }
                    }
                }
            } while (FindNextVolume(hFind, volumeName, MAX_PATH));

            FindVolumeClose(hFind);
        }

        pAppData->partitionCount++;
    }

    free(pLayout);
    CloseHandle(hDisk);
    return TRUE;
}

void VerifyPartitionCreation(int diskNumber)
{
    DWORD bytesReturned = 0;
    TCHAR diskPath[MAX_PATH];
    StringCchPrintf(diskPath, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), diskNumber);

    HANDLE hDisk = CreateFile(diskPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk != INVALID_HANDLE_VALUE)
    {
        DWORD layoutSize = 0;
        DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, NULL, 0, &layoutSize, NULL);

        DRIVE_LAYOUT_INFORMATION_EX* pLayout = (DRIVE_LAYOUT_INFORMATION_EX*)malloc(layoutSize);
        if (pLayout)
        {
            if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                NULL, 0, pLayout, layoutSize, &bytesReturned, NULL))
            {
                TCHAR debugMsg[256];
                StringCchPrintf(debugMsg, 256, TEXT("Current partition count: %d"), pLayout->PartitionCount);
                OutputDebugString(debugMsg);

                for (DWORD i = 0; i < pLayout->PartitionCount; i++)
                {
                    StringCchPrintf(debugMsg, 256, TEXT("Partition %d: Size %llu bytes"),
                        i, pLayout->PartitionEntry[i].PartitionLength.QuadPart);
                    OutputDebugString(debugMsg);
                }
            }
            free(pLayout);
        }
        CloseHandle(hDisk);
    }
    else {
        MessageBox(NULL, TEXT("No. Not yet"), TEXT("Bruh"), MB_ICONINFORMATION);
    }
}

void RescanDisks()
{
    // Заметка об изменениях в дискех...
    DEV_BROADCAST_VOLUME dbv = { 0 };
    dbv.dbcv_size = sizeof(dbv);
    dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME;
    dbv.dbcv_flags = DBTF_MEDIA;
    dbv.dbcv_unitmask = 0xFFFFFFFF; // ...Всех

    SendMessageTimeout(HWND_BROADCAST, WM_DEVICECHANGE, DBT_DEVICEARRIVAL,
        (LPARAM)&dbv, SMTO_ABORTIFHUNG, 1000, NULL);

    // Еще одно обновление дисков
    PostMessage(HWND_BROADCAST, WM_DEVICECHANGE, DBT_CONFIGCHANGED, 0);
}

// Создать партицию
BOOL CreatePartition(APP_DATA* pAppData, DWORD sizeMB, TCHAR driveLetter, LPCTSTR fileSystem)
{
    if (pAppData->selectedDisk < 0 || pAppData->selectedDisk >= pAppData->diskCount)
    {
        MessageBox(NULL, TEXT("Please select a valid disk first"), TEXT("Error"), MB_ICONERROR);
        return FALSE;
    }

    // МБ?
    ULONGLONG partitionSize = (ULONGLONG)sizeMB * 1024 * 1024;
    TCHAR diskPath[MAX_PATH];
    StringCchPrintf(diskPath, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), pAppData->selectedDisk);

    // Получение доступа к редактированию в диске
    HANDLE hDisk = CreateFile(diskPath, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        TCHAR errMsg[256];
        StringCchPrintf(errMsg, 256, TEXT("Failed to open disk (Error %d)"), err);
        MessageBox(NULL, errMsg, TEXT("Error"), MB_ICONERROR);
        return FALSE;
    }

    // Буфер
    DWORD layoutSize = 0;
    DWORD bytesReturned = 0;

    BOOL bResult = DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, NULL, 0, &layoutSize, NULL);

    DWORD lastError = GetLastError();
    if (!bResult && lastError != ERROR_INSUFFICIENT_BUFFER)
    {
        TCHAR errMsg[256];
        StringCchPrintf(errMsg, 256, TEXT("Failed to get layout size. Error: %d"), lastError);
        MessageBox(NULL, errMsg, TEXT("Error"), MB_ICONERROR);
        CloseHandle(hDisk);
        return FALSE;
    }

    // Зафиксировать мин размер буфера?
    if (layoutSize < sizeof(DRIVE_LAYOUT_INFORMATION_EX))
    {
        layoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (128 * sizeof(PARTITION_INFORMATION_EX));
    }

    // Выделение буфера
    DRIVE_LAYOUT_INFORMATION_EX* pLayout = (DRIVE_LAYOUT_INFORMATION_EX*)malloc(layoutSize);
    if (!pLayout)
    {
        CloseHandle(hDisk);
        MessageBox(NULL, TEXT("Memory allocation failed"), TEXT("Error"), MB_ICONERROR);
        return FALSE;
    }

    ZeroMemory(pLayout, layoutSize);

    // Получение данных 
    bResult = DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, pLayout, layoutSize, &bytesReturned, NULL);

    if (!bResult)
    {
        DWORD err = GetLastError();
        TCHAR errMsg[256];
        StringCchPrintf(errMsg, 256, TEXT("Failed to read disk layout. Error: %d"), err);

        if (err == ERROR_ACCESS_DENIED)
            StringCchCat(errMsg, 256, TEXT("\nTry running as Administrator."));
        else if (err == ERROR_NOT_READY)
            StringCchCat(errMsg, 256, TEXT("\nDisk may be offline or not initialized."));

        MessageBox(NULL, errMsg, TEXT("Error"), MB_ICONERROR);
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    // Снова размер в мегабайт и вычисление, сколько их осталось
    ULONGLONG offset = 0;
    if (pLayout->PartitionCount > 0)
    {
        PARTITION_INFORMATION_EX& lastPart = pLayout->PartitionEntry[pLayout->PartitionCount - 1];
        offset = lastPart.StartingOffset.QuadPart + lastPart.PartitionLength.QuadPart;
    }
    offset = ((offset + 0xFFFFF) / 0x100000) * 0x100000;

    // Геометрия диска (здесь для размера)
    DISK_GEOMETRY_EX diskGeometry = { 0 };
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0, &diskGeometry, sizeof(diskGeometry), &bytesReturned, NULL))
    {
        MessageBox(NULL, TEXT("Failed to get disk geometry (size)"), TEXT("Error"), MB_ICONERROR);
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    ULONGLONG freeSpace = diskGeometry.DiskSize.QuadPart - offset;

    if (partitionSize > freeSpace)
    {
        TCHAR msg[256];
        StringCchPrintf(msg, 256, TEXT("Not enough space. Available: %llu MB, Requested: %lu MB"),
            freeSpace / (1024 * 1024), sizeMB);
        MessageBox(NULL, msg, TEXT("Error"), MB_ICONERROR);
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    // Создание входа для партиции
    PARTITION_INFORMATION_EX newPartition = {  };
    newPartition.PartitionStyle = PARTITION_STYLE_MBR; // Потому-что конфликтует со стилем GPT. Пока что тут будет только MBR
    newPartition.StartingOffset.QuadPart = offset;
    newPartition.PartitionLength.QuadPart = partitionSize;
    newPartition.PartitionNumber = pLayout->PartitionCount + 1;

    if (pLayout->PartitionStyle == PARTITION_STYLE_MBR)
    {
        newPartition.Mbr.BootIndicator = FALSE;
        newPartition.Mbr.RecognizedPartition = TRUE;
        newPartition.Mbr.HiddenSectors = (DWORD)(offset / diskGeometry.Geometry.BytesPerSector);

        if (lstrcmpi(fileSystem, TEXT("FAT32")) == 0)
            newPartition.Mbr.PartitionType = PARTITION_FAT32;
        else
            newPartition.Mbr.PartitionType = PARTITION_IFS; // Эксперимент (надо будет использовать NTFS. IFS регает за себя почти все)
    }
    //else if (pLayout->PartitionStyle == PARTITION_STYLE_GPT)
    //{
    //    newPartition.Gpt.Attributes = 0;
    //    if (lstrcmpi(fileSystem, TEXT("FAT32")) == 0)
    //        newPartition.Gpt.PartitionType = PARTITION_MSFT_BASIC_DATA_GUID;
    //    else
    //        newPartition.Gpt.PartitionType = PARTITION_BASIC_DATA_GUID;

    //    StringCchCopyW(newPartition.Gpt.Name, 128, L"Basic Data Partition");
    //}

    // Проверка на восприятие количества партиций
    if (pLayout->PartitionCount >= 128)
    {
        MessageBox(NULL, TEXT("Maximum partition limit reached"), TEXT("Error"), MB_ICONERROR);
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    pLayout->PartitionEntry[pLayout->PartitionCount] = newPartition;
    pLayout->PartitionCount++;

    

    //// Форматирование лучше сделать отдельным




    // Регистрация изменения непосредственно в диск
    if (!DeviceIoControl(hDisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
        pLayout, layoutSize, NULL, 0, &bytesReturned, NULL))
    {
        DWORD err = GetLastError();
        TCHAR errMsg[256];
        StringCchPrintf(errMsg, 256, TEXT("Failed to write partition table (Error %d)"), err);
        MessageBox(NULL, errMsg, TEXT("Error"), MB_ICONERROR);
        free(pLayout);
        CloseHandle(hDisk);
        return FALSE;
    }

    // Обновляем свойства диска для учета изменений
    if (!DeviceIoControl(hDisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        DWORD err = GetLastError();
        TCHAR errMsg[256];
        StringCchPrintf(errMsg, 256, TEXT("Failed to update disk properties (Error %d)"), err);
        MessageBox(NULL, errMsg, TEXT("Warning"), MB_ICONWARNING);

    }

    VerifyPartitionCreation(pAppData->selectedDisk);

    // Сборщик
    free(pLayout);
    CloseHandle(hDisk);

    // Надо заставить сисему увидеть партицию
    RescanDisks();

    // Может, больше времени на обработку?
    Sleep(5000);



    MessageBox(NULL, TEXT("Partition created successfully! Please assign drive letter and format manually in Disk Management."), TEXT("Success"), MB_ICONINFORMATION);
    return TRUE;
}

// удаление партиции
BOOL DeletePartition(APP_DATA* pAppData)
{
    if (pAppData->selectedDisk < 0 || pAppData->selectedDisk >= pAppData->diskCount)
        return FALSE;
    if (pAppData->selectedPartition < 0 || pAppData->selectedPartition >= pAppData->partitionCount)
        return FALSE;

    //"открытие" диска
    TCHAR diskPath[MAX_PATH];
    HANDLE hDisk = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    DRIVE_LAYOUT_INFORMATION_EX layout = { 0 };

    StringCchPrintf(diskPath, MAX_PATH, TEXT("\\\\.\\PhysicalDrive%d"), pAppData->selectedDisk);

    hDisk = CreateFile(diskPath, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // захват определенной партиции
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, &layout, sizeof(layout), &bytesReturned, NULL))
    {
        CloseHandle(hDisk);
        return FALSE;
    }

    // удаление
    for (DWORD i = pAppData->selectedPartition; i < layout.PartitionCount - 1; i++)
    {
        layout.PartitionEntry[i] = layout.PartitionEntry[i + 1];
    }
    layout.PartitionCount--;

    // обновление
    if (!DeviceIoControl(hDisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
        &layout, sizeof(layout), NULL, 0, &bytesReturned, NULL))
    {
        CloseHandle(hDisk);
        return FALSE;
    }

    CloseHandle(hDisk);
    return TRUE;
}

// форматирование партиции
BOOL FormatPartition(TCHAR driveLetter, LPCTSTR fileSystem, LPCTSTR volumeLabel)
{
    int driveIndex = driveLetter - 'A';
    TCHAR volumePath[] = TEXT("\\\\.\\X:");  // Путь
    volumePath[4] = driveLetter;  // Буква

    HANDLE hVolume = CreateFile(volumePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    );

    if (hVolume == INVALID_HANDLE_VALUE) {
        return FALSE;
    }


    DWORD clusterSize = 4096; // размер кластера

    if (lstrcmpi(fileSystem, TEXT("NTFS")) == 0) // написано именно так, потому что в 
        //файовых системах часто нужно сделать выбор не чувствительным к регистру
        //также, это гибко
        //иначе - можно использовать _tcscmp
    {
        // настройки для NTFS
        clusterSize = 4096;  // обычно у ntfs он такой
    }
    else if (lstrcmpi(fileSystem, TEXT("FAT32")) == 0)
    {
        // настройки для FAT32
        clusterSize = 2048;
    }
    else if (lstrcmpi(fileSystem, TEXT("exFAT")) == 0)
    {
        // настройки для exFAT
        clusterSize = 4096;
    }


    int result = SHFormatDrive(NULL, driveIndex, 0xFFFF, 0);

    if (result == SHFMT_ERROR) {
        DWORD err = GetLastError();
        ShowErrorMessage(TEXT("Failed to format"));
        return false;
    }

    return (result > 0);
}

// Правильный диск?
BOOL IsValidDriveLetter(TCHAR letter)
{
    return (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z');
}

// Досупно ли?
BOOL IsDriveLetterAvailable(TCHAR letter)
{
    TCHAR drivePath[] = TEXT("A:\\");
    drivePath[0] = toupper(letter);

    DWORD drives = GetLogicalDrives();
    return !(drives & (1 << (toupper(letter) - 'A')));
}

// Читаемое описание
void BytesToHumanReadable(ULONGLONG bytes, LPTSTR output, size_t outputSize) {
    const TCHAR* units[] = { TEXT("B"), TEXT("KB"), TEXT("MB"), TEXT("GB"), TEXT("TB") };
    int unitIndex = 0;
    double size = (double)bytes;

    while (size >= 1024 && unitIndex < 4) {
        size /= 1024;
        unitIndex++;
    }

    StringCchPrintf(output, outputSize, TEXT("%.2f %s"), size, units[unitIndex]);
}

// Обновление статуса
void UpdateStatusBar(APP_DATA* pAppData, LPCTSTR szText)
{
    SendMessage(pAppData->hStatusBar, SB_SETTEXT, 0, (LPARAM)szText);
}


void ShowErrorMessage(LPCTSTR szMessage)
{
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    TCHAR szError[512];
    StringCchPrintf(szError, 512, TEXT("%s\nError %d: %s"), szMessage, dw, (LPTSTR)lpMsgBuf);

    MessageBox(NULL, szError, TEXT("Error"), MB_ICONERROR);
    LocalFree(lpMsgBuf);
}



// Окно
INT_PTR CALLBACK DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static APP_DATA appData = { 0 };

    

    switch (message)
    {
    case WM_INITDIALOG: 
        
            InitializeApp(&appData, hDlg);

            return TRUE;
    

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_DISK_LIST:
            if (HIWORD(wParam) == LBN_SELCHANGE)
            {
                appData.selectedDisk = SendMessage(appData.hDiskList, LB_GETCURSEL, 0, 0);
                RefreshPartitionList(&appData);
            }
            break;

        case IDC_PARTITION_LIST:
            if (HIWORD(wParam) == LBN_SELCHANGE)
            {
                appData.selectedPartition = SendMessage(appData.hPartitionList, LB_GETCURSEL, 0, 0);
            }
            break;

        case IDC_CREATE_PARTITION:
        {
            TCHAR szSize[32], szLetter[32], szType[32];
            GetWindowText(appData.hPartitionSize, szSize, 32);
            GetWindowText(appData.hPartitionLetter, szLetter, 32);
            GetWindowText(appData.hPartitionType, szType, 32);

            if (szSize[0] == '\0' || szLetter[0] == '\0' || szType[0] == '\0')
            {
                MessageBox(hDlg, TEXT("Please fill all partition fields"), TEXT("Error"), MB_ICONERROR);
                break;
            }

            DWORD sizeMB = _wtoi(szSize);
            TCHAR driveLetter = szLetter[0];

            if (!IsValidDriveLetter(driveLetter))
            {
                MessageBox(hDlg, TEXT("Invalid drive letter. Please use A-Z."), TEXT("Error"), MB_ICONERROR);
                break;
            }

            if (!IsDriveLetterAvailable(driveLetter))
            {
                MessageBox(hDlg, TEXT("Drive letter is already in use. Please choose another."), TEXT("Error"), MB_ICONERROR);
                break;
            }

            if (CreatePartition(&appData, sizeMB, driveLetter, szType))
            {
                MessageBox(hDlg, TEXT("Partition created successfully!"), TEXT("Success"), MB_ICONINFORMATION);
                RefreshDiskList(&appData);
                UpdateStatusBar(&appData, TEXT("Partition created successfully"));
            }
            else
            {
                ShowErrorMessage(TEXT("Failed to create partition"));
            }
        }
        break;

        case IDC_DELETE_PARTITION:
            if (appData.selectedPartition >= 0 && appData.selectedPartition < appData.partitionCount)
            {
                TCHAR szMessage[256];
                StringCchPrintf(szMessage, 256,
                    TEXT("Are you sure you want to delete partition %s?"),
                    appData.partitions[appData.selectedPartition].partitionName);

                if (MessageBox(hDlg, szMessage, TEXT("Confirm"), MB_YESNO | MB_ICONQUESTION) == IDYES)
                {
                    if (DeletePartition(&appData))
                    {
                        MessageBox(hDlg, TEXT("Partition deleted successfully!"), TEXT("Success"), MB_ICONINFORMATION);
                        RefreshDiskList(&appData);
                        UpdateStatusBar(&appData, TEXT("Partition deleted successfully"));
                    }
                    else
                    {
                        ShowErrorMessage(TEXT("Failed to delete partition"));
                    }
                }
            }
            else
            {
                MessageBox(hDlg, TEXT("Please select a partition to delete"), TEXT("Error"), MB_ICONERROR);
            }
            break;

        case IDC_REFRESH:
            RefreshDiskList(&appData);
            break;

        case ID_FILE_EXIT:
            EndDialog(hDlg, 0);
            break;

        case ID_HELP_ABOUT:
            MessageBox(hDlg,
                TEXT("Disk Partition Manager\nVersion 1.0\n\nA tool for managing disk partitions\n\nin Beta version"),
                TEXT("About"), MB_ICONINFORMATION);
            break;
        }
        return TRUE;

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return (INT_PTR)FALSE;
}


// Main
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Контроль прав доступа
    if (!IsUserAnAdmin()) {
        MessageBox(NULL, L"Please run as administrator", L"Error", MB_ICONERROR);
        ShellExecute(NULL, L"runas", L"YourApp.exe", NULL, NULL, SW_SHOW);
        return 0;
    }

    MessageBox(NULL, L"Program started as Admin", L"Debug", MB_OK);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    // Основное окно
    INT_PTR result = DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, DlgProc, 0);
    if (result == -1) {
        ShowErrorMessage(TEXT("Failed to create dialog"));
        return 1;
    }

    return static_cast<int>(result);
}