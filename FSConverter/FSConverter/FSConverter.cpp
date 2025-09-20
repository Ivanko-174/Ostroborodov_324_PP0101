#include <windows.h>
#include <winioctl.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <inttypes.h>
#include <ntddstor.h>
#include <tlhelp32.h>
#include "FSConverter.h"

#pragma comment(lib, "comctl32.lib")

// Структуры FAT32
#pragma pack(push, 1)
typedef struct tagFAT_BOOTSECTOR32 {
    BYTE sJmpBoot[3];
    BYTE sOEMName[8];
    WORD wBytsPerSec;
    BYTE bSecPerClus;
    WORD wRsvdSecCnt;
    BYTE bNumFATs;
    WORD wRootEntCnt;
    WORD wTotSec16;
    BYTE bMedia;
    WORD wFATSz16;
    WORD wSecPerTrk;
    WORD wNumHeads;
    DWORD dHiddSec;
    DWORD dTotSec32;
    DWORD dFATSz32;
    WORD wExtFlags;
    WORD wFSVer;
    DWORD dRootClus;
    WORD wFSInfo;
    WORD wBkBootSec;
    BYTE Reserved[12];
    BYTE bDrvNum;
    BYTE Reserved1;
    BYTE bBootSig;
    DWORD dBS_VolID;
    BYTE sVolLab[11];
    BYTE sBS_FilSysType[8];
} FAT_BOOTSECTOR32;

typedef struct {
    DWORD dLeadSig;
    BYTE sReserved1[480];
    DWORD dStrucSig;
    DWORD dFree_Count;
    DWORD dNxt_Free;
    BYTE sReserved2[12];
    DWORD dTrailSig;
} FAT_FSINFO;

// exFAT
typedef struct {
    BYTE jumpBoot[3];
    BYTE fileSystemName[8];
    BYTE mustBeZero[53];
    u64 partitionOffset;
    u64 volumeLength;
    DWORD fatOffset;
    DWORD fatLength;
    DWORD clusterHeapOffset;
    DWORD clusterCount;
    DWORD firstClusterOfRootDirectory;
    DWORD volumeSerialNumber;
    WORD fileSystemRevision;
    WORD volumeFlags;
    BYTE bytesPerSectorShift;
    BYTE sectorsPerClusterShift;
    BYTE numberOfFats;
    BYTE driveSelect;
    BYTE percentInUse;
    BYTE reserved[7];
    BYTE bootCode[390];
    WORD bootSignature;
} ExfatBootSec;

typedef struct {
    BYTE entryType;
    BYTE characterCount;
    WCHAR volumeLabel[11];
    BYTE reserved[8];
} ExfatVolLabelEntry;

typedef struct {
    BYTE entryType;
    BYTE flags;
    BYTE reserved[18];
    DWORD firstCluster;
    u64 dataLength;
} ExfatBitmapEntry;

typedef struct {
    BYTE entryType;
    BYTE reserved1[3];
    DWORD tableChecksum;
    BYTE reserved2[12];
    DWORD firstCluster;
    u64 dataLength;
} ExfatUpCaseEntry;

// NTFS
typedef struct {
    BYTE jumpBoot[3];
    BYTE oemID[8];
    WORD bytesPerSector;
    BYTE sectorsPerCluster;
    WORD reservedSectors;
    BYTE alwaysZero[3];
    WORD notUsed;
    BYTE mediaDescriptor;
    WORD alwaysZero2;
    WORD sectorsPerTrack;
    WORD numberOfHeads;
    DWORD hiddenSectors;
    DWORD notUsed2;
    DWORD notUsed3;
    ULONGLONG totalSectors;
    ULONGLONG mftStartCluster;
    ULONGLONG mftMirrorStartCluster;
    BYTE clustersPerFileRecord;
    BYTE notUsed4[3];
    BYTE clustersPerIndexBlock;
    BYTE notUsed5[3];
    ULONGLONG volumeSerialNumber;
    DWORD checksum;
} NTFS_BOOTSECTOR;

typedef struct {
    BYTE signature[4]; // "FILE"
    WORD updateSeqOffset;
    WORD updateSeqSize;
    ULONGLONG logFileSeqNumber;
    WORD sequenceNumber;
    WORD hardLinkCount;
    WORD firstAttributeOffset;
    WORD flags;
    DWORD usedSize;
    DWORD allocatedSize;
    ULONGLONG fileRefToBase;
    WORD nextAttributeId;
    BYTE reserved[2];
    DWORD mftRecordNumber;
} MFT_RECORD;

typedef struct {
    DWORD type;
    DWORD length;
    BYTE nonResidentFlag;
    BYTE nameLength;
    WORD nameOffset;
    WORD flags;
    WORD attributeId;
} MFT_ATTRIBUTE;

typedef struct {
    MFT_ATTRIBUTE attribute;
    DWORD streamNameLength;
    WORD streamNameOffset;
    ULONGLONG startingVCN;
    ULONGLONG lastVCN;
    WORD dataRunOffset;
    WORD compressionUnitSize;
    DWORD padding;
    ULONGLONG allocatedSize;
    ULONGLONG dataSize;
    ULONGLONG validDataSize;
} MFT_DATA_ATTRIBUTE;
#pragma pack(pop)

// exFAT дефайны
#define EXFAT_FIRST_ENT 2
#define EXFAT_EOF 0xFFFFFFFF
#define EXFAT_RESERVED 0xFFFFFFF8
#define BS_JUMP_BOOT "\xEB\x76\x90"
#define BS_FILE_SYS_NAME "EXFAT   "
#define BS_FILE_SYS_REV_1_00 0x0100
#define BS_DRIVE_SELECT 0x80
#define BS_BOOT_SIG 0xAA55
#define TYPE_VOL_LABEL 0x83
#define TYPE_BITMAP 0x81
#define TYPE_UP_CASE 0x82

static const BYTE g_upCaseTable[512] = { 0 };
static const DWORD UP_CASE_TABLE_CHECKSUM = 0x12345678;


void show_error(HWND hwnd, const wchar_t* error) {
    DWORD dw = GetLastError();
    std::wstring msg;
    if (dw) {
        LPVOID lpMsgBuf;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&lpMsgBuf, 0, NULL);
        msg = L"Error: " + std::wstring(error) + L"\nGetLastError()=" + std::to_wstring(dw) + L": " + (LPWSTR)lpMsgBuf;
        LocalFree(lpMsgBuf);
    }
    else {
        msg = std::wstring(error);
    }
    MessageBoxW(hwnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
}

bool terminate_processes_using_drive(const std::wstring& drive_letter, HWND hwnd) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        show_error(hwnd, L"Failed to create process snapshot");
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    std::vector<DWORD> pids_to_terminate;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HANDLE hFile;
                WCHAR filePath[MAX_PATH];
                DWORD size = MAX_PATH;

                hFile = CreateFileW((drive_letter + L"\\").c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hFile);
                    if (QueryDosDeviceW(drive_letter.substr(0, 2).c_str(), filePath, size)) {
                        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                        if (hModuleSnap != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };
                            if (Module32FirstW(hModuleSnap, &me32)) {
                                do {
                                    if (_wcsicmp(me32.szExePath, filePath) == 0) {
                                        pids_to_terminate.push_back(pe32.th32ProcessID);
                                        break;
                                    }
                                } while (Module32NextW(hModuleSnap, &me32));
                            }
                            CloseHandle(hModuleSnap);
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    for (DWORD pid : pids_to_terminate) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            if (!TerminateProcess(hProcess, 0)) {
                show_error(hwnd, L"Failed to terminate process");
            }
            CloseHandle(hProcess);
        }
    }
    return true;
}

DWORD get_volume_id() {
    SYSTEMTIME s;
    GetLocalTime(&s);
    WORD lo = s.wDay + (s.wMonth << 8) + (s.wMilliseconds / 10) + (s.wSecond << 8);
    WORD hi = s.wMinute + (s.wHour << 8) + s.wYear;
    return (DWORD)lo + ((DWORD)hi << 16);
}

DWORD get_fat_size_sectors(DWORD DskSize, DWORD ReservedSecCnt, DWORD SecPerClus, DWORD NumFATs, DWORD BytesPerSect) {
    ULONGLONG Numerator = 4ULL * (DskSize - ReservedSecCnt);
    ULONGLONG Denominator = (SecPerClus * BytesPerSect) + (4ULL * NumFATs);
    ULONGLONG FatSz = Numerator / Denominator + 1;
    return (DWORD)FatSz;
}

void seek_to_sect(HANDLE hDevice, DWORD Sector, DWORD BytesPerSect) {
    LONGLONG Offset = (LONGLONG)Sector * BytesPerSect;
    LONG HiOffset = (LONG)(Offset >> 32);
    SetFilePointer(hDevice, (LONG)Offset, &HiOffset, FILE_BEGIN);
}

bool write_sect(HANDLE hDevice, DWORD Sector, DWORD BytesPerSector, void* Data, DWORD NumSects, HWND hwnd) {
    DWORD dwWritten;
    seek_to_sect(hDevice, Sector, BytesPerSector);
    if (!WriteFile(hDevice, Data, NumSects * BytesPerSector, &dwWritten, NULL)) {
        show_error(hwnd, L"Failed to write to disk");
        return false;
    }
    if (dwWritten != NumSects * BytesPerSector) {
        show_error(hwnd, L"Incomplete write to disk");
        return false;
    }
    return true;
}

bool zero_sectors(HANDLE hDevice, DWORD Sector, DWORD BytesPerSect, DWORD NumSects, DISK_GEOMETRY* pdgDrive, HWND hwnd, HANDLE cancelEvent) {
    BYTE* pZeroSect = (BYTE*)VirtualAlloc(NULL, BytesPerSect * 128, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pZeroSect) {
        show_error(hwnd, L"Failed to allocate memory for zeroing sectors");
        return false;
    }
    DWORD dwWritten;
    seek_to_sect(hDevice, Sector, BytesPerSect);
    DWORD totalSects = NumSects;
    while (NumSects > 0) {
        if (WaitForSingleObject(cancelEvent, 0) == WAIT_OBJECT_0) {
            VirtualFree(pZeroSect, 0, MEM_RELEASE);
            return false;
        }
        DWORD WriteSize = (NumSects > 128) ? 128 : NumSects;
        if (!WriteFile(hDevice, pZeroSect, WriteSize * BytesPerSect, &dwWritten, NULL)) {
            VirtualFree(pZeroSect, 0, MEM_RELEASE);
            show_error(hwnd, L"Failed to write");
            return false;
        }
        NumSects -= WriteSize;
        double progress = (totalSects - NumSects) * 100.0 / totalSects;
        SendMessage(hwnd, WM_UPDATE_PROGRESS, (WPARAM)(int)progress, 0);
    }
    VirtualFree(pZeroSect, 0, MEM_RELEASE);
    return true;
}

BYTE get_sectors_per_cluster(LONGLONG DiskSizeBytes, DWORD BytesPerSect) {
    BYTE ret = 1;
    LONGLONG DiskSizeMB = DiskSizeBytes / (1024 * 1024);
    if (DiskSizeMB > 512) ret = (BYTE)((4 * 1024) / BytesPerSect);
    if (DiskSizeMB > 8192) ret = (BYTE)((8 * 1024) / BytesPerSect);
    if (DiskSizeMB > 16384) ret = (BYTE)((16 * 1024) / BytesPerSect);
    if (DiskSizeMB > 32768) ret = (BYTE)((32 * 1024) / BytesPerSect);
    return ret;
}

static u32 calcExFatBootChecksum(const BYTE* data, WORD bytesPerSector) {
    u32 checksum = 0;
    for (unsigned i = 0; i < (bytesPerSector * 11); i++) {
        if (i == 106 || i == 107 || i == 112) continue;
        checksum = (checksum & 1u ? 0x80000000u : 0u) + (checksum >> 1) + data[i];
    }
    return checksum;
}

static u32 countTrailingZeros(u32 value) {
    u32 count = 0;
    while (value && !(value & 1)) {
        count++;
        value >>= 1;
    }
    return count;
}

static u32 udivCeil(u32 num, u32 denom) {
    return (num + denom - 1) / denom;
}

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
                                show_error(NULL, L"Failed to allocate memory for device descriptor");
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

// Конвертация
bool format_fat32(format_thread_data* data) {
    format_params* params = data->params;
    HANDLE hDevice = data->hDevice;
    DISK_GEOMETRY dgDrive = data->dgDrive;
    PARTITION_INFORMATION_EX xpiDrive = data->xpiDrive;
    HWND hwnd = params->hwnd;
    char vol = params->drive_letter;

    std::wstring driveLetter(1, vol);
    driveLetter += L":";
    DWORD VolumeId = get_volume_id();
    const DWORD NumFATs = 2;
    const DWORD BackupBootSect = 6;
    DWORD BytesPerSect = 0, SectorsPerCluster = 0, TotalSectors = 0, FatSize = 0, ReservedSectCount = 0;
    u64 qTotalSectors = 0;
    DWORD SystemAreaSize = 0, UserAreaSize = 0;
    u64 ClusterCount = 0;

    if (!terminate_processes_using_drive(driveLetter, hwnd)) {
        return false;
    }

    DWORD cbRet;
    if (!DeviceIoControl(hDevice, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &cbRet, NULL)) {
        MessageBoxW(hwnd, L"FSCTL_ALLOW_EXTENDED_DASD_IO failed, continuing anyway.", L"Warning", MB_OK | MB_ICONWARNING);
    }
    if (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
        show_error(hwnd, L"Failed to lock device");
        CloseHandle(hDevice);
        return false;
    }

    BytesPerSect = dgDrive.BytesPerSector;
    qTotalSectors = xpiDrive.PartitionLength.QuadPart / dgDrive.BytesPerSector;
    if (qTotalSectors < 65536) {
        show_error(hwnd, L"This drive is too small for FAT32 - must have at least 64K clusters");
        CloseHandle(hDevice);
        return false;
    }
    if (qTotalSectors > 0xFFFFFFFFULL) {
        show_error(hwnd, L"This drive is too big for FAT32 - max 2TB supported");
        CloseHandle(hDevice);
        return false;
    }
    TotalSectors = static_cast<DWORD>(qTotalSectors);

    FAT_BOOTSECTOR32* pFAT32BootSect = (FAT_BOOTSECTOR32*)VirtualAlloc(NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    FAT_FSINFO* pFAT32FsInfo = (FAT_FSINFO*)VirtualAlloc(NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD* pFirstSectOfFat = (DWORD*)VirtualAlloc(NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pFAT32BootSect || !pFAT32FsInfo || !pFirstSectOfFat) {
        show_error(hwnd, L"Failed to allocate memory");
        if (pFAT32BootSect) VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        if (pFAT32FsInfo) VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        if (pFirstSectOfFat) VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    pFAT32BootSect->sJmpBoot[0] = 0xEB;
    pFAT32BootSect->sJmpBoot[1] = 0x58;
    pFAT32BootSect->sJmpBoot[2] = 0x90;
    std::copy_n("MSWIN4.1", 8, pFAT32BootSect->sOEMName);
    pFAT32BootSect->wBytsPerSec = static_cast<WORD>(BytesPerSect);
    SectorsPerCluster = params->sectors_per_cluster ? params->sectors_per_cluster : get_sectors_per_cluster(xpiDrive.PartitionLength.QuadPart, BytesPerSect);
    if (SectorsPerCluster > 255) {
        show_error(hwnd, L"Sectors per cluster exceeds BYTE limit");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }
    pFAT32BootSect->bSecPerClus = static_cast<BYTE>(SectorsPerCluster);
    pFAT32BootSect->bNumFATs = static_cast<BYTE>(NumFATs);
    pFAT32BootSect->wRootEntCnt = 0;
    pFAT32BootSect->wTotSec16 = 0;
    pFAT32BootSect->bMedia = 0xF8;
    pFAT32BootSect->wFATSz16 = 0;
    pFAT32BootSect->wSecPerTrk = static_cast<WORD>(dgDrive.SectorsPerTrack);
    pFAT32BootSect->wNumHeads = static_cast<WORD>(dgDrive.TracksPerCylinder);
    pFAT32BootSect->dHiddSec = xpiDrive.Mbr.HiddenSectors;
    pFAT32BootSect->dTotSec32 = TotalSectors;

    if (params->ReservedSectCount == (DWORD)-1) {
        DWORD align = 32;
        FatSize = get_fat_size_sectors(TotalSectors, 2 * align, SectorsPerCluster, NumFATs, BytesPerSect);
        ReservedSectCount = align + align - (align + NumFATs * FatSize) % align;
    }
    else {
        ReservedSectCount = params->ReservedSectCount;
        FatSize = get_fat_size_sectors(TotalSectors, ReservedSectCount, SectorsPerCluster, NumFATs, BytesPerSect);
    }
    pFAT32BootSect->wRsvdSecCnt = static_cast<WORD>(ReservedSectCount);
    pFAT32BootSect->dFATSz32 = FatSize;
    pFAT32BootSect->wExtFlags = 0;
    pFAT32BootSect->wFSVer = 0;
    pFAT32BootSect->dRootClus = 2;
    pFAT32BootSect->wFSInfo = 1;
    pFAT32BootSect->wBkBootSec = static_cast<WORD>(BackupBootSect);
    pFAT32BootSect->bDrvNum = 0x80;
    pFAT32BootSect->Reserved1 = 0;
    pFAT32BootSect->bBootSig = 0x29;
    pFAT32BootSect->dBS_VolID = VolumeId;
    std::copy_n("NO NAME    ", 11, pFAT32BootSect->sVolLab);
    std::copy_n("FAT32   ", 8, pFAT32BootSect->sBS_FilSysType);
    ((BYTE*)pFAT32BootSect)[510] = 0x55;
    ((BYTE*)pFAT32BootSect)[511] = 0xAA;
    if (BytesPerSect != 512) {
        ((BYTE*)pFAT32BootSect)[BytesPerSect - 2] = 0x55;
        ((BYTE*)pFAT32BootSect)[BytesPerSect - 1] = 0xAA;
    }

    pFAT32FsInfo->dLeadSig = 0x41615252;
    pFAT32FsInfo->dStrucSig = 0x61417272;
    pFAT32FsInfo->dFree_Count = static_cast<DWORD>(-1);
    pFAT32FsInfo->dNxt_Free = static_cast<DWORD>(-1);
    pFAT32FsInfo->dTrailSig = 0xAA550000;

    pFirstSectOfFat[0] = 0x0FFFFFF8;
    pFirstSectOfFat[1] = 0x0FFFFFFF;
    pFirstSectOfFat[2] = 0x0FFFFFFF;

    UserAreaSize = TotalSectors - ReservedSectCount - (NumFATs * FatSize);
    ClusterCount = UserAreaSize / SectorsPerCluster;

    if (ClusterCount > 0x0FFFFFFF) {
        show_error(hwnd, L"Too many clusters (>2^28). Try a larger cluster size.");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }
    if (ClusterCount < 65536) {
        show_error(hwnd, L"FAT32 requires at least 65536 clusters. Try a smaller cluster size.");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    u64 FatNeeded = ClusterCount * 4;
    FatNeeded += (BytesPerSect - 1);
    FatNeeded /= BytesPerSect;
    if (FatNeeded > FatSize) {
        show_error(hwnd, L"FAT size too small for this drive.");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    std::wstringstream info;
    info << std::fixed << std::setprecision(2)
        << L"Size: " << (xpiDrive.PartitionLength.QuadPart / (1000.0 * 1000 * 1000)) << L" GB, " << TotalSectors << L" sectors\n"
        << L"Bytes per sector: " << BytesPerSect << L", Cluster size: " << (SectorsPerCluster * BytesPerSect) << L" bytes\n"
        << L"Volume ID: " << std::hex << (VolumeId >> 16) << L":" << (VolumeId & 0xFFFF) << std::dec << L"\n"
        << L"Reserved Sectors: " << ReservedSectCount << L", Sectors per FAT: " << FatSize << L", FATs: " << NumFATs << L"\n"
        << L"Total clusters: " << ClusterCount << L"\n"
        << L"Free clusters: " << (UserAreaSize / SectorsPerCluster - 1);
    MessageBoxW(hwnd, info.str().c_str(), L"Format Information", MB_OK | MB_ICONINFORMATION);

    SystemAreaSize = ReservedSectCount + (NumFATs * FatSize) + SectorsPerCluster;
    if (!zero_sectors(hDevice, 0, BytesPerSect, SystemAreaSize, &dgDrive, hwnd, data->cancelEvent)) {
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    for (DWORD i = 0; i < 2; i++) {
        if (WaitForSingleObject(data->cancelEvent, 0) == WAIT_OBJECT_0) {
            VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
            VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
            VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
        DWORD SectorStart = (i == 0) ? 0 : BackupBootSect;
        if (!write_sect(hDevice, SectorStart, BytesPerSect, pFAT32BootSect, 1, hwnd) ||
            !write_sect(hDevice, SectorStart + 1, BytesPerSect, pFAT32FsInfo, 1, hwnd)) {
            VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
            VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
            VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    for (DWORD i = 0; i < NumFATs; i++) {
        if (WaitForSingleObject(data->cancelEvent, 0) == WAIT_OBJECT_0) {
            VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
            VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
            VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
        DWORD SectorStart = ReservedSectCount + (i * FatSize);
        if (!write_sect(hDevice, SectorStart, BytesPerSect, pFirstSectOfFat, 1, hwnd)) {
            VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
            VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
            VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    if (xpiDrive.PartitionStyle != PARTITION_STYLE_MBR) {
        SET_PARTITION_INFORMATION spiDrive;
        spiDrive.PartitionType = 0x0C;
        if (!DeviceIoControl(hDevice, IOCTL_DISK_SET_PARTITION_INFO, &spiDrive, sizeof(spiDrive), NULL, 0, &cbRet, NULL)) {
            if (xpiDrive.Mbr.HiddenSectors) {
                show_error(hwnd, L"Failed to set partition info");
                VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
                VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
                VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
                CloseHandle(hDevice);
                return false;
            }
        }
    }

    if (!DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
        show_error(hwnd, L"Failed to dismount device");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }
    if (!DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
        show_error(hwnd, L"Failed to unlock device");
        VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
        VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
        VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    VirtualFree(pFAT32BootSect, 0, MEM_RELEASE);
    VirtualFree(pFAT32FsInfo, 0, MEM_RELEASE);
    VirtualFree(pFirstSectOfFat, 0, MEM_RELEASE);
    CloseHandle(hDevice);
    return WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0;
}

bool format_exfat(format_thread_data* data) {
    format_params* params = data->params;
    HANDLE hDevice = data->hDevice;
    DISK_GEOMETRY dgDrive = data->dgDrive;
    PARTITION_INFORMATION_EX xpiDrive = data->xpiDrive;
    HWND hwnd = params->hwnd;
    char vol = params->drive_letter;

    std::wstring driveLetter(1, vol);
    driveLetter += L":";
    DWORD VolumeId = get_volume_id();

    if (!terminate_processes_using_drive(driveLetter, hwnd)) {
        return false;
    }

    DWORD cbRet;
    if (!DeviceIoControl(hDevice, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &cbRet, NULL)) {
        MessageBoxW(hwnd, L"FSCTL_ALLOW_EXTENDED_DASD_IO failed, continuing anyway.", L"Warning", MB_OK | MB_ICONWARNING);
    }
    if (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
        show_error(hwnd, L"Failed to lock device");
        CloseHandle(hDevice);
        return false;
    }

    DWORD bytesPerSec = dgDrive.BytesPerSector;
    u64 totSec = xpiDrive.PartitionLength.QuadPart / bytesPerSec;
    DWORD secPerClus = params->sectors_per_cluster ? params->sectors_per_cluster : get_sectors_per_cluster(xpiDrive.PartitionLength.QuadPart, bytesPerSec);
    DWORD bytesPerClus = secPerClus * bytesPerSec;

    const DWORD bootRegionSectors = 12;
    const DWORD backupBootOffset = 12;
    const DWORD fatOffset = 24;
    u32 clusterCount = static_cast<u32>((totSec - fatOffset) / (secPerClus + (4.0 / bytesPerSec)));
    DWORD fatLength = ((clusterCount + 2) * 4 + bytesPerSec - 1) / bytesPerSec;
    DWORD clusterHeapOffset = fatOffset + fatLength;
    clusterCount = static_cast<u32>((totSec - clusterHeapOffset) / secPerClus);
    fatLength = ((clusterCount + 2) * 4 + bytesPerSec - 1) / bytesPerSec;
    clusterHeapOffset = fatOffset + fatLength;

    u32 bitmapClus = udivCeil(clusterCount, bytesPerClus * 8);
    u32 upCaseClus = udivCeil(sizeof(g_upCaseTable), bytesPerClus);
    u32 rootDirCluster = EXFAT_FIRST_ENT + bitmapClus + upCaseClus;

    BYTE* bootRegion = (BYTE*)VirtualAlloc(NULL, bytesPerSec * 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD* fatEntries = (DWORD*)VirtualAlloc(NULL, fatLength * bytesPerSec, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE* bitmapData = (BYTE*)VirtualAlloc(NULL, bitmapClus * bytesPerSec * secPerClus, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE* upCaseData = (BYTE*)VirtualAlloc(NULL, upCaseClus * bytesPerSec * secPerClus, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE* rootDirData = (BYTE*)VirtualAlloc(NULL, secPerClus * bytesPerSec, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!bootRegion || !fatEntries || !bitmapData || !upCaseData || !rootDirData) {
        show_error(hwnd, L"Failed to allocate memory");
        if (bootRegion) VirtualFree(bootRegion, 0, MEM_RELEASE);
        if (fatEntries) VirtualFree(fatEntries, 0, MEM_RELEASE);
        if (bitmapData) VirtualFree(bitmapData, 0, MEM_RELEASE);
        if (upCaseData) VirtualFree(upCaseData, 0, MEM_RELEASE);
        if (rootDirData) VirtualFree(rootDirData, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    ExfatBootSec* bs = (ExfatBootSec*)bootRegion;
    memcpy(bs->jumpBoot, BS_JUMP_BOOT, 3);
    memcpy(bs->fileSystemName, BS_FILE_SYS_NAME, 8);
    memset(bs->mustBeZero, 0, 53);
    bs->partitionOffset = 0;
    bs->volumeLength = totSec;
    bs->fatOffset = fatOffset;
    bs->fatLength = fatLength;
    bs->clusterHeapOffset = clusterHeapOffset;
    bs->clusterCount = clusterCount;
    bs->firstClusterOfRootDirectory = rootDirCluster;
    bs->volumeSerialNumber = VolumeId;
    bs->fileSystemRevision = BS_FILE_SYS_REV_1_00;
    bs->volumeFlags = 0;
    bs->bytesPerSectorShift = static_cast<BYTE>(countTrailingZeros(bytesPerSec));
    bs->sectorsPerClusterShift = static_cast<BYTE>(countTrailingZeros(secPerClus));
    bs->numberOfFats = 1;
    bs->driveSelect = BS_DRIVE_SELECT;
    bs->percentInUse = 0;
    memset(bs->bootCode, 0xF4, sizeof(bs->bootCode));
    bs->bootSignature = BS_BOOT_SIG;

    for (unsigned i = 1; i < 9; i++) {
        *(DWORD*)(bootRegion + bytesPerSec * i + bytesPerSec - 4) = 0xAA550000;
    }

    memset(bootRegion + bytesPerSec * 9, 0, bytesPerSec);

    u32 checksum = calcExFatBootChecksum(bootRegion, static_cast<WORD>(bytesPerSec));
    for (unsigned i = 0; i < bytesPerSec / 4; i++) {
        *(u32*)(bootRegion + bytesPerSec * 11 + i * 4) = checksum;
    }

    memset(fatEntries, 0, fatLength * bytesPerSec);
    fatEntries[0] = EXFAT_RESERVED;
    fatEntries[1] = EXFAT_EOF;
    for (u32 i = EXFAT_FIRST_ENT; i < EXFAT_FIRST_ENT + bitmapClus - 1; i++) {
        fatEntries[i] = i + 1;
    }
    fatEntries[EXFAT_FIRST_ENT + bitmapClus - 1] = EXFAT_EOF;
    for (u32 i = EXFAT_FIRST_ENT + bitmapClus; i < EXFAT_FIRST_ENT + bitmapClus + upCaseClus - 1; i++) {
        fatEntries[i] = i + 1;
    }
    fatEntries[EXFAT_FIRST_ENT + bitmapClus + upCaseClus - 1] = EXFAT_EOF;
    fatEntries[rootDirCluster] = EXFAT_EOF;

    memset(bitmapData, 0, bitmapClus * bytesPerSec * secPerClus);
    for (u32 i = 0; i < bitmapClus + upCaseClus + 1; i++) {
        bitmapData[i / 8] |= (1 << (i % 8));
    }

    memcpy(upCaseData, g_upCaseTable, sizeof(g_upCaseTable));
    memset(upCaseData + sizeof(g_upCaseTable), 0, upCaseClus * bytesPerSec * secPerClus - sizeof(g_upCaseTable));

    ExfatVolLabelEntry* labelEntry = (ExfatVolLabelEntry*)rootDirData;
    labelEntry->entryType = TYPE_VOL_LABEL;
    labelEntry->characterCount = 7;
    memcpy(labelEntry->volumeLabel, L"NO NAME", 7 * sizeof(WCHAR));
    ExfatBitmapEntry* bitmapEntry = (ExfatBitmapEntry*)(rootDirData + sizeof(ExfatVolLabelEntry));
    bitmapEntry->entryType = TYPE_BITMAP;
    bitmapEntry->flags = 0;
    bitmapEntry->firstCluster = EXFAT_FIRST_ENT;
    bitmapEntry->dataLength = udivCeil(clusterCount, 8);
    ExfatUpCaseEntry* upCaseEntry = (ExfatUpCaseEntry*)(rootDirData + sizeof(ExfatVolLabelEntry) + sizeof(ExfatBitmapEntry));
    upCaseEntry->entryType = TYPE_UP_CASE;
    upCaseEntry->tableChecksum = UP_CASE_TABLE_CHECKSUM;
    upCaseEntry->firstCluster = EXFAT_FIRST_ENT + bitmapClus;
    upCaseEntry->dataLength = sizeof(g_upCaseTable);

    if (!zero_sectors(hDevice, 0, bytesPerSec, clusterHeapOffset + secPerClus * (bitmapClus + upCaseClus + 1), &dgDrive, hwnd, data->cancelEvent)) {
        VirtualFree(bootRegion, 0, MEM_RELEASE);
        VirtualFree(fatEntries, 0, MEM_RELEASE);
        VirtualFree(bitmapData, 0, MEM_RELEASE);
        VirtualFree(upCaseData, 0, MEM_RELEASE);
        VirtualFree(rootDirData, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    if (WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0) {
        if (!write_sect(hDevice, 0, bytesPerSec, bootRegion, bootRegionSectors, hwnd) ||
            !write_sect(hDevice, backupBootOffset, bytesPerSec, bootRegion, bootRegionSectors, hwnd) ||
            !write_sect(hDevice, fatOffset, bytesPerSec, fatEntries, fatLength, hwnd) ||
            !write_sect(hDevice, clusterHeapOffset, bytesPerSec, bitmapData, bitmapClus * secPerClus, hwnd) ||
            !write_sect(hDevice, clusterHeapOffset + bitmapClus * secPerClus, bytesPerSec, upCaseData, upCaseClus * secPerClus, hwnd) ||
            !write_sect(hDevice, clusterHeapOffset + (bitmapClus + upCaseClus) * secPerClus, bytesPerSec, rootDirData, secPerClus, hwnd)) {
            VirtualFree(bootRegion, 0, MEM_RELEASE);
            VirtualFree(fatEntries, 0, MEM_RELEASE);
            VirtualFree(bitmapData, 0, MEM_RELEASE);
            VirtualFree(upCaseData, 0, MEM_RELEASE);
            VirtualFree(rootDirData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    if (WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0) {
        if (!DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
            show_error(hwnd, L"Failed to dismount device");
            VirtualFree(bootRegion, 0, MEM_RELEASE);
            VirtualFree(fatEntries, 0, MEM_RELEASE);
            VirtualFree(bitmapData, 0, MEM_RELEASE);
            VirtualFree(upCaseData, 0, MEM_RELEASE);
            VirtualFree(rootDirData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
        if (!DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
            show_error(hwnd, L"Failed to unlock device");
            VirtualFree(bootRegion, 0, MEM_RELEASE);
            VirtualFree(fatEntries, 0, MEM_RELEASE);
            VirtualFree(bitmapData, 0, MEM_RELEASE);
            VirtualFree(upCaseData, 0, MEM_RELEASE);
            VirtualFree(rootDirData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    VirtualFree(bootRegion, 0, MEM_RELEASE);
    VirtualFree(fatEntries, 0, MEM_RELEASE);
    VirtualFree(bitmapData, 0, MEM_RELEASE);
    VirtualFree(upCaseData, 0, MEM_RELEASE);
    VirtualFree(rootDirData, 0, MEM_RELEASE);
    CloseHandle(hDevice);
    return WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0;
}

bool format_ntfs(format_thread_data* data) {
    format_params* params = data->params;
    HANDLE hDevice = data->hDevice;
    DISK_GEOMETRY dgDrive = data->dgDrive;
    PARTITION_INFORMATION_EX xpiDrive = data->xpiDrive;
    HWND hwnd = params->hwnd;
    char vol = params->drive_letter;

    std::wstring driveLetter(1, vol);
    driveLetter += L":";
    ULONGLONG VolumeId = get_volume_id();

    if (!terminate_processes_using_drive(driveLetter, hwnd)) {
        return false;
    }

    DWORD cbRet;
    if (!DeviceIoControl(hDevice, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &cbRet, NULL)) {
        MessageBoxW(hwnd, L"FSCTL_ALLOW_EXTENDED_DASD_IO failed, continuing anyway.", L"Warning", MB_OK | MB_ICONWARNING);
    }
    if (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
        show_error(hwnd, L"Failed to lock device");
        CloseHandle(hDevice);
        return false;
    }

    DWORD bytesPerSec = dgDrive.BytesPerSector;
    ULONGLONG totSec = xpiDrive.PartitionLength.QuadPart / bytesPerSec;
    BYTE secPerClus = static_cast<BYTE>(params->sectors_per_cluster ? params->sectors_per_cluster : get_sectors_per_cluster(xpiDrive.PartitionLength.QuadPart, bytesPerSec));
    if (secPerClus > 255) {
        show_error(hwnd, L"Sectors per cluster exceeds BYTE limit");
        CloseHandle(hDevice);
        return false;
    }

    if (bytesPerSec < 512) {
        show_error(hwnd, L"Bytes per sector is less than 512, cannot format NTFS");
        CloseHandle(hDevice);
        return false;
    }

    NTFS_BOOTSECTOR* pNtfsBootSect = (NTFS_BOOTSECTOR*)VirtualAlloc(NULL, bytesPerSec, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pNtfsBootSect) {
        show_error(hwnd, L"Failed to allocate memory for NTFS boot sector");
        CloseHandle(hDevice);
        return false;
    }

    memcpy(pNtfsBootSect->jumpBoot, "\xEB\x52\x90", 3);
    memcpy(pNtfsBootSect->oemID, "NTFS    ", 8);
    pNtfsBootSect->bytesPerSector = static_cast<WORD>(bytesPerSec);
    pNtfsBootSect->sectorsPerCluster = secPerClus;
    pNtfsBootSect->reservedSectors = 0;
    memset(pNtfsBootSect->alwaysZero, 0, 3);
    pNtfsBootSect->notUsed = 0;
    pNtfsBootSect->mediaDescriptor = 0xF8;
    pNtfsBootSect->alwaysZero2 = 0;
    pNtfsBootSect->sectorsPerTrack = static_cast<WORD>(dgDrive.SectorsPerTrack);
    pNtfsBootSect->numberOfHeads = static_cast<WORD>(dgDrive.TracksPerCylinder);
    pNtfsBootSect->hiddenSectors = xpiDrive.Mbr.HiddenSectors;
    pNtfsBootSect->notUsed2 = 0;
    pNtfsBootSect->notUsed3 = 0;
    pNtfsBootSect->totalSectors = totSec;
    ULONGLONG mftStartCluster = 786432 / (secPerClus * bytesPerSec);
    pNtfsBootSect->mftStartCluster = mftStartCluster;
    pNtfsBootSect->mftMirrorStartCluster = mftStartCluster + 1;
    pNtfsBootSect->clustersPerFileRecord = -10; 
    pNtfsBootSect->clustersPerIndexBlock = 1;
    pNtfsBootSect->volumeSerialNumber = VolumeId;
    pNtfsBootSect->checksum = 0;

    ((BYTE*)pNtfsBootSect)[510] = 0x55;
    ((BYTE*)pNtfsBootSect)[511] = 0xAA;

    BYTE* mftData = (BYTE*)VirtualAlloc(NULL, bytesPerSec * secPerClus * 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mftData) {
        show_error(hwnd, L"Failed to allocate memory for MFT");
        VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }
    memset(mftData, 0, bytesPerSec * secPerClus * 16);

    MFT_RECORD* mftRecord = (MFT_RECORD*)mftData;
    memcpy(mftRecord->signature, "FILE", 4);
    mftRecord->updateSeqOffset = 0x30;
    mftRecord->updateSeqSize = 2;
    mftRecord->logFileSeqNumber = 1;
    mftRecord->sequenceNumber = 1;
    mftRecord->hardLinkCount = 1;
    mftRecord->firstAttributeOffset = 0x38;
    mftRecord->flags = 0x0001; // Использующийся файл
    mftRecord->usedSize = 0x100;
    mftRecord->allocatedSize = 1024;
    mftRecord->fileRefToBase = 0;
    mftRecord->nextAttributeId = 2;
    mftRecord->mftRecordNumber = 0;

    MFT_DATA_ATTRIBUTE* dataAttr = (MFT_DATA_ATTRIBUTE*)(mftData + 0x38);
    dataAttr->attribute.type = 0x80; // $DATA
    dataAttr->attribute.length = sizeof(MFT_DATA_ATTRIBUTE);
    dataAttr->attribute.nonResidentFlag = 1;
    dataAttr->attribute.nameLength = 0;
    dataAttr->attribute.nameOffset = 0;
    dataAttr->attribute.flags = 0;
    dataAttr->attribute.attributeId = 1;
    dataAttr->startingVCN = 0;
    dataAttr->lastVCN = (bytesPerSec * secPerClus * 16) / bytesPerSec - 1;
    dataAttr->dataRunOffset = sizeof(MFT_DATA_ATTRIBUTE);
    dataAttr->allocatedSize = bytesPerSec * secPerClus * 16;
    dataAttr->dataSize = bytesPerSec * secPerClus * 16;
    dataAttr->validDataSize = bytesPerSec * secPerClus * 16;

    BYTE* dataRun = (BYTE*)dataAttr + sizeof(MFT_DATA_ATTRIBUTE);
    dataRun[0] = 0x21; 
    dataRun[1] = 16;   // В кластерах
    dataRun[2] = 0;
    dataRun[3] = (BYTE)mftStartCluster;

    DWORD systemAreaSectors = secPerClus * (mftStartCluster + 16);
    if (!zero_sectors(hDevice, 0, bytesPerSec, systemAreaSectors, &dgDrive, hwnd, data->cancelEvent)) {
        VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
        VirtualFree(mftData, 0, MEM_RELEASE);
        CloseHandle(hDevice);
        return false;
    }

    if (WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0) {
        if (!write_sect(hDevice, 0, bytesPerSec, pNtfsBootSect, 1, hwnd) ||
            !write_sect(hDevice, mftStartCluster * secPerClus, bytesPerSec, mftData, secPerClus * 16, hwnd)) {
            VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
            VirtualFree(mftData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    if (WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0) {
        if (!DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
            show_error(hwnd, L"Failed to dismount device");
            VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
            VirtualFree(mftData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
        if (!DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL)) {
            show_error(hwnd, L"Failed to unlock device");
            VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
            VirtualFree(mftData, 0, MEM_RELEASE);
            CloseHandle(hDevice);
            return false;
        }
    }

    VirtualFree(pNtfsBootSect, 0, MEM_RELEASE);
    VirtualFree(mftData, 0, MEM_RELEASE);
    CloseHandle(hDevice);
    return WaitForSingleObject(data->cancelEvent, 0) != WAIT_OBJECT_0;
}

DWORD WINAPI FormatThread(LPVOID lpParam) {
    format_thread_data* data = (format_thread_data*)lpParam;
    bool success = false;

    switch (data->params->fs_type) {
    case FS_FAT32: success = format_fat32(data); break;
    case FS_EXFAT: success = format_exfat(data); break;
    case FS_NTFS: success = format_ntfs(data); break;
    }

    SendMessage(data->params->hwnd, WM_FORMAT_COMPLETE, success, 0);
    CloseHandle(data->cancelEvent);
    delete data;
    return 0;
}

INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static format_params params;
    static char selectedDrive = 0;
    static HANDLE formatThread = NULL;
    static format_thread_data* threadData = NULL;

    switch (msg) {
    case WM_INITDIALOG: {
        HWND hDriveCombo = GetDlgItem(hwnd, IDC_DRIVE_COMBO);

        if (IsRunningAsAdmin()) {
            DWORD drives = GetLogicalDrives();
            for (char c = 'A'; c <= 'Z'; c++) {
                if (drives & (1 << (c - 'A'))) {
                    std::wstring drive = std::wstring(1, c) + L":";
                    SendMessageW(hDriveCombo, CB_ADDSTRING, 0, (LPARAM)drive.c_str());
                }
            }
        }
        else {
            std::vector<std::wstring> usbDrives = GetUSBDrives();
            for (const auto& drive : usbDrives) {
                SendMessageW(hDriveCombo, CB_ADDSTRING, 0, (LPARAM)drive.c_str());
            }
        }
        SendMessage(hDriveCombo, CB_SETCURSEL, 0, 0);

        HWND hClusterCombo = GetDlgItem(hwnd, IDC_CLUSTER_COMBO);
        const DWORD clusterSizes[] = { 0, 1, 2, 4, 8, 16, 32, 64, 128 };
        for (DWORD size : clusterSizes) {
            std::wstring text = size ? (std::to_wstring(size) + L" sector(s)") : L"Default";
            SendMessageW(hClusterCombo, CB_ADDSTRING, 0, (LPARAM)text.c_str());
        }
        SendMessage(hClusterCombo, CB_SETCURSEL, 0, 0);

        HWND hFsCombo = GetDlgItem(hwnd, IDC_FILESYSTEM_COMBO);
        SendMessageW(hFsCombo, CB_ADDSTRING, 0, (LPARAM)L"FAT32");
        SendMessageW(hFsCombo, CB_ADDSTRING, 0, (LPARAM)L"exFAT");
        SendMessageW(hFsCombo, CB_ADDSTRING, 0, (LPARAM)L"NTFS");
        SendMessage(hFsCombo, CB_SETCURSEL, 0, 0);

        SetDlgItemTextW(hwnd, IDC_RESERVED_EDIT, L"-1");

        HWND hProgress = GetDlgItem(hwnd, IDC_PROGRESS_BAR);
        SendMessage(hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hProgress, PBM_SETSTEP, 1, 0);
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        SetDlgItemTextW(hwnd, IDC_STATUS_TEXT, L"Status: Idle");

        return TRUE;
    }
    case WM_UPDATE_PROGRESS: {
        int progress = (int)wParam;
        HWND hProgress = GetDlgItem(hwnd, IDC_PROGRESS_BAR);
        SendMessage(hProgress, PBM_SETPOS, progress, 0);
        std::wstringstream ss;
        ss << L"Status: Formatting " << progress << L"% complete";
        SetDlgItemTextW(hwnd, IDC_STATUS_TEXT, ss.str().c_str());
        return TRUE;
    }
    case WM_FORMAT_COMPLETE: {
        bool success = (bool)wParam;
        if (formatThread) {
            CloseHandle(formatThread);
            formatThread = NULL;
            threadData = NULL;
        }
        EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDCANCEL), TRUE);
        SetDlgItemTextW(hwnd, IDC_STATUS_TEXT, success ? L"Status: Formatting completed successfully" : L"Status: Formatting failed");
        if (success) {
            MessageBoxW(hwnd, L"Formatting completed successfully.", L"Success", MB_OK | MB_ICONINFORMATION);
            EndDialog(hwnd, IDOK);
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            if (formatThread) return TRUE;

            HWND hDriveCombo = GetDlgItem(hwnd, IDC_DRIVE_COMBO);
            int driveIndex = static_cast<int>(SendMessage(hDriveCombo, CB_GETCURSEL, 0, 0));
            if (driveIndex == CB_ERR) {
                MessageBoxW(hwnd, L"Please select a drive.", L"Error", MB_OK | MB_ICONERROR);
                return TRUE;
            }
            wchar_t driveText[3];
            SendMessageW(hDriveCombo, CB_GETLBTEXT, driveIndex, (LPARAM)driveText);
            selectedDrive = static_cast<char>(driveText[0]);

            HWND hClusterCombo = GetDlgItem(hwnd, IDC_CLUSTER_COMBO);
            int clusterIndex = static_cast<int>(SendMessage(hClusterCombo, CB_GETCURSEL, 0, 0));
            const DWORD clusterSizes[] = { 0, 1, 2, 4, 8, 16, 32, 64, 128 };
            params.sectors_per_cluster = clusterSizes[clusterIndex];

            HWND hFsCombo = GetDlgItem(hwnd, IDC_FILESYSTEM_COMBO);
            int fsIndex = static_cast<int>(SendMessage(hFsCombo, CB_GETCURSEL, 0, 0));
            switch (fsIndex) {
            case 0: params.fs_type = FS_FAT32; break;
            case 1: params.fs_type = FS_EXFAT; break;
            case 2: params.fs_type = FS_NTFS; break;
            default: params.fs_type = FS_FAT32; break;
            }

            wchar_t reservedText[32];
            GetDlgItemTextW(hwnd, IDC_RESERVED_EDIT, reservedText, 32);
            params.ReservedSectCount = static_cast<DWORD>(_wtoi(reservedText));
            if (params.fs_type == FS_FAT32 && params.ReservedSectCount != (DWORD)-1 && params.ReservedSectCount < 8) {
                MessageBoxW(hwnd, L"Reserved sectors must be >= 8 or -1 for FAT32.", L"Error", MB_OK | MB_ICONERROR);
                return TRUE;
            }

            if (MessageBoxW(hwnd, (L"Warning: ALL data on drive '" + std::wstring(1, selectedDrive) + L"' will be lost irretrievably. Are you sure?").c_str(),
                L"Confirm Format", MB_YESNO | MB_ICONWARNING) != IDYES) {
                return TRUE;
            }

            params.drive_letter = selectedDrive;
            params.hwnd = hwnd;

            std::wstring DriveDevicePath = L"\\\\.\\" + std::wstring(1, selectedDrive) + L":";
            HANDLE hDevice = CreateFileW(DriveDevicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
            if (hDevice == INVALID_HANDLE_VALUE) {
                show_error(hwnd, L"Failed to open device - ensure Admin rights.");
                return TRUE;
            }

            DISK_GEOMETRY dgDrive;
            PARTITION_INFORMATION_EX xpiDrive;
            DWORD cbRet;
            if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dgDrive, sizeof(dgDrive), &cbRet, NULL)) {
                show_error(hwnd, L"Failed to get device geometry");
                CloseHandle(hDevice);
                return TRUE;
            }
            if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &xpiDrive, sizeof(xpiDrive), &cbRet, NULL)) {
                show_error(hwnd, L"Failed to get partition info");
                CloseHandle(hDevice);
                return TRUE;
            }

            threadData = new format_thread_data;
            threadData->params = &params; // Исправлено с ¶ms на params
            threadData->hDevice = hDevice;
            threadData->dgDrive = dgDrive;
            threadData->xpiDrive = xpiDrive;
            threadData->cancelEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            if (!threadData->cancelEvent) {
                show_error(hwnd, L"Failed to create cancel event");
                delete threadData;
                CloseHandle(hDevice);
                threadData = NULL;
                return TRUE;
            }

            EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDCANCEL), TRUE);
            SetDlgItemTextW(hwnd, IDC_STATUS_TEXT, L"Status: Formatting started...");
            SendMessage(GetDlgItem(hwnd, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0);

            formatThread = CreateThread(NULL, 0, FormatThread, threadData, 0, NULL);
            if (!formatThread) {
                show_error(hwnd, L"Failed to create format thread");
                CloseHandle(threadData->cancelEvent);
                CloseHandle(hDevice);
                delete threadData;
                threadData = NULL;
                EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
                EnableWindow(GetDlgItem(hwnd, IDCANCEL), TRUE);
            }
            return TRUE;
        }
        case IDCANCEL: {
            if (formatThread && threadData) {
                SetEvent(threadData->cancelEvent);
                MessageBoxW(hwnd, L"Cancelling format operation...", L"Information", MB_OK | MB_ICONINFORMATION);
                WaitForSingleObject(formatThread, 5000);
                if (formatThread) {
                    CloseHandle(formatThread);
                    formatThread = NULL;
                    threadData = NULL;
                }
                ResetEvent(threadData->cancelEvent);
                SetDlgItemTextW(hwnd, IDC_STATUS_TEXT, L"Status: Operation cancelled");
                EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
                EnableWindow(GetDlgItem(hwnd, IDCANCEL), TRUE);
            }
            else {
                EndDialog(hwnd, IDCANCEL);
            }
            return TRUE;
        }
        }
        break;
    case WM_CLOSE:
        if (formatThread && threadData) {
            SetEvent(threadData->cancelEvent);
            WaitForSingleObject(formatThread, 5000);
            if (formatThread) {
                CloseHandle(formatThread);
                formatThread = NULL;
                threadData = NULL;
            }
            ResetEvent(threadData->cancelEvent);
        }
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    if (!InitCommonControlsEx(&icc)) {
        MessageBoxW(NULL, L"Failed to initialize common controls.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    INT_PTR result = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_FORMAT_DIALOG), NULL, DialogProc, 0);
    if (result == -1) {
        show_error(NULL, L"Failed to create dialog");
        return 1;
    }
    return static_cast<int>(result);
}
