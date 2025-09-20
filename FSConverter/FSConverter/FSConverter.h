#ifndef FAT32FORMATTERGUI_H
#define FAT32FORMATTERGUI_H

// � Windows API ���  ��������� ���������  ��� ����������� ��� ������� � ��������� ����������
#include <windows.h>
#include <winioctl.h>
#include <commctrl.h>

// �������������� ���������� ���� � ��������� ����������
#define IDD_FORMAT_DIALOG    100
#define IDC_DRIVE_COMBO     1001
#define IDC_CLUSTER_COMBO   1003
#define IDC_RESERVED_EDIT   1005
#define IDC_FILESYSTEM_COMBO 1009
#define IDC_PROGRESS_BAR    1012
#define IDC_STATUS_TEXT     1011
#define IDC_STATIC    1013
// �����������  Windows IDs
#define IDOK                1
#define IDCANCEL            2

// ��������� ��������� Windows
#define WM_UPDATE_PROGRESS  (WM_USER + 1)
#define WM_FORMAT_COMPLETE  (WM_USER + 2)

// ����������� �����
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int u32;
typedef unsigned long long u64;

// ������������ ����� �������� �������
typedef enum {
    FS_FAT32,
    FS_EXFAT,
    FS_NTFS
} fs_type_t;

// ��������� ���������� �������
typedef struct {
    fs_type_t fs_type;
    DWORD sectors_per_cluster;
    DWORD ReservedSectCount;
    char drive_letter;
    HWND hwnd;
} format_params;

// ��������� ��� �������������� ������ ������
typedef struct {
    format_params* params;
    HANDLE hDevice;
    DISK_GEOMETRY dgDrive;
    PARTITION_INFORMATION_EX xpiDrive;
    HANDLE cancelEvent; // ����� ��� ������
} format_thread_data;

#endif // FAT32FORMATTERGUI_H
