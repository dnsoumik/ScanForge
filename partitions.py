import ctypes
import os
import string
import sys

def get_all_partitions_with_names():
    drive_bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    
    bytes_in_gb = 1024 ** 3
    sectors_per_cluster = ctypes.c_ulong()
    bytes_per_sector = ctypes.c_ulong()
    free_clusters = ctypes.c_ulong()
    total_clusters = ctypes.c_ulong()

    for i in range(26):
        if drive_bitmask & (1 << i):
            drive_letter = string.ascii_uppercase[i]
            drive_root = f"{drive_letter}:\\"
            
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_root))
            if drive_type not in (3, 4, 6):  # Fixed, Network, or RAM disks
                continue

            # Buffer setup to hold the volume name
            volume_name_buffer = ctypes.create_unicode_buffer(260)
            
            # Fetch Volume Name
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_root),
                volume_name_buffer,
                ctypes.sizeof(volume_name_buffer),
                None, None, None, None, 0
            )
            
            # If the partition has no custom label, assign a default identifier
            volume_name = volume_name_buffer.value if volume_name_buffer.value else "Local Disk"

            # Fetch storage geometry and spaces
            success = ctypes.windll.kernel32.GetDiskFreeSpaceW(
                ctypes.c_wchar_p(drive_root),
                ctypes.byref(sectors_per_cluster),
                ctypes.byref(bytes_per_sector),
                ctypes.byref(free_clusters),
                ctypes.byref(total_clusters)
            )

            if not success:
                continue

            b_sector = bytes_per_sector.value
            s_cluster = sectors_per_cluster.value
            t_clusters = total_clusters.value
            f_clusters = free_clusters.value

            total_sectors = s_cluster * t_clusters
            total_bytes = total_sectors * b_sector
            free_bytes = f_clusters * s_cluster * b_sector
            used_bytes = total_bytes - free_bytes

            total_gb = total_bytes / bytes_in_gb
            used_gb = used_bytes / bytes_in_gb
            git_bash_path = f"/{drive_letter.lower()}/"

            # Formatted terminal output block
            print(f"Drive: {drive_letter}: {volume_name}")
            print(f"Path: {git_bash_path}")
            print(f"Sector Size: {total_sectors}")
            print(f"Used Space: {used_gb:.2f} GB / {total_gb:.2f} GB")
            print("-" * 30)

if __name__ == "__main__":
    get_all_partitions_with_names()