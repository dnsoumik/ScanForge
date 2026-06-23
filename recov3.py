import os
import sys

DRIVE_PATH = "/d/"  
SECTOR_SIZE = 512  

# Root-level signatures to quickly filter data blocks
SIGNATURES = {
    # --- IMAGES ---
    b"\xFF\xD8\xFF": "JPG/JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
    b"8BPS": "PSD",
    b"<?xml": "SVG",
    b"\x49\x49\x2a\x00\x10\x00\x00\x00": "CR2",
    b"\x4d\x4d\x00\x2a": "NEF",
    
    # --- AUDIO & VIDEO CONTAINER BAIT ---
    b"RIFF": "RIFF_CONTAINER",  # Dissected downstream for WAV, AVI, WEBP
    b"OggS": "OGG/OPUS",
    b"fLaC": "FLAC",
    b"ID3": "MP3",
    b"\xFF\xFB": "MP3",
    b"\xFF\xF1": "AAC",
    b"\xFF\xF9": "AAC",
    
    # --- VIDEO & AUDIO (ISO BASE MEDIA CONTAINERS) ---
    b"\x1a\x45\xdf\xa3": "MKV/WEBM",
    b"FLV\x01": "FLV",
    b"\x00\x00\x01\xBA": "MPEG",
    b"\x00\x00\x01\xB3": "MPG",
    b"\x30\x26\xB2\x75\x8E\x66\xCF\x11": "WMV/WMA",
    
    # --- DOCUMENTS & ARCHIVES ---
    b"%PDF": "PDF",
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "DOC/XLS/PPT", # Legacy Microsoft Binary
    b"PK\x03\x04": "ZIP_CONTAINER",                  # Deep parsed for modern formats
    b"Rar!\x1a\x07\x00": "RAR",
    b"Rar!\x1a\x07\x01\x00": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7Z",
    b"\x1f\x8b": "GZ",
    b"BZh": "BZ2",
    b"\xfd\x37\x7a\x58\x5a\x00": "XZ",
    
    # --- TEXT / SOURCE CODE ---
    b"#!/": "SHELL_SCRIPT",
    b"import ": "PYTHON",
    b"def ": "PYTHON",
    b"#include": "C/CPP",
    b"using namespace": "CPP",
    b"<!DOCTYPE html": "HTML",
    b"<html>": "HTML",
}

def resolve_git_bash_path(bash_path):
    cleaned = bash_path.strip().strip('/')
    drive_letter = cleaned[0].upper() if cleaned else "D"
    return f"\\\\.\\{drive_letter}:"

def parse_shared_containers(sector_data, primary_type):
    """Deep inspects bytes to distinguish overlapping structural formats."""
    # Handle ISO Base Media File Format (MP4, MOV, HEIC, M4V, 3GP)
    if b"ftyp" in sector_data[4:12]:
        box = sector_data[8:16]
        if b"mp4" in box or b"MSNV" in box: return "MP4"
        if b"m4v" in box: return "M4V"
        if b"M4A" in box: return "M4A"
        if b"qt  " in box: return "MOV"
        if b"heic" in box or b"mif1" in box: return "HEIC"
        if b"3gp" in box: return "3GP"
        return "ISO_MEDIA_FORMAT"

    # Handle standard RIFF wrappers
    if primary_type == "RIFF_CONTAINER":
        payload = sector_data[8:12]
        if payload == b"WAVE": return "WAV"
        if payload == b"AVI ": return "AVI"
        if payload == b"WEBP": return "WEBP"
        return "RIFF_DATA"

    # Handle Zip Compressed Formats (DOCX, XLSX, PPTX, ODT, ODS, ODP)
    if primary_type == "ZIP_CONTAINER":
        if b"word/" in sector_data: return "DOCX"
        if b"xl/" in sector_data: return "XLSX"
        if b"ppt/" in sector_data: return "PPTX"
        if b"document" in sector_data and b"oasis" in sector_data: return "ODT"
        if b"spreadsheet" in sector_data and b"oasis" in sector_data: return "ODS"
        if b"presentation" in sector_data and b"oasis" in sector_data: return "ODP"
        return "ZIP"
        
    return primary_type

def scan_volume(bash_path, sector_size):
    device_path = resolve_git_bash_path(bash_path)
    discovered_files = []
    
    try:
        with open(device_path, "rb") as disk:
            sector_number = 0
            print(f"Monitoring Volume Context: {device_path}")
            
            while len(discovered_files) < 10:
                sector_data = disk.read(sector_size)
                if not sector_data or len(sector_data) < sector_size:
                    break

                # Catch custom plaintext files that lack standardized byte sequences
                if sector_number == 0 and not sector_data.startswith(b"\x00"):
                    if b"{" in sector_data[:10] and b":" in sector_data:
                        discovered_files.append(f"Found JSON structure at Sector: {sector_number}")

                # Evaluation against main dictionary structures
                matched = False
                for signature, file_type in SIGNATURES.items():
                    if sector_data.startswith(signature):
                        matched = True
                        final_extension = parse_shared_containers(sector_data, file_type)
                        record = f"Found {final_extension} format at Sector: {sector_number}"
                        discovered_files.append(record)
                        print(f"[!] Logged: {record}")
                        break

                # Scan for media box strings directly if root signature misses standard layout
                if not matched and b"ftyp" in sector_data[4:12]:
                    final_extension = parse_shared_containers(sector_data, "FTYP_BAIT")
                    record = f"Found {final_extension} format at Sector: {sector_number}"
                    discovered_files.append(record)
                    print(f"[!] Logged: {record}")

                if sector_number % 100000 == 0:
                    print(f"Sectors checked: {sector_number} | Logs captured: {len(discovered_files)}", end="\r")
                sector_number += 1

    except PermissionError:
        print("\n[ERROR] Administrative privileges are completely mandatory.")
    except Exception as error:
        print(f"\n[ERROR] Session failure: {error}")
    finally:
        print("\n" + "="*50)
        print("SUMMARY OF DISCOVERED FILES:")
        print("="*50)
        for index, item in enumerate(discovered_files, 1):
            print(f"{index}. {item}")

if __name__ == "__main__":
    scan_volume(DRIVE_PATH, SECTOR_SIZE)