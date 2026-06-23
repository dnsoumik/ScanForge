# Open the raw physical drive
drive = open(r"\\.\D:", "rb")

# Standard JPEG signatures
JPEG_START = b"\xff\xd8\xff\xe0"
JPEG_END = b"\xff\xd9"

file_count = 0
chunk_size = 512  # Read disk sector by sector

print("Scanning drive... Press Ctrl+C to stop.")
try:
    while True:
        chunk = drive.read(chunk_size)
        if not chunk:
            break
            
        # Check if sector starts with a JPEG header
        if chunk.startswith(JPEG_START):
            print(f"Found image #{file_count}, carving data...")
            file_data = chunk
            
            # Keep reading chunks until the closing signature is found
            while True:
                next_chunk = drive.read(chunk_size)
                file_data += next_chunk
                if JPEG_END in next_chunk:
                    break
            
            # Save the carved file out to a safe drive
            with open(f"C:\\Recovered\\restored_{file_count}.jpg", "wb") as f:
                f.write(file_data)
            file_count += 1
except KeyboardInterrupt:
    print("Scan stopped by user.")
finally:
    drive.close()
