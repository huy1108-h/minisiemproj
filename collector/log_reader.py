from pathlib import Path 
import time

def read_logs(file_path: str):
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                yield line #yield dung de doc 1 dong , roi xu ly sau do lai doc dong tiep roi lai xu ly , qua trinh lap lai.


def tail_logs(file_path: str, poll_interval: float = 0.5, start_from_beginning: bool = False):
    """
    Lắng nghe log thời gian thực theo cơ chế tail -f.
    Nếu start_from_beginning=False, sẽ nhảy tới cuối file và chỉ đọc các log mới sinh ra.
    """
    path = Path(file_path)
    if not path.exists():
        path.touch()

    with path.open("r", encoding="utf-8") as file:
        if not start_from_beginning:
            file.seek(0, 2)  # Seek to EOF

        while True:
            line = file.readline()
            if not line:
                time.sleep(poll_interval)
                continue

            line = line.strip()
            if line:
                yield line

def parse_log(line : str):
    parts = line.split()
    timestamp = f"{parts[0]} {parts[1]}"
    level = parts[2]

    data = {
        "timestamp": timestamp,
        "level": level,
    }

    for item in parts[3:]:
        if "=" in item:
            key, value = item.split("=", 1)
            data[key] = value

    return data

