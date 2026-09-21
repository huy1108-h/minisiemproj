from pathlib import Path
def read_logs(file_path: str):
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                yield line  


