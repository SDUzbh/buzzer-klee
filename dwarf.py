import subprocess
import re
import sys

def extract_dwarf_entries(binary_path):
    try:
        result = subprocess.run(
            ["readelf", "--debug-dump=info", binary_path],
            capture_output=True, text=True, errors="ignore"
        )
        data = result.stdout
    except Exception as e:
        print("Error extracting DWARF info:", e)
        return

    entries = []

    entry_start_pattern = re.compile(r"<\s*\d+><[0-9a-f]+>:\s+Abbrev Number: \d+.*")
    name_pattern = re.compile(r"DW_AT_name\s+:\s*(.*)")
    line_pattern = re.compile(r"DW_AT_decl_line\s+:\s*(\d+)")
    location_pattern = re.compile(r"DW_AT_location\s+:\s*(.*)")

    current = {}
    for line in data.splitlines():
        if entry_start_pattern.match(line):
            if current:
                entries.append(current)
                current = {}
        elif "DW_TAG_variable" in line or "DW_TAG_formal_parameter" in line:
            current = {}
        elif "DW_AT_name" in line:
            match = name_pattern.search(line)
            if match:
                current["name"] = match.group(1).strip()
        elif "DW_AT_decl_line" in line:
            match = line_pattern.search(line)
            if match:
                current["line"] = match.group(1).strip()
        elif "DW_AT_location" in line:
            match = location_pattern.search(line)
            if match:
                current["location"] = match.group(1).strip()

    if current:
        entries.append(current)

    for entry in entries:
        name = entry.get("name", "<unknown>")
        line = entry.get("line", "<no_line>")
        location = entry.get("location", "<no_location>")
        print(f"{line}: {name}: {location}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dwarf_vars.py <binary_file>")
        sys.exit(1)

    binary_path = sys.argv[1]
    extract_dwarf_entries(binary_path)
