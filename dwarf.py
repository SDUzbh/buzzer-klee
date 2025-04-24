import subprocess
import re
import sys

def extract_dwarf_entries(binary_path):
    """Extract DWARF information (variable names and line numbers)."""
    try:
        result = subprocess.run(
            ["readelf", "--debug-dump=info", binary_path],
            capture_output=True, text=True, errors="ignore"
        )
        data = result.stdout
    except Exception as e:
        print("Error extracting DWARF info:", e)
        return []

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

    return entries

def extract_register_info(register_file):
    """Extract register values and their corresponding offsets."""
    registers = {}
    with open(register_file, 'r') as file:
        for line in file:
            match = re.match(r"Offset: (\d+), Register: (\w+), Value: (\d+)", line.strip())
            if match:
                offset = int(match.group(1))
                register = match.group(2)
                value = int(match.group(3))
                registers[offset] = (register, value)
    return registers

def merge_dwarf_and_registers(dwarf_entries, register_info):
    """Merge DWARF information with register values based on line number and offset."""
    merged_info = []
    for entry in dwarf_entries:
        line = entry.get("line")
        name = entry.get("name")
        location = entry.get("location")
        
        # Try to extract the offset from the location
        if location:
            match = re.match(r"DW_OP_fbreg (-?\d+)", location)
            if match:
                offset = int(match.group(1))
                # Check if we have a corresponding register and value for this offset
                if offset in register_info:
                    register, value = register_info[offset]
                    merged_info.append({
                        "line": line,
                        "variable": name,
                        "register": register,
                        "value": value
                    })
    return merged_info

def print_merged_info(merged_info):
    """Print merged information in the format: line-number variable register-value."""
    for item in merged_info:
        print(f"Line {item['line']}: {item['variable']} - {item['register']} = {item['value']}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python merge_dwarf_and_registers.py <binary_file> <register_file>")
        sys.exit(1)

    binary_file = sys.argv[1]
    register_file = sys.argv[2]

    dwarf_entries = extract_dwarf_entries(binary_file)
    register_info = extract_register_info(register_file)
    
    merged_info = merge_dwarf_and_registers(dwarf_entries, register_info)
    print_merged_info(merged_info)
