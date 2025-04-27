import yara

def scan_with_yara(file_path):
    try:
        # Compile the hardcoded YARA rules file
        rules_file = "yara_rules.yar"  # Hardcoded YARA rules file
        rules = yara.compile(filepath=rules_file)

        # Scan the file
        matches = rules.match(file_path)

        # Generate output string
        output = ""
        if matches:
            for match in matches:
                output += f"Matched Rule: {match.rule}\n"
                output += f"Tags: {match.tags}\n"
                output += f"Strings: {match.strings}\n\n"
        else:
            output = "No matches found."

        return output
    except Exception as e:
        return f"Error scanning with YARA: {str(e)}"

# Example usage:
if __name__ == "__main__":
    # Adjust the rules_file and file_path as needed
    rules_file = "path/to/your/yara_rules.yar"  # Hardcoded YARA rules file
    file_path = "path/to/your/file"
    print(scan_with_yara(file_path, rules_file))
