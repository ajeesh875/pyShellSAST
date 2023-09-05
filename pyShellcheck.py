import re

# Read the shell script file
def find_vulnerabilities(script_file):
    with open(script_file, 'r') as f:
        script_content = f.read()
        
        # Search for CWE-78: OS Command Injection
        cwe_78_matches = re.findall(r'\$\((.*?)\)|\$\{(.*?)\}', script_content)
        
        # Search for CWE-73: External Control of File Name or Path
        cwe_73_matches = re.findall(r'\bcat\b\s+(\'|"|`).*?\'|\".*?\"|`.*?`', script_content)
        
        return cwe_78_matches, cwe_73_matches

if __name__ == "__main__":
    script_file = "script.sh"
    
    cwe_78_matches, cwe_73_matches = find_vulnerabilities(script_file)
    
    if cwe_78_matches:
        print("CWE-78: OS Command Injection vulnerabilities found:")
        for match in cwe_78_matches:
            print("Match:", match[0] or match[1])
    
    if cwe_73_matches:
        print("CWE-73: External Control of File Name or Path vulnerabilities found:")
        for match in cwe_73_matches:
            print("Match:", match)

    if not cwe_78_matches and not cwe_73_matches:
        print("No vulnerabilities found.")
