import re
import json
from collections import defaultdict

def load_regex_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)

def analyze_vulnerabilities(script_content, regex_config):
    vulnerabilities = defaultdict(list)

    for pattern_data, description in regex_config:
        pattern= re.compile(pattern_data)
        print(pattern)
        for word in script_content.split():
            if pattern.search(word):
                vulnerabilities[description].append(word)

    return vulnerabilities

def analyze_shell_script(script_path, regex_config, output_file):
    try:
        with open(script_path, 'r') as script_file:
            script_content = script_file.read()

        vulnerabilities = analyze_vulnerabilities(script_content, regex_config)

        result = {
            "vulnerabilities": vulnerabilities,
            "script_path": script_path,
        }

        with open(output_file, 'w') as json_output:
            json.dump(result, json_output, indent=4)

        print(f"Analysis results saved to {output_file}")

    except Exception as e:
        print(f"Error analyzing the script: {str(e)}")

if __name__ == "__main__":
    script_path = "example.sh"
    config_file = "regex_config.json"
    output_file = "analysis_result.json"
    json_content =load_regex_config(config_file)
    
    # Load the regular expressions and descriptions from the JSON config file
    regex_config = [(content['pattern'], content['description']) for content in json_content]

    analyze_shell_script(script_path, regex_config, output_file)
