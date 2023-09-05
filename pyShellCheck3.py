import re
import json
import multiprocessing
from collections import defaultdict

def load_regex_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)

def analyze_vulnerability(script_content, pattern, description):
    vulnerabilities = []
    for word in script_content.split():
        if pattern.search(word):
            vulnerabilities.append(word)
    return description, vulnerabilities

def analyze_shell_script(script_path, regex_config, output_file, max_processes=None):
    try:
        with open(script_path, 'r') as script_file:
            script_content = script_file.read()

        # Create a multiprocessing Pool with a limited number of processes
        if max_processes is None:
            max_processes = multiprocessing.cpu_count() - 1  # Use all available CPU cores

        with multiprocessing.Pool(processes=max_processes) as pool:
            results = pool.starmap(analyze_vulnerability, [(script_content, pattern, description) for pattern, description in regex_config])

        vulnerabilities = defaultdict(list)

        for description, vulns in results:
            vulnerabilities[description].extend(vulns)

        result = {
            "vulnerabilities": dict(vulnerabilities),
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

    # Load the regular expressions and descriptions from the JSON config file
    regex_config = [(re.compile(pattern), description) for pattern, description in load_regex_config(config_file)]
    print(regex_config)

    # Limit the number of processes to the number of CPU cores - 1
    max_processes = multiprocessing.cpu_count() - 1
    print(max_processes)

    analyze_shell_script(script_path, regex_config, output_file, max_processes)
