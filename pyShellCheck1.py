import re
import json
import multiprocessing

def load_regex_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)

def analyze_vulnerability(script_content, pattern, description, result_queue):
    if re.search(pattern, script_content):
        result_queue.put(description)

def analyze_shell_script(script_path, regex_config, output_file):
    try:
        with open(script_path, 'r') as script_file:
            script_content = script_file.read()

        result_queue = multiprocessing.Queue()
        processes = []

        for item in regex_config:
            pattern = item["pattern"]
            description = item["description"]
            process = multiprocessing.Process(target=analyze_vulnerability, args=(script_content, pattern, description, result_queue))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        vulnerabilities = []

        while not result_queue.empty():
            vulnerabilities.append(result_queue.get())

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
    
    # Load the regular expressions and descriptions from the JSON config file
    regex_config = load_regex_config(config_file)
    
    analyze_shell_script(script_path, regex_config, output_file)
