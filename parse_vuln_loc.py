import re
import os
from get_functions import *

def parse_vuln_locations(file_path):
    '''
    parse the root cause analysis report file, and return a list of tuples containing the function name, line number, file name, and path rank
    '''
    vuln_locations = {}

    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r'-- (.+) \(path rank: ([0-9.]+)\) //(\w+) at (\S+):(\d+)', line)
            if match:
                path_rank = float(match.group(2))
                function_name = match.group(3)
                file_name = match.group(4)
                line_number = match.group(5)
                key = (line_number, file_name)
                
                # Only add or replace the entry if the new path rank is higher
                if key not in vuln_locations:
                    vuln_locations[key] = (function_name, line_number, file_name, path_rank)

    # Convert the dictionary values to a list and sort
    sorted_vuln_locations = sorted(vuln_locations.values(), key=lambda x: (-x[3], x[0], x[1], x[2]))

    return sorted_vuln_locations

def traverse_dir(root_dir, file_name:str):
    '''Traverse from the root directory to search for the given file, return the file path if found
    heuristically return the found file path if the file path contains the |include| folder
    '''
    file_path = os.path.join(root_dir, file_name)
    
    if not os.path.exists(file_path):
        potential_file_paths = []
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file == file_name:
                    potential_file_paths.append(os.path.join(root, file))
        if len(potential_file_paths) == 0:
            # print(f"File {file_name} not found in {root_dir}")
            return None
        else:
            if len(potential_file_paths) > 1:
                # print(f"Multiple files with the same name {file_name} found in {root_dir}")
                pass
            else:
                # print(f"File {file_name} found in {root_dir}")
                pass
            
            for file_path in potential_file_paths:
                if 'src' in file_path:
                    return file_path
                elif 'core' in file_path:
                    return file_path
                elif 'include' in file_path:
                    return file_path
            return potential_file_paths[0]

def get_function_info_from_rca(rca_report_dir:str='./rca/rca_reports', project_dir:str='./rca/mruby'):
    '''Get the function snippets (list) for the function with the highest path rank from the root cause analysis report
    '''
    
    rca_report_path = os.path.join(rca_report_dir, 'ranked_predicates_verbose.txt')
    
    vuln_list = parse_vuln_locations(rca_report_path)
    
    # print(f"Vulns: {vuln_list}")
    
    function_list = []
    try: 
        for vuln in vuln_list:
            
            # use get_function_snippet to get the function snippet
            # print(f"Function Name: {vuln[0]}\nLine Number: {vuln[1]}\nFile Name: {vuln[2]}\nPath Rank: {vuln[3]}\n")
            
            file_path = os.path.join(project_dir, vuln[2])
            if not os.path.exists(file_path):
                file_path = traverse_dir(project_dir, vuln[2])
                if file_path is None:
                    # print(f"File {vuln[2]} not found, continuing...")
                    continue
            
            code_snippet = get_function_snippet(file_path, vuln[0])
            
            if code_snippet and code_snippet != ' ':
                
                # print(f"Code Snippet:\n{code_snippet}")
                
                # filter out the function snippet with path rank higher than 1.0
                # if vuln[2] == 'vm.c' and int(vuln[1]) >= 1100 and int(vuln[1]) <= 1250:
                if vuln[3] >= 0.5:
                    function_list.append((vuln[0], vuln[1], vuln[2], vuln[3], code_snippet))
                # print(f"Function Name: {vuln[0]}\nLine Number: {vuln[1]}\nFile Name: {vuln[2]}\nPath Rank: {vuln[3]}\n {code_snippet}\n")
                    # print(f"Function Name: {vuln[0]}\nLine Number: {vuln[1]}\nPath Rank: {vuln[3]}\n")
                

            else:
                # print(f"Function {vuln[0]} not found in {file_path}, continuing...")
                pass
        # break
        
    except Exception as e:
        print(f"Error: {e}, continuing...")
        
    return function_list
        

if __name__ == '__main__':

    project_dir = '/home/kaixuan/conti/AutoPatcher/rca/mruby'
    
    rca_report_dir = './rca/rca_reports'
    
    functions = get_function_info_from_rca(rca_report_dir, project_dir)
    
    print(f"Total functions: {len(functions)}")
    print(f"Function sample: {functions[0]}")
