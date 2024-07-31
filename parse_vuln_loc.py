from __future__ import absolute_import, division, print_function
import re
import os
from get_functions import *
import argparse
import pandas as pd

from wasabi import Printer

msg = Printer()

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
    sorted_vuln_locations = sorted(vuln_locations.values(), key=lambda x: (x[3], x[0], x[1], x[2]))

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
                # if vuln[3] >= 0.5:
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
        
def main():
    parser = argparse.ArgumentParser()
     # Params
    parser.add_argument("--rca_dir", default='rca/rca_reports', type=str, required=False,
                        help="The path to the root cause analysis report directory. Default is `rca/rca_reports`.")
    parser.add_argument("--project_dir", default='rca/mruby', type=str, required=False,
                        help="The path to the project directory. Default is `rca/mruby`.")
    parser.add_argument("--output_dir", default="data/", type=str, required=False,
                        help="The output directory where the `vuln_functions.csv` file will be saved. Default is `data/`.")
    args = parser.parse_args()

    functions = get_function_info_from_rca(args.rca_dir, args.project_dir)
    
    functions = functions[:20]
    
    # sort the functions by the length of the code snippet
    functions = sorted(functions, key=lambda x: len(x[4]))
    msg.info(f"Total functions: {len(functions)}")
    msg.good(f"Function sample:\n {functions[0][4]}")

    # save all the function snippets into a csv file, and the column name is 'vuln_code'
    functions_df = pd.DataFrame(functions, columns=['function_name', 'line_number', 'file_name', 'path_rank', 'vuln_code'])
    
    # # length of the df should be the same as the length of the functions
    # assert(len(functions_df) == len(functions), "Length of the dataframe is not the same as the length of the functions")
    # print(len(functions_df))
    
    os.makedirs(args.output_dir, exist_ok=True)
    functions_df.to_csv(os.path.join(args.output_dir, 'vuln_functions.csv'), index=False)
    
    msg.info(f"Vulnerable functions saved to {os.path.join(args.output_dir, 'vuln_functions.csv')}")
    

if __name__ == '__main__':

    main()


    
    
