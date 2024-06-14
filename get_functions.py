import tree_sitter_c as tsc
from tree_sitter import Language, Parser

def extract_functions_from_c_file(file_path):
    # Initialize the C language parser
    C_LANGUAGE = Language(tsc.language())
    
    # Create a parser instance
    parser = Parser(C_LANGUAGE)

    # Read the C file
    with open(file_path, 'r') as f:
        code = f.read()

    # Parse the C file
    tree = parser.parse(bytes(code, 'utf8'))

    # Function to extract function nodes
    def extract_functions(node):
        functions = []
        if node.type == 'function_definition':
            functions.append(node)
        for child in node.children:
            functions.extend(extract_functions(child))
        return functions

    # Extract function nodes
    root_node = tree.root_node
    functions = extract_functions(root_node)

    # Extract and return function snippets
    function_snippets = []
    for func in functions:
        start_byte = func.start_byte
        end_byte = func.end_byte
        snippet = code[start_byte:end_byte]
        # Extract function name
        declarator = func.child_by_field_name('declarator')
        if declarator is not None:
            for child in declarator.children:
                if child.type == 'identifier':
                    function_name = child.text.decode('utf-8')
                    function_snippets.append((function_name, snippet))
                    break

    return function_snippets

def get_function_snippet(file_path, function_name)->str:
    '''
    Obtain the function snippet for the specified function name from the given C file
    
    Note: If the function is not found, return a space character.
    '''
    
    
    # Extract all function snippets from the file
    function_snippets = extract_functions_from_c_file(file_path)
    
    # Filter and return the snippet for the specified function name
    for name, snippet in function_snippets:
        if name == function_name:
            return snippet

    # print(f"Function {function_name} not found in {file_path}")
    return ' '


if __name__ == "__main__":
    
    # Example usage:
    file_path = './rca/test_parser.c'
    function_snippets = extract_functions_from_c_file(file_path)
    for name, snippet in function_snippets:
        print(f"Function Name: {name}\n{snippet}\n")

    func_name = 'add'
    res = get_function_snippet(file_path, func_name)
    print(f"Snippet for {func_name}:\n{res}")
    