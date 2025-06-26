from mcp.server.fastmcp import FastMCP
import requests


binja_server_url = "http://localhost:9009"
mcp = FastMCP("binja-mcp")


def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request. If 'params' is given, we convert it to a query string.
    """
    if params is None:
        params = {}
    qs = [f"{k}={v}" for k, v in params.items()]
    query_string = "&".join(qs)
    url = f"{binja_server_url}/{endpoint}"
    if query_string:
        url += "?" + query_string

    try:
        response = requests.get(url, timeout=5)
        response.encoding = "utf-8"
        if response.ok:
            try:
                # Try to parse JSON response
                json_data = response.json()
                # If the response has a main data key, return that array
                if isinstance(json_data, dict):
                    # Look for common array keys
                    for key in ["tags", "functions", "methods", "strings", "imports", "exports", "data", "matches", "types", "sections", "symbols", "references", "callees", "callers"]:
                        if key in json_data and isinstance(json_data[key], list):
                            return json_data[key]
                    # If no array found, return the whole response as a single item
                    return [json_data]
                elif isinstance(json_data, list):
                    return json_data
                else:
                    return [json_data]
            except ValueError:
                # Fallback to original behavior for non-JSON responses
                return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        if isinstance(data, dict):
            response = requests.post(
                f"{binja_server_url}/{endpoint}", data=data, timeout=5
            )
        else:
            response = requests.post(
                f"{binja_server_url}/{endpoint}", data=data.encode("utf-8"), timeout=5
            )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def retype_variable(function_name: str, variable_name: str, type_str: str) -> str:
    """
    Retype a variable in a function.
    """
    return safe_get("retypeVariable", {"functionName": function_name, "variableName": variable_name, "type": type_str})

@mcp.tool()
def rename_variable(function_name: str, variable_name: str, new_name: str) -> str:
    """
    Rename a variable in a function.
    """
    return safe_get("renameVariable", {"functionName": function_name, "variableName": variable_name, "newName": new_name})

@mcp.tool()
def define_types(c_code: str) -> str:
    """
    Define types from a C code string.
    """
    return safe_get("defineTypes", {"cCode": c_code})

@mcp.tool()
def edit_function_signature(function_name: str, signature: str) -> str:
    """
    Edit the signature of a function.
    """
    return safe_get("editFunctionSignature", {"functionName": function_name, "signature": signature})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})


@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_get("decompile", {"name": name})

@mcp.tool()
def fetch_disassembly(name: str) -> list:
    """
    Retrieve the disassembled code of a function with a given name as assembly mnemonic instructions.
    """
    return safe_get("assembly", {"name": name})

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@mcp.tool()
def set_comment(address: str, comment: str) -> str:
    """
    Set an address comment at a specific address. Address comments are global to the binary 
    and visible everywhere that address appears. Use primarily for data annotations, global 
    constants, or memory layout notes. For code annotations within functions, prefer function 
    comments instead.
    """
    return safe_post("comment", {"address": address, "comment": comment})

@mcp.tool()
def get_comment(address: str) -> str:
    """
    Get the address comment at a specific address. Address comments are global annotations
    visible throughout the binary wherever this address appears.
    """
    return safe_get("comment", {"address": address})[0]

@mcp.tool()
def delete_comment(address: str) -> str:
    """
    Delete the address comment at a specific address. This removes the global annotation
    that was visible throughout the binary at this address.
    """
    return safe_post("comment", {"address": address, "_method": "DELETE"})

@mcp.tool()
def set_function_comment(function_name: str, comment: str) -> str:
    """
    Set a function comment. Function comments are specific to individual functions and only 
    visible within that function's context. Use for function-level documentation, behavior 
    descriptions, and ALL code annotations within functions (disassembly, decompilation analysis, 
    algorithm explanations, etc.). This is the preferred method for annotating function code.
    """
    return safe_post("comment/function", {"name": function_name, "comment": comment})

@mcp.tool()
def get_function_comment(function_name: str) -> str:
    """
    Get the function comment. Returns the function-specific comment that is only visible 
    within this function's context, not address comments that might exist at the function's address.
    """
    return safe_get("comment/function", {"name": function_name})[0]

@mcp.tool()
def delete_function_comment(function_name: str) -> str:
    """
    Delete the function comment. This removes only the function-specific comment, 
    not any address comments that might exist at the function's address.
    """
    return safe_post("comment/function", {"name": function_name, "_method": "DELETE"})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring (case insensitive).
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(
        "searchFunctions", {"query": query, "offset": offset, "limit": limit}
    )


@mcp.tool()
def load_binary(filepath: str) -> str:
    """
    Load a binary file for analysis.
    
    Args:
        filepath: Path to the binary file to load
    """
    return safe_post("load", {"filepath": filepath})

@mcp.tool()
def get_binary_status() -> str:
    """
    Get the current status of the loaded binary.
    """
    return safe_get("status")[0]

@mcp.tool()
def function_at(address: str) -> list:
    """
    Retrieve the name of the function the address belongs to. Address must be in hexadecimal format 0x00001
    """
    return safe_get("functionAt", {"address": address})

@mcp.tool()
def code_references(function_name: str) -> list:
    """
    Retrieve names and addresses of functions that call the given function_name
    """
    return safe_get("codeReferences", {"function": function_name})
    
@mcp.tool()
def get_user_defined_type(type_name: str) -> list:
    """
    Retrieve definition of a user defined type (struct, enumeration, typedef, union)
    """
    return safe_get("getUserDefinedType", {"name": type_name})

# ========== STRING ANALYSIS TOOLS ==========

@mcp.tool()
def list_strings(min_length: int = 4, encoding: str = 'utf-8', offset: int = 0, limit: int = 100) -> list:
    """
    Get all strings found in the binary with pagination and filtering.
    
    Args:
        min_length: Minimum string length to include (default: 4)
        encoding: String encoding to search for (default: 'utf-8') 
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 100)
    """
    return safe_get("strings", {"minLength": min_length, "encoding": encoding, "offset": offset, "limit": limit})

@mcp.tool()
def search_strings(pattern: str, regex: bool = False, case_sensitive: bool = False, offset: int = 0, limit: int = 100) -> list:
    """
    Search for strings matching a specific pattern.
    
    Args:
        pattern: Search pattern to match against string content
        regex: Whether to treat pattern as regex (default: False)
        case_sensitive: Whether search should be case sensitive (default: False)
        offset: Pagination offset (default: 0)
        limit: Maximum results to return (default: 100)
    """
    return safe_get("searchStrings", {"pattern": pattern, "regex": regex, "caseSensitive": case_sensitive, "offset": offset, "limit": limit})

@mcp.tool()
def get_string_references(address: str) -> list:
    """
    Get all references to a specific string address.
    
    Args:
        address: Address of the string (hex format like 0x401000)
    """
    return safe_get("stringReferences", {"address": address})

@mcp.tool()
def analyze_string_usage() -> str:
    """
    Analyze string usage patterns and get statistics about strings in the binary.
    """
    return safe_get("analyzeStringUsage")

# ========== TAG MANAGEMENT TOOLS ==========

@mcp.tool()
def list_tag_types() -> list:
    """
    List all available tag types in the binary view.
    """
    return safe_get("tagTypes")

@mcp.tool()
def create_tag_type(name: str, icon: str = "🏷️", visible: bool = True) -> str:
    """
    Create a new tag type.
    
    Args:
        name: Name of the tag type
        icon: Icon character for the tag type (default: 🏷️)
        visible: Whether the tag type should be visible (default: True)
    """
    return safe_post("createTagType", {"name": name, "icon": icon, "visible": visible})

@mcp.tool()
def list_tags(tag_type: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List tags in the binary, optionally filtered by tag type (case insensitive).
    
    Args:
        tag_type: Optional tag type name to filter by
        offset: Pagination offset (default: 0)
        limit: Maximum number of tags to return (default: 100)
    """
    params = {"offset": offset, "limit": limit}
    if tag_type:
        params["tagType"] = tag_type
    return safe_get("tags", params)

@mcp.tool()
def create_address_tag(tag_type: str, address: str, data: str = None) -> str:
    """
    Create a tag at a specific address.
    
    Args:
        tag_type: Name of the tag type
        address: Address to tag (hex format like 0x401000)
        data: Optional data associated with the tag
    """
    params = {"tagType": tag_type, "address": address}
    if data:
        params["data"] = data
    return safe_post("createAddressTag", params)

@mcp.tool()
def create_function_tag(tag_type: str, function_name: str, data: str = None) -> str:
    """
    Create a tag on a function.
    
    Args:
        tag_type: Name of the tag type
        function_name: Name of the function to tag
        data: Optional data associated with the tag
    """
    params = {"tagType": tag_type, "functionName": function_name}
    if data:
        params["data"] = data
    return safe_post("createFunctionTag", params)

@mcp.tool()
def create_data_tag(tag_type: str, address: str, data: str = None) -> str:
    """
    Create a tag on data at a specific address.
    
    Args:
        tag_type: Name of the tag type
        address: Address of the data to tag (hex format like 0x401000)
        data: Optional data associated with the tag
    """
    params = {"tagType": tag_type, "address": address}
    if data:
        params["data"] = data
    return safe_post("createDataTag", params)

@mcp.tool()
def get_tags_at_address(address: str) -> list:
    """
    Get all tags at a specific address.
    
    Args:
        address: Address to check for tags (hex format like 0x401000)
    """
    return safe_get("tagsAtAddress", {"address": address})

@mcp.tool()
def remove_tag(tag_id: str) -> str:
    """
    Remove a tag by its ID.
    
    Args:
        tag_id: ID of the tag to remove
    """
    return safe_post("removeTag", {"tagId": tag_id})

@mcp.tool()
def search_tags(query: str) -> list:
    """
    Search tags by their data content (case insensitive).
    
    Args:
        query: Search query to match against tag data
    """
    return safe_get("searchTags", {"query": query})

# ========== ENHANCED CROSS-REFERENCE TOOLS ==========

@mcp.tool()
def get_all_references_to(address: str) -> str:
    """
    Get all references (code and data) to a specific address.
    
    Args:
        address: Target address to find references to (hex format like 0x401000)
    """
    return safe_get("allReferencesTo", {"address": address})

@mcp.tool()
def get_all_references_from(address: str) -> str:
    """
    Get all references from a specific address.
    
    Args:
        address: Source address to find references from (hex format like 0x401000)
    """
    return safe_get("allReferencesFrom", {"address": address})

@mcp.tool()
def find_constant_usage(value: str, size: int = None) -> list:
    """
    Find all uses of a specific constant value in the binary.
    
    Args:
        value: Constant value to search for (can be decimal or hex with 0x prefix)
        size: Optional size constraint in bytes (1, 2, 4, 8)
    """
    params = {"value": value}
    if size:
        params["size"] = size
    return safe_get("findConstantUsage", params)

@mcp.tool()
def get_call_graph(function_name: str, depth: int = 2, direction: str = "both") -> str:
    """
    Get call graph relationships for a function.
    
    Args:
        function_name: Name of the function to analyze
        depth: Maximum depth to traverse (default: 2)
        direction: Direction to analyze - 'callers', 'callees', or 'both' (default: 'both')
    """
    return safe_get("callGraph", {"functionName": function_name, "depth": depth, "direction": direction})

@mcp.tool()
def find_function_callers(function_name: str, recursive: bool = False) -> list:
    """
    Enhanced function caller analysis.
    
    Args:
        function_name: Name of the function to find callers for
        recursive: Whether to find callers recursively (default: False)
    """
    return safe_get("functionCallers", {"functionName": function_name, "recursive": recursive})

@mcp.tool()
def analyze_cross_references_summary() -> str:
    """
    Get a summary of cross-reference patterns in the binary including statistics
    about function call relationships and orphaned functions.
    """
    return safe_get("crossReferencesSummary")

# ========== MEMORY & DATA ANALYSIS TOOLS ==========

@mcp.tool()
def read_bytes(address: str, length: int) -> str:
    """
    Read raw bytes from the binary at a specific address.
    
    Args:
        address: Address to read from (hex format like 0x401000)
        length: Number of bytes to read
    """
    return safe_get("readBytes", {"address": address, "length": length})

@mcp.tool()
def write_bytes(address: str, data: str) -> str:
    """
    Write bytes to the binary at a specific address.
    
    Args:
        address: Address to write to (hex format like 0x401000)
        data: Hex string of data to write (e.g., "41424344")
    """
    return safe_post("writeBytes", {"address": address, "data": data})

@mcp.tool()
def get_instruction_details(address: str) -> str:
    """
    Get detailed instruction information at a specific address.
    
    Args:
        address: Address of the instruction (hex format like 0x401000)
    """
    return safe_get("getInstruction", {"address": address})

# ========== IL (INTERMEDIATE LANGUAGE) ACCESS TOOLS ==========

@mcp.tool()
def get_hlil_function(function_name: str) -> str:
    """
    Get High Level Intermediate Language representation of a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("hlilFunction", {"functionName": function_name})

@mcp.tool()
def get_mlil_function(function_name: str) -> str:
    """
    Get Medium Level Intermediate Language representation of a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("mlilFunction", {"functionName": function_name})

@mcp.tool()
def get_llil_function(function_name: str) -> str:
    """
    Get Low Level Intermediate Language representation of a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("llilFunction", {"functionName": function_name})

@mcp.tool()
def find_il_instructions(function_name: str, operation_type: str, il_level: str = "hlil") -> list:
    """
    Find specific IL operations in a function.
    
    Args:
        function_name: Name or address of the function
        operation_type: Type of operation to find (e.g., "HLIL_CALL", "HLIL_ASSIGN")
        il_level: IL level to search - "hlil", "mlil", or "llil" (default: "hlil")
    """
    return safe_get("findILInstructions", {"functionName": function_name, "operationType": operation_type, "ilLevel": il_level})

# ========== BASIC BLOCK & CONTROL FLOW ANALYSIS TOOLS ==========

@mcp.tool()
def get_basic_blocks(function_name: str) -> str:
    """
    Get basic blocks information for a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("basicBlocks", {"functionName": function_name})

@mcp.tool()
def get_control_flow_graph(function_name: str) -> str:
    """
    Get control flow graph information for a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("controlFlowGraph", {"functionName": function_name})

@mcp.tool()
def find_loops(function_name: str) -> str:
    """
    Identify loop structures in a function.
    
    Args:
        function_name: Name or address of the function
    """
    return safe_get("findLoops", {"functionName": function_name})

# ========== SEARCH & PATTERN MATCHING TOOLS ==========

@mcp.tool()
def search_bytes(pattern: str, mask: str = None) -> list:
    """
    Search for byte patterns in the binary.
    
    Args:
        pattern: Hex string pattern to search for (e.g., "41424344")
        mask: Optional mask string (e.g., "FFFF00FF") to ignore certain bytes
    """
    params = {"pattern": pattern}
    if mask:
        params["mask"] = mask
    return safe_get("searchBytes", params)

@mcp.tool()
def find_immediate_values(value: str, size: int = None) -> list:
    """
    Find immediate values in instructions.
    
    Args:
        value: Value to search for (can be decimal or hex with 0x prefix)
        size: Optional size constraint in bytes (1, 2, 4, 8)
    """
    params = {"value": value}
    if size:
        params["size"] = size
    return safe_get("findImmediateValues", params)

@mcp.tool()
def search_instructions(mnemonic: str, operand_pattern: str = None) -> list:
    """
    Search for specific instruction patterns.
    
    Args:
        mnemonic: Instruction mnemonic to search for (e.g., "call", "mov")
        operand_pattern: Optional operand pattern to match
    """
    params = {"mnemonic": mnemonic}
    if operand_pattern:
        params["operandPattern"] = operand_pattern
    return safe_get("searchInstructions", params)

@mcp.tool()
def find_apis_by_pattern(pattern: str) -> list:
    """
    Find API calls matching a pattern.
    
    Args:
        pattern: Pattern to match against API names (case insensitive search)
    """
    return safe_get("findAPIsByPattern", {"pattern": pattern})

# ========== ANALYSIS CONTROL TOOLS ==========

@mcp.tool()
def run_analysis(analysis_type: str = "auto") -> str:
    """
    Run or control Binary Ninja analysis.
    
    Args:
        analysis_type: Type of analysis to run - "auto", "linear", or "full" (default: "auto")
    """
    return safe_get("runAnalysis", {"analysisType": analysis_type})

@mcp.tool()
def analyze_function(function_name: str) -> str:
    """
    Force reanalysis of a specific function.
    
    Args:
        function_name: Name or address of function to reanalyze
    """
    return safe_get("analyzeFunction", {"functionName": function_name})

@mcp.tool()
def create_function(address: str) -> str:
    """
    Create a function at the specified address.
    
    Args:
        address: Address where to create the function (hex format like 0x401000)
    """
    return safe_get("createFunction", {"address": address})

@mcp.tool()
def undefine_function(function_name: str) -> str:
    """
    Remove a function definition.
    
    Args:
        function_name: Name or address of function to undefine
    """
    return safe_get("undefineFunction", {"functionName": function_name})

@mcp.tool()
def get_analysis_info() -> str:
    """
    Get information about the current analysis state including binary details,
    architecture, platform, and analysis statistics.
    """
    return safe_get("analysisInfo")


@mcp.tool()
def get_dominance_tree(function_name: str) -> str:
    """
    Get dominance tree information for a function.
    
    Args:
        function_name: Name or address of the function to analyze
    """
    return safe_get("dominanceTree", {"functionName": function_name})

@mcp.tool()
def get_data_type_at(address: str) -> str:
    """
    Get data type information at a specific address.
    
    Args:
        address: Address to check (hex format like 0x401000)
    """
    return safe_get("getDataType", {"address": address})

@mcp.tool()
def define_data_type(address: str, type_string: str) -> str:
    """
    Define data at an address as a specific type.
    
    Args:
        address: Address to define (hex format like 0x401000)
        type_string: Type string (e.g., "int32_t", "char[16]", "struct MyStruct")
    """
    return safe_post("defineDataType", {"address": address, "typeString": type_string})

# ========== ENHANCED STRUCT AND TYPE MANAGEMENT TOOLS ==========

@mcp.tool()
def list_user_types(offset: int = 0, limit: int = 100) -> list:
    """
    List all user-defined types (structs, enums, typedefs) with metadata and pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of types to return (default: 100)
        
    Returns:
        List of user-defined types with detailed information including
        name, category (struct/enum/typedef), size, member count, and member details
    """
    return safe_get("listUserTypes", {"offset": offset, "limit": limit})

@mcp.tool()
def create_struct(name: str, members: str, packed: bool = False) -> str:
    """
    Create a new structure type with specified members.
    
    Args:
        name: Name of the structure to create
        members: JSON string defining struct members. Format: [{"name": "field1", "type": "int32_t"}, {"name": "field2", "type": "char*"}]
        packed: Whether the structure should be packed (default: False)
        
    Example members JSON:
        '[{"name": "id", "type": "int32_t"}, {"name": "name", "type": "char[32]"}, {"name": "next", "type": "struct Node*"}]'
    """
    return safe_post("createStruct", {"name": name, "members": members, "packed": packed})

@mcp.tool()
def modify_struct(name: str, operation: str, member_name: str = None, member_type: str = None, index: int = None) -> str:
    """
    Modify an existing structure type by adding or removing members.
    
    Args:
        name: Name of the structure to modify
        operation: Operation to perform - "add_member" or "remove_member"
        member_name: Name of the member (required for both operations)
        member_type: Type string for the member (required for add_member)
        index: Position to insert new member (optional for add_member)
        
    Examples:
        Add member: modify_struct("MyStruct", "add_member", "new_field", "int32_t")
        Remove member: modify_struct("MyStruct", "remove_member", "old_field")
    """
    data = {"name": name, "operation": operation}
    if member_name:
        data["memberName"] = member_name
    if member_type:
        data["memberType"] = member_type
    if index is not None:
        data["index"] = index
    
    return safe_post("modifyStruct", data)

@mcp.tool()
def create_enum(name: str, members: str, size: int = 4) -> str:
    """
    Create a new enumeration type.
    
    Args:
        name: Name of the enumeration to create
        members: JSON string defining enum members. Format: [{"name": "VALUE1", "value": 0}, {"name": "VALUE2", "value": 1}]
        size: Size of the enumeration in bytes (default: 4)
        
    Example members JSON:
        '[{"name": "SUCCESS", "value": 0}, {"name": "ERROR", "value": 1}, {"name": "PENDING", "value": 2}]'
    """
    return safe_post("createEnum", {"name": name, "members": members, "size": size})

@mcp.tool()
def create_union(name: str, members: str) -> str:
    """
    Create a new union type.
    
    Args:
        name: Name of the union to create
        members: JSON string defining union members. Format: [{"name": "field1", "type": "int32_t"}, {"name": "field2", "type": "float"}]
        
    Example members JSON:
        '[{"name": "int_val", "type": "int32_t"}, {"name": "float_val", "type": "float"}, {"name": "ptr_val", "type": "void*"}]'
    """
    return safe_post("createUnion", {"name": name, "members": members})

@mcp.tool()
def create_typedef(name: str, target_type: str) -> str:
    """
    Create a type alias (typedef).
    
    Args:
        name: Name of the new type alias
        target_type: Target type string to alias (e.g., "int32_t", "struct MyStruct*")
        
    Examples:
        create_typedef("HANDLE", "void*")
        create_typedef("NodePtr", "struct Node*")
    """
    return safe_post("createTypedef", {"name": name, "targetType": target_type})

@mcp.tool()
def delete_user_type(name: str) -> str:
    """
    Remove a user-defined type (struct, enum, union, or typedef).
    
    Args:
        name: Name of the type to remove
        
    Warning: This will permanently remove the type definition.
    Make sure no other types or variables depend on this type.
    """
    return safe_post("deleteUserType", {"name": name})

@mcp.tool()
def get_type_references(name: str) -> list:
    """
    Find all locations where a specific type is used throughout the binary.
    
    Args:
        name: Name of the type to find references for
        
    Returns:
        List of references showing where the type is used in variables,
        function parameters, return types, and struct members
    """
    return safe_get("getTypeReferences", {"name": name})

@mcp.tool()
def analyze_struct_usage(name: str) -> str:
    """
    Analyze how a structure is used in the binary including usage patterns and member access frequency.
    
    Args:
        name: Name of the structure to analyze
        
    Returns:
        Detailed analysis including:
        - Structure information (size, member count, packing)
        - Usage patterns (as variable, pointer, array, parameter)
        - Member access patterns and frequency
        - Frequently accessed offsets
        - Instantiation locations across functions
    """
    return safe_get("analyzeStructUsage", {"name": name})

@mcp.tool()
def export_types_as_c_header(type_names: str = None) -> str:
    """
    Export type definitions as C header code.
    
    Args:
        type_names: Comma-separated list of specific type names to export. 
                   If empty or None, exports all user-defined types.
                   
    Returns:
        Complete C header file content with all type definitions,
        properly formatted with includes and header guards
        
    Example:
        export_types_as_c_header("MyStruct,MyEnum,MyTypedef")
        export_types_as_c_header()  # Export all types
    """
    params = {}
    if type_names:
        params["typeNames"] = type_names
    
    return safe_get("exportTypesHeader", params)


# New advanced analysis tools

@mcp.tool()
def get_memory_map() -> list:
    """
    Get a comprehensive memory layout map including segments, sections, and entry points.
    
    Returns detailed information about the binary's memory structure including:
    - Segments with permissions and entropy data
    - Sections with their names and locations
    - Entry points and address ranges
    - Memory region types and characteristics
    """
    return safe_get("memory_map")

@mcp.tool()
def get_sections(offset: int = 0, limit: int = 100) -> list:
    """
    Get detailed information about binary sections with pagination.
    
    Args:
        offset: Starting index for pagination
        limit: Maximum number of sections to return
        
    Returns:
        List of sections with their names, addresses, sizes, and types
    """
    return safe_get("sections", {"offset": offset, "limit": limit})

@mcp.tool()
def get_entropy(address: str, length: int, block_size: int = 256) -> list:
    """
    Calculate Shannon entropy for a specific memory region.
    
    Args:
        address: Starting address (hex string like "0x401000" or decimal)
        length: Number of bytes to analyze
        block_size: Size of each entropy calculation block (default 256)
        
    Returns:
        Entropy analysis results including values, averages, and statistics
        
    Example:
        get_entropy("0x401000", 4096, 512)
    """
    return safe_get("entropy", {"address": address, "length": length, "block_size": block_size})

@mcp.tool()
def search_symbols(name_pattern: str, namespace: str = None) -> list:
    """
    Search for symbols by name pattern with optional namespace filtering.
    
    Args:
        name_pattern: Symbol name or pattern to search for
        namespace: Optional namespace to filter results
        
    Returns:
        List of matching symbols with their names, addresses, types, and namespaces
        
    Example:
        search_symbols("main")
        search_symbols("str", "std")
    """
    params = {"name": name_pattern}
    if namespace:
        params["namespace"] = namespace
    return safe_get("search_symbols", params)

@mcp.tool()
def get_data_references_to(address: str) -> list:
    """
    Get all data references pointing to a specific address.
    
    Args:
        address: Target address (hex string like "0x401000" or decimal)
        
    Returns:
        List of data references with source addresses and context information
        
    Example:
        get_data_references_to("0x401000")
    """
    return safe_get("data_references_to", {"address": address})

@mcp.tool()
def get_code_references_to(address: str) -> list:
    """
    Get all code references pointing to a specific address with instruction context.
    
    Args:
        address: Target address (hex string like "0x401000" or decimal)
        
    Returns:
        List of code references with source addresses, functions, and disassembly context
        
    Example:
        get_code_references_to("0x401000")
    """
    return safe_get("code_references_to", {"address": address})

@mcp.tool()
def get_function_callees(function_address: str) -> list:
    """
    Get all functions called by the specified function.
    
    Args:
        function_address: Address of the function to analyze (hex string like "0x401000" or decimal)
        
    Returns:
        List of called functions with their names, addresses, and call sites
        
    Example:
        get_function_callees("0x401000")
    """
    return safe_get("callees", {"function_address": function_address})

@mcp.tool()
def get_function_callers(function_address: str) -> list:
    """
    Get all functions that call the specified function.
    
    Args:
        function_address: Address of the function to analyze (hex string like "0x401000" or decimal)
        
    Returns:
        List of calling functions with their names and addresses
        
    Example:
        get_function_callers("0x401000")
    """
    return safe_get("callers", {"function_address": function_address})


# Enhanced metadata tools

@mcp.tool()
def get_file_system_info() -> list:
    """
    Get filesystem information about the loaded binary file.
    
    Returns:
        Filesystem properties: filename, size, timestamps, and modification status
    """
    return safe_get("file_system_info")

@mcp.tool()
def get_binary_info() -> list:
    """
    Get comprehensive binary analysis information.
    
    Returns:
        Complete binary analysis: architecture, platform, entry points, segments, sections, and statistics
    """
    return safe_get("binary_info")


if __name__ == "__main__":
    print("Starting MCP bridge service...")
    mcp.run()
