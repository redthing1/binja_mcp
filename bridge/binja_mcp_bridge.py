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
    Set a comment at a specific address.
    """
    return safe_post("comment", {"address": address, "comment": comment})


@mcp.tool()
def set_function_comment(function_name: str, comment: str) -> str:
    """
    Set a comment for a function.
    """
    return safe_post("comment/function", {"name": function_name, "comment": comment})


@mcp.tool()
def get_comment(address: str) -> str:
    """
    Get the comment at a specific address.
    """
    return safe_get("comment", {"address": address})[0]


@mcp.tool()
def get_function_comment(function_name: str) -> str:
    """
    Get the comment for a function.
    """
    return safe_get("comment/function", {"name": function_name})[0]


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
    Search for functions whose name contains the given substring.
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
def delete_comment(address: str) -> str:
    """
    Delete the comment at a specific address.
    """
    return safe_post("comment", {"address": address, "_method": "DELETE"})


@mcp.tool()
def delete_function_comment(function_name: str) -> str:
    """
    Delete the comment for a function.
    """
    return safe_post("comment/function", {"name": function_name, "_method": "DELETE"})

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
    List tags in the binary, optionally filtered by tag type.
    
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
    Search tags by their data content.
    
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
def get_file_metadata() -> list:
    """
    Get comprehensive file metadata including file properties, binary information,
    architecture details, platform info, segments, sections, imports/exports, and statistics.
    
    Returns detailed information about:
    - File properties (name, size, timestamps, modification status)
    - Binary view properties (start/end offsets, length, view type)
    - Architecture information (name, address size, endianness, instruction alignment)
    - Platform details (name, calling conventions, system call convention)
    - Entry point information
    - Segment and section details with permissions
    - Import and export symbols
    - Basic statistics (function count, symbol count, etc.)
    """
    return safe_get("fileMetadata")

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

if __name__ == "__main__":
    print("Starting MCP bridge service...")
    mcp.run()
