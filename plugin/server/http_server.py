from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from typing import Dict, Any
import binaryninja as bn
import threading
from ..core.binary_operations import BinaryOperations
from ..core.config import Config
from ..api.endpoints import BinaryNinjaEndpoints
from ..utils.string_utils import parse_int_or_default


class MCPRequestHandler(BaseHTTPRequestHandler):
    binary_ops = None  # Will be set by the server

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def endpoints(self):
        # Create endpoints on demand to ensure binary_ops is set
        if not hasattr(self, "_endpoints"):
            if not self.binary_ops:
                raise RuntimeError("binary_ops not initialized")
            self._endpoints = BinaryNinjaEndpoints(self.binary_ops)
        return self._endpoints

    def log_message(self, format, *args):
        bn.log_info(format % args)

    def _set_headers(self, content_type="application/json", status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        self._set_headers(status_code=status_code)
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _parse_query_params(self) -> Dict[str, str]:
        parsed_path = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed_path.query))

    def _parse_post_params(self) -> Dict[str, Any]:
        """Parse POST request parameters from various formats.

        Supports:
        - JSON data (application/json)
        - Form data (application/x-www-form-urlencoded)
        - Raw text (text/plain)

        Returns:
            Dictionary containing the parsed parameters
        """
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}

        content_type = self.headers.get("Content-Type", "")
        post_data = self.rfile.read(content_length).decode("utf-8")

        bn.log_info(f"Received POST data: {post_data}")
        bn.log_info(f"Content-Type: {content_type}")

        # Handle JSON data
        if "application/json" in content_type.lower():
            try:
                return json.loads(post_data)
            except json.JSONDecodeError as e:
                bn.log_error(f"Failed to parse JSON: {e}")
                return {"error": "Invalid JSON format"}

        # Handle form data
        if "application/x-www-form-urlencoded" in content_type.lower():
            try:
                return dict(urllib.parse.parse_qsl(post_data))
            except Exception as e:
                bn.log_error(f"Failed to parse form data: {e}")
                return {"error": "Invalid form data format"}

        # Handle raw text
        if "text/plain" in content_type.lower() or not content_type:
            return {"name": post_data.strip()}

        # Try all formats as fallback
        try:
            return json.loads(post_data)
        except json.JSONDecodeError:
            try:
                parsed = dict(urllib.parse.parse_qsl(post_data))
                if parsed:
                    return parsed
            except (ValueError, TypeError):
                pass

            return {"name": post_data.strip()}

    def _check_binary_loaded(self):
        """Check if a binary is loaded and return appropriate error response if not"""
        if not self.binary_ops or not self.binary_ops.current_view:
            self._send_json_response({"error": "No binary loaded"}, 400)
            return False
        return True

    def _validate_string_param(self, param: str, param_name: str, max_length: int = 1000) -> bool:
        """Validate string parameters for security and length.
        
        Args:
            param: Parameter value to validate
            param_name: Name of the parameter for error messages
            max_length: Maximum allowed length
            
        Returns:
            True if valid, False otherwise (and sends error response)
        """
        if not param:
            self._send_json_response({"error": f"Missing {param_name} parameter"}, 400)
            return False
            
        if len(param) > max_length:
            self._send_json_response({
                "error": f"{param_name} parameter too long (max {max_length} characters)"
            }, 400)
            return False
            
        # Basic security check - prevent obvious injection attempts
        dangerous_chars = ['<', '>', '"', "'", '&', '\0', '\n', '\r']
        if any(char in param for char in dangerous_chars):
            self._send_json_response({
                "error": f"{param_name} parameter contains invalid characters"
            }, 400)
            return False
            
        return True

    def _validate_address_param(self, address: str, param_name: str = "address") -> tuple:
        """Validate and parse address parameter.
        
        Args:
            address: Address string to validate
            param_name: Name of the parameter for error messages
            
        Returns:
            Tuple of (is_valid: bool, parsed_address: int or None)
        """
        if not address:
            self._send_json_response({"error": f"Missing {param_name} parameter"}, 400)
            return False, None
            
        try:
            # Parse hex or decimal address
            if address.startswith("0x") or address.startswith("0X"):
                addr = int(address, 16)
            else:
                addr = int(address)
                
            # Basic range validation - addresses should be reasonable
            if addr < 0 or addr > 0xFFFFFFFFFFFFFFFF:  # 64-bit max
                self._send_json_response({
                    "error": f"Invalid {param_name} range: {address}"
                }, 400)
                return False, None
                
            return True, addr
            
        except ValueError:
            self._send_json_response({
                "error": f"Invalid {param_name} format: {address}"
            }, 400)
            return False, None

    def do_GET(self):
        try:
            # For all endpoints except /status, check if binary is loaded
            if not self.path.startswith("/status") and not self._check_binary_loaded():
                return

            params = self._parse_query_params()
            path = urllib.parse.urlparse(self.path).path
            offset = parse_int_or_default(params.get("offset"), 0)
            limit = parse_int_or_default(params.get("limit"), 100)

            if path == "/status":
                status = {
                    "loaded": self.binary_ops
                    and self.binary_ops.current_view is not None,
                    "filename": self.binary_ops.current_view.file.filename
                    if self.binary_ops and self.binary_ops.current_view
                    else None,
                }
                self._send_json_response(status)

            elif path == "/functions" or path == "/methods":
                functions = self.binary_ops.get_function_names(offset, limit)
                bn.log_info(f"Found {len(functions)} functions")
                self._send_json_response({"functions": functions})

            elif path == "/classes":
                classes = self.binary_ops.get_class_names(offset, limit)
                self._send_json_response({"classes": classes})

            elif path == "/segments":
                segments = self.binary_ops.get_segments(offset, limit)
                self._send_json_response({"segments": segments})

            elif path == "/memory_map":
                try:
                    memory_map = self.binary_ops.get_memory_map()
                    self._send_json_response(memory_map)
                except Exception as e:
                    bn.log_error(f"Error getting memory map: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/sections":
                try:
                    sections = self.binary_ops.get_sections(offset, limit)
                    self._send_json_response({"sections": sections})
                except Exception as e:
                    bn.log_error(f"Error getting sections: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/entropy":
                address_param = params.get("address")
                length_param = params.get("length")
                block_size_param = params.get("block_size", "256")
                
                # Validate required parameters
                is_valid, address = self._validate_address_param(address_param)
                if not is_valid:
                    return
                
                if not length_param:
                    self._send_json_response({"error": "Missing length parameter"}, 400)
                    return
                
                try:
                    length = int(length_param)
                    block_size = int(block_size_param)
                    
                    if length <= 0:
                        self._send_json_response({"error": "Length must be positive"}, 400)
                        return
                    
                    entropy_info = self.binary_ops.get_entropy(address, length, block_size)
                    self._send_json_response(entropy_info)
                except ValueError as e:
                    self._send_json_response({"error": f"Invalid parameter: {e}"}, 400)
                except Exception as e:
                    bn.log_error(f"Error calculating entropy: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/search_symbols":
                name_pattern = params.get("name") or params.get("pattern")
                namespace = params.get("namespace")
                
                if not name_pattern:
                    self._send_json_response({"error": "Missing name or pattern parameter"}, 400)
                    return
                
                if not self._validate_string_param(name_pattern, "name_pattern"):
                    return
                
                try:
                    symbols = self.binary_ops.search_symbols_by_name(name_pattern, namespace)
                    self._send_json_response({"symbols": symbols})
                except Exception as e:
                    bn.log_error(f"Error searching symbols: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/data_references_to":
                address_param = params.get("address")
                
                is_valid, address = self._validate_address_param(address_param)
                if not is_valid:
                    return
                
                try:
                    references = self.binary_ops.get_data_references_to(address)
                    self._send_json_response({"references": references})
                except Exception as e:
                    bn.log_error(f"Error getting data references: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/code_references_to":
                address_param = params.get("address")
                
                is_valid, address = self._validate_address_param(address_param)
                if not is_valid:
                    return
                
                try:
                    references = self.binary_ops.get_code_references_to(address)
                    self._send_json_response({"references": references})
                except Exception as e:
                    bn.log_error(f"Error getting code references: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/callees":
                address_param = params.get("function_address") or params.get("address")
                
                is_valid, address = self._validate_address_param(address_param, "function_address")
                if not is_valid:
                    return
                
                try:
                    callees = self.binary_ops.get_callees(address)
                    self._send_json_response({"callees": callees})
                except ValueError as e:
                    self._send_json_response({"error": str(e)}, 400)
                except Exception as e:
                    bn.log_error(f"Error getting callees: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/callers":
                address_param = params.get("function_address") or params.get("address")
                
                is_valid, address = self._validate_address_param(address_param, "function_address")
                if not is_valid:
                    return
                
                try:
                    callers = self.binary_ops.get_callers(address)
                    self._send_json_response({"callers": callers})
                except ValueError as e:
                    self._send_json_response({"error": str(e)}, 400)
                except Exception as e:
                    bn.log_error(f"Error getting callers: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/imports":
                imports = self.endpoints.get_imports(offset, limit)
                self._send_json_response({"imports": imports})

            elif path == "/exports":
                exports = self.endpoints.get_exports(offset, limit)
                self._send_json_response({"exports": exports})

            elif path == "/namespaces":
                namespaces = self.endpoints.get_namespaces(offset, limit)
                self._send_json_response({"namespaces": namespaces})

            elif path == "/data":
                try:
                    data_items = self.binary_ops.get_defined_data(offset, limit)
                    self._send_json_response({"data": data_items})
                except Exception as e:
                    bn.log_error(f"Error getting data items: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/searchFunctions":
                search_term = params.get("query", "")
                matches = self.endpoints.search_functions(search_term, offset, limit)
                self._send_json_response({"matches": matches})

            elif path == "/decompile":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                self._handle_decompile(function_name)

            elif path == "/assembly":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                try:
                    func_info = self.binary_ops.get_function_info(function_name)
                    if not func_info:
                        bn.log_error(f"Function not found: {function_name}")
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested_name": function_name,
                                "available_functions": self.binary_ops.get_function_names(
                                    0, 10
                                ),
                            },
                            404,
                        )
                        return

                    bn.log_info(f"Found function for assembly: {func_info}")
                    assembly = self.binary_ops.get_assembly_function(function_name)

                    if assembly is None:
                        self._send_json_response(
                            {
                                "error": "Assembly retrieval failed",
                                "function": func_info,
                                "reason": "Function assembly could not be retrieved. Check the Binary Ninja log for detailed error information.",
                            },
                            500,
                        )
                    else:
                        self._send_json_response(
                            {"assembly": assembly, "function": func_info}
                        )
                except Exception as e:
                    bn.log_error(f"Error handling assembly request: {str(e)}")
                    import traceback
                    bn.log_error(traceback.format_exc())
                    self._send_json_response(
                        {
                            "error": "Assembly retrieval failed",
                            "requested_name": function_name,
                            "exception": str(e),
                        },
                        500,
                    )

            elif path == "/functionAt":
                address_str = params.get("address")
                if not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address (in hex format, e.g., 0x41d100) the address of an insruction",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Convert hex string to integer
                    if isinstance(address_str, str) and address_str.startswith("0x"):
                        offset = int(address_str, 16)
                    else:
                        offset = int(address_str)
                        
                    # Add function to binary_operations.py
                    function_names = self.binary_ops.get_functions_containing_address(offset)
                    
                    self._send_json_response(
                        {
                            "address": hex(offset),
                            "functions": function_names
                        }
                    )
                except ValueError:
                    self._send_json_response(
                        {
                            "error": "Invalid address format",
                            "help": "Address must be a valid hexadecimal (0x...) or decimal number",
                            "received": address_str,
                        },
                        400,
                    )
                except Exception as e:
                    bn.log_error(f"Error handling function_at request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "address": address_str,
                        },
                        500,
                    )
                    
            elif path == "/codeReferences":
                function_name = params.get("function")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function parameter",
                            "help": "Required parameter: function (name of the function to find references to)",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Get function information first to confirm it exists
                    func_info = self.binary_ops.get_function_info(function_name)
                    if not func_info:
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested_function": function_name
                            },
                            404,
                        )
                        return
                        
                    # Get all code references to this function
                    code_refs = self.binary_ops.get_function_code_references(function_name)
                    
                    self._send_json_response(
                        {
                            "function": function_name,
                            "code_references": code_refs
                        }
                    )
                except Exception as e:
                    bn.log_error(f"Error handling code_references request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "function": function_name,
                        },
                        500,
                    )
                    
            elif path == "/getUserDefinedType":
                type_name = params.get("name")
                if not type_name:
                    self._send_json_response(
                        {
                            "error": "Missing name parameter",
                            "help": "Required parameter: name (name of the user-defined type to retrieve)",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Get the user-defined type definition
                    type_info = self.binary_ops.get_user_defined_type(type_name)
                    
                    if type_info:
                        self._send_json_response(type_info)
                    else:
                        # If type not found, list available types for reference
                        available_types = {}
                        
                        try:
                            if (hasattr(self.binary_ops._current_view, "user_type_container") and 
                                self.binary_ops._current_view.user_type_container):
                                for type_id in self.binary_ops._current_view.user_type_container.types.keys():
                                    current_type = self.binary_ops._current_view.user_type_container.types[type_id]
                                    available_types[current_type[0]] = str(current_type[1].type) if hasattr(current_type[1], "type") else "unknown"
                        except Exception as e:
                            bn.log_error(f"Error listing available types: {e}")
                            
                        self._send_json_response(
                            {
                                "error": "Type not found",
                                "requested_type": type_name,
                                "available_types": available_types
                            },
                            404,
                        )
                except Exception as e:
                    bn.log_error(f"Error handling getUserDefinedType request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "type_name": type_name,
                        },
                        500,
                    )
                    
            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )
            elif path == "/editFunctionSignature":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                signature = params.get("signature")
                if not signature:
                    self._send_json_response(
                        {"error": "Missing signature parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.edit_function_signature(function_name, signature))
                except Exception as e:
                    bn.log_error(f"Error handling editFunctionSignature request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/retypeVariable":
                function_name =  params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                type_str = params.get("type")
                if not type_str:
                    self._send_json_response(
                        {"error": "Missing type parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.retype_variable(function_name, variable_name, type_str))
                except Exception as e:
                    bn.log_error(f"Error handling retypeVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/renameVariable":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                new_name = params.get("newName")
                if not new_name:
                    self._send_json_response(
                        {"error": "Missing new name parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.rename_variable(function_name, variable_name, new_name))
                except Exception as e:
                    bn.log_error(f"Error handling renameVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )

            elif path == "/defineTypes":
                c_code = params.get("cCode")
                if not c_code:
                    self._send_json_response(
                        {"error": "Missing cCode parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.define_types(c_code))
                except Exception as e:
                    bn.log_error(f"Error handling defineTypes request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            # ========== STRING ANALYSIS ENDPOINTS ==========
            elif path == "/strings":
                min_length = parse_int_or_default(params.get("minLength"), 4)
                encoding = params.get("encoding", "utf-8")
                strings = self.binary_ops.get_strings(min_length, encoding, offset, limit)
                self._send_json_response({"strings": strings})

            elif path == "/searchStrings":
                pattern = params.get("pattern", "")
                if not pattern:
                    self._send_json_response(
                        {"error": "Missing pattern parameter"}, 400
                    )
                    return
                
                regex = params.get("regex", "false").lower() == "true"
                case_sensitive = params.get("caseSensitive", "false").lower() == "true"
                matches = self.binary_ops.search_strings(pattern, regex, case_sensitive, offset, limit)
                self._send_json_response({"matches": matches})

            elif path == "/stringReferences":
                string_address = params.get("address")
                if not string_address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(string_address, 16) if string_address.startswith("0x") else int(string_address)
                    references = self.binary_ops.get_string_references(addr)
                    self._send_json_response({"references": references})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/analyzeStringUsage":
                stats = self.binary_ops.analyze_string_usage()
                self._send_json_response({"statistics": stats})

            # ========== TAG MANAGEMENT ENDPOINTS ==========
            elif path == "/tagTypes":
                tag_types = self.binary_ops.get_tag_types()
                self._send_json_response({"tag_types": tag_types})

            elif path == "/tags":
                tag_type_name = params.get("tagType")
                tags = self.binary_ops.get_tags(tag_type_name, offset, limit)
                self._send_json_response({"tags": tags})

            elif path == "/tagsAtAddress":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    tags = self.binary_ops.get_tags_at_address(addr)
                    self._send_json_response({"tags": tags})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/searchTags":
                query = params.get("query", "")
                if not query:
                    self._send_json_response(
                        {"error": "Missing query parameter"}, 400
                    )
                    return
                
                matching_tags = self.binary_ops.search_tags(query)
                self._send_json_response({"matches": matching_tags})

            # ========== ENHANCED CROSS-REFERENCE ENDPOINTS ==========
            elif path == "/allReferencesTo":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    references = self.binary_ops.get_all_references_to(addr)
                    self._send_json_response({"references": references})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/allReferencesFrom":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    references = self.binary_ops.get_all_references_from(addr)
                    self._send_json_response({"references": references})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/findConstantUsage":
                value = params.get("value")
                if not value:
                    self._send_json_response(
                        {"error": "Missing value parameter"}, 400
                    )
                    return
                
                try:
                    const_value = int(value, 16) if value.startswith("0x") else int(value)
                    size = parse_int_or_default(params.get("size"), None)
                    usage = self.binary_ops.find_constant_usage(const_value, size)
                    self._send_json_response({"usage": usage})
                except ValueError:
                    self._send_json_response({"error": "Invalid value format"}, 400)

            elif path == "/callGraph":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                depth = parse_int_or_default(params.get("depth"), 2)
                direction = params.get("direction", "both")
                call_graph = self.binary_ops.get_call_graph(function_name, depth, direction)
                self._send_json_response({"call_graph": call_graph})

            elif path == "/functionCallers":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                recursive = params.get("recursive", "false").lower() == "true"
                callers = self.binary_ops.find_function_callers(function_name, recursive)
                self._send_json_response({"callers": callers})

            elif path == "/crossReferencesSummary":
                summary = self.binary_ops.analyze_cross_references_summary()
                self._send_json_response({"summary": summary})

            # ========== MEMORY & DATA ANALYSIS ENDPOINTS ==========
            elif path == "/readBytes":
                address = params.get("address")
                length = params.get("length")
                if not address or not length:
                    self._send_json_response(
                        {"error": "Missing required parameters: address and length"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    length_int = int(length)
                    result = self.binary_ops.read_bytes(addr, length_int)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address or length format"}, 400)

            elif path == "/getInstruction":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.get_instruction_at(addr)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            # ========== IL ACCESS ENDPOINTS ==========
            elif path == "/hlilFunction":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_hlil_function(function_name)
                self._send_json_response(result)

            elif path == "/mlilFunction":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_mlil_function(function_name)
                self._send_json_response(result)

            elif path == "/llilFunction":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_llil_function(function_name)
                self._send_json_response(result)

            elif path == "/findILInstructions":
                function_name = params.get("functionName")
                operation_type = params.get("operationType")
                if not function_name or not operation_type:
                    self._send_json_response(
                        {"error": "Missing required parameters: functionName and operationType"}, 400
                    )
                    return
                
                il_level = params.get("ilLevel", "hlil")
                result = self.binary_ops.find_il_instructions(function_name, operation_type, il_level)
                self._send_json_response({"instructions": result})

            # ========== CONTROL FLOW ANALYSIS ENDPOINTS ==========
            elif path == "/basicBlocks":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_basic_blocks(function_name)
                self._send_json_response(result)

            elif path == "/controlFlowGraph":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_control_flow_graph(function_name)
                self._send_json_response(result)

            elif path == "/findLoops":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.find_loops(function_name)
                self._send_json_response(result)

            # ========== SEARCH & PATTERN MATCHING ENDPOINTS ==========
            elif path == "/searchBytes":
                pattern = params.get("pattern")
                if not pattern:
                    self._send_json_response(
                        {"error": "Missing pattern parameter"}, 400
                    )
                    return
                
                mask = params.get("mask")
                result = self.binary_ops.search_bytes(pattern, mask)
                self._send_json_response({"matches": result})

            elif path == "/findImmediateValues":
                value = params.get("value")
                if not value:
                    self._send_json_response(
                        {"error": "Missing value parameter"}, 400
                    )
                    return
                
                try:
                    value_int = int(value, 16) if value.startswith("0x") else int(value)
                    size = parse_int_or_default(params.get("size"), None)
                    result = self.binary_ops.find_immediate_values(value_int, size)
                    self._send_json_response({"matches": result})
                except ValueError:
                    self._send_json_response({"error": "Invalid value format"}, 400)

            elif path == "/searchInstructions":
                mnemonic = params.get("mnemonic")
                if not mnemonic:
                    self._send_json_response(
                        {"error": "Missing mnemonic parameter"}, 400
                    )
                    return
                
                operand_pattern = params.get("operandPattern")
                result = self.binary_ops.search_instructions(mnemonic, operand_pattern)
                self._send_json_response({"matches": result})

            elif path == "/findAPIsByPattern":
                pattern = params.get("pattern")
                if not pattern:
                    self._send_json_response(
                        {"error": "Missing pattern parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.find_apis_by_pattern(pattern)
                self._send_json_response({"matches": result})

            # ========== ANALYSIS CONTROL ENDPOINTS ==========
            elif path == "/runAnalysis":
                analysis_type = params.get("analysisType", "auto")
                result = self.binary_ops.run_analysis(analysis_type)
                self._send_json_response(result)

            elif path == "/analyzeFunction":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.analyze_function(function_name)
                self._send_json_response(result)

            elif path == "/createFunction":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.create_function_at(addr)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/undefineFunction":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.undefine_function(function_name)
                self._send_json_response(result)

            elif path == "/analysisInfo":
                result = self.binary_ops.get_analysis_info()
                self._send_json_response(result)

            elif path == "/fileMetadata":
                result = self.binary_ops.get_file_metadata()
                self._send_json_response(result)

            elif path == "/dominanceTree":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing functionName parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_dominance_tree(function_name)
                self._send_json_response(result)

            elif path == "/getDataType":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {"error": "Missing address parameter"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.get_data_type_at(addr)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            # ========== STRUCT AND TYPE MANAGEMENT ENDPOINTS ==========
            elif path == "/listUserTypes":
                offset = parse_int_or_default(params.get("offset"), 0)
                limit = parse_int_or_default(params.get("limit"), 100)
                
                # Validate ranges
                if offset < 0:
                    offset = 0
                if limit < 1 or limit > 1000:
                    limit = 100
                
                result = self.binary_ops.list_user_types(offset, limit)
                self._send_json_response(result)

            elif path == "/getTypeReferences":
                type_name = params.get("name")
                if not type_name:
                    self._send_json_response(
                        {"error": "Missing name parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.get_type_references(type_name)
                self._send_json_response(result)

            elif path == "/analyzeStructUsage":
                struct_name = params.get("name")
                if not struct_name:
                    self._send_json_response(
                        {"error": "Missing name parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.analyze_struct_usage(struct_name)
                self._send_json_response(result)

            elif path == "/exportTypesHeader":
                type_names = params.get("typeNames")
                if type_names:
                    # Split comma-separated type names
                    type_names = [name.strip() for name in type_names.split(",") if name.strip()]
                
                result = self.binary_ops.export_types_as_c_header(type_names)
                self._send_json_response(result)

            else:
                self._send_json_response({"error": "Not found"}, 404)

        except Exception as e:
            bn.log_error(f"Error handling GET request: {e}")
            self._send_json_response({"error": str(e)}, 500)

    def _handle_decompile(self, function_name: str):
        """Handle function decompilation requests.

        Args:
            function_name: Name or address of the function to decompile

        Sends JSON response with either:
        - Decompiled function code and metadata
        - Error message with available functions list
        """
        try:
            func_info = self.binary_ops.get_function_info(function_name)
            if not func_info:
                bn.log_error(f"Function not found: {function_name}")
                self._send_json_response(
                    {
                        "error": "Function not found",
                        "requested_name": function_name,
                        "available_functions": self.binary_ops.get_function_names(
                            0, 10
                        ),
                    },
                    404,
                )
                return

            bn.log_info(f"Found function for decompilation: {func_info}")
            decompiled = self.binary_ops.decompile_function(function_name)

            if decompiled is None:
                self._send_json_response(
                    {
                        "error": "Decompilation failed",
                        "function": func_info,
                        "reason": "Function could not be decompiled. This might be due to missing debug information or unsupported function type.",
                    },
                    500,
                )
            else:
                self._send_json_response(
                    {"decompiled": decompiled, "function": func_info}
                )
        except Exception as e:
            bn.log_error(f"Error during decompilation: {e}")
            self._send_json_response(
                {
                    "error": f"Decompilation error: {str(e)}",
                    "requested_name": function_name,
                },
                500,
            )

    def do_POST(self):
        try:
            if not self._check_binary_loaded():
                return

            params = self._parse_post_params()
            path = urllib.parse.urlparse(self.path).path

            bn.log_info(f"POST {path} with params: {params}")

            if path == "/load":
                filepath = params.get("filepath")
                if not filepath:
                    self._send_json_response(
                        {"error": "Missing filepath parameter"}, 400
                    )
                    return

                try:
                    self.binary_ops.load_binary(filepath)
                    self._send_json_response(
                        {"success": True, "message": f"Binary loaded: {filepath}"}
                    )
                except Exception as e:
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/rename/function" or path == "/renameFunction":
                old_name = params.get("oldName") or params.get("old_name")
                new_name = params.get("newName") or params.get("new_name")

                bn.log_info(
                    f"Rename request - old_name: {old_name}, new_name: {new_name}, params: {params}"
                )

                if not old_name or not new_name:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required parameters: oldName (or old_name) and newName (or new_name)",
                            "received": params,
                        },
                        400,
                    )
                    return

                # Handle address format (both 0x... and plain number)
                if isinstance(old_name, str):
                    if old_name.startswith("0x"):
                        try:
                            old_name = int(old_name, 16)
                        except ValueError:
                            pass
                    elif old_name.isdigit():
                        old_name = int(old_name)

                bn.log_info(f"Attempting to rename function: {old_name} -> {new_name}")

                # Get function info for validation
                func_info = self.binary_ops.get_function_info(old_name)
                if func_info:
                    bn.log_info(f"Found function: {func_info}")
                    success = self.binary_ops.rename_function(old_name, new_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully renamed function from {old_name} to {new_name}",
                                "function": func_info,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to rename function",
                                "message": "The function was found but could not be renamed. This might be due to permissions or binary restrictions.",
                                "function": func_info,
                            },
                            500,
                        )
                else:
                    available_funcs = self.binary_ops.get_function_names(0, 10)
                    bn.log_error(f"Function not found: {old_name}")
                    self._send_json_response(
                        {
                            "error": "Function not found",
                            "requested": old_name,
                            "help": "Make sure the function exists. You can use either the function name or its address.",
                            "available_functions": available_funcs,
                        },
                        404,
                    )

            elif path == "/rename/data" or path == "/renameData":
                address = params.get("address")
                new_name = params.get("newName") or params.get("new_name")
                if not address or not new_name:
                    self._send_json_response({"error": "Missing parameters"}, 400)
                    return

                try:
                    address_int = (
                        int(address, 16) if isinstance(address, str) else int(address)
                    )
                    success = self.binary_ops.rename_data(address_int, new_name)
                    self._send_json_response({"success": success})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("functionName") or params.get("name")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )

            # ========== TAG MANAGEMENT POST ENDPOINTS ==========
            elif path == "/createTagType":
                name = params.get("name")
                if not name:
                    self._send_json_response(
                        {"error": "Missing name parameter"}, 400
                    )
                    return
                
                icon = params.get("icon", "🏷️")
                visible = params.get("visible", "true").lower() == "true"
                result = self.binary_ops.create_tag_type(name, icon, visible)
                self._send_json_response(result)

            elif path == "/createAddressTag":
                tag_type_name = params.get("tagType")
                address = params.get("address")
                data = params.get("data")
                
                if not tag_type_name or not address:
                    self._send_json_response(
                        {"error": "Missing required parameters: tagType and address"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.create_address_tag(tag_type_name, addr, data)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/createFunctionTag":
                tag_type_name = params.get("tagType")
                function_name = params.get("functionName")
                data = params.get("data")
                
                if not tag_type_name or not function_name:
                    self._send_json_response(
                        {"error": "Missing required parameters: tagType and functionName"}, 400
                    )
                    return
                
                result = self.binary_ops.create_function_tag(tag_type_name, function_name, data)
                self._send_json_response(result)

            elif path == "/createDataTag":
                tag_type_name = params.get("tagType")
                address = params.get("address")
                data = params.get("data")
                
                if not tag_type_name or not address:
                    self._send_json_response(
                        {"error": "Missing required parameters: tagType and address"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.create_data_tag(tag_type_name, addr, data)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/removeTag":
                tag_id = params.get("tagId")
                if not tag_id:
                    self._send_json_response(
                        {"error": "Missing tagId parameter"}, 400
                    )
                    return
                
                result = self.binary_ops.remove_tag(tag_id)
                self._send_json_response(result)

            # ========== MEMORY & DATA ANALYSIS POST ENDPOINTS ==========
            elif path == "/writeBytes":
                address = params.get("address")
                data = params.get("data")
                if not address or not data:
                    self._send_json_response(
                        {"error": "Missing required parameters: address and data"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.write_bytes(addr, data)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/defineDataType":
                address = params.get("address")
                type_string = params.get("typeString")
                if not address or not type_string:
                    self._send_json_response(
                        {"error": "Missing required parameters: address and typeString"}, 400
                    )
                    return
                
                try:
                    addr = int(address, 16) if address.startswith("0x") else int(address)
                    result = self.binary_ops.define_data_type(addr, type_string)
                    self._send_json_response(result)
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            # ========== STRUCT AND TYPE CREATION POST ENDPOINTS ==========
            elif path == "/createStruct":
                name = params.get("name")
                members = params.get("members")
                
                if not name or not members:
                    self._send_json_response(
                        {"error": "Missing required parameters: name and members"}, 400
                    )
                    return
                
                # Parse members if it's a JSON string
                try:
                    import json
                    if isinstance(members, str):
                        members = json.loads(members)
                    
                    packed = params.get("packed", "false").lower() == "true"
                    result = self.binary_ops.create_struct(name, members, packed)
                    self._send_json_response(result)
                except json.JSONDecodeError:
                    self._send_json_response({"error": "Invalid JSON format for members"}, 400)

            elif path == "/modifyStruct":
                name = params.get("name")
                operation = params.get("operation")
                
                if not name or not operation:
                    self._send_json_response(
                        {"error": "Missing required parameters: name and operation"}, 400
                    )
                    return
                
                # Collect operation-specific parameters
                kwargs = {}
                if operation == "add_member":
                    kwargs["member_name"] = params.get("memberName")
                    kwargs["member_type"] = params.get("memberType")
                    if params.get("index"):
                        kwargs["index"] = int(params.get("index"))
                elif operation == "remove_member":
                    kwargs["member_name"] = params.get("memberName")
                
                result = self.binary_ops.modify_struct(name, operation, **kwargs)
                self._send_json_response(result)

            elif path == "/createEnum":
                name = params.get("name")
                members = params.get("members")
                
                if not name or not members:
                    self._send_json_response(
                        {"error": "Missing required parameters: name and members"}, 400
                    )
                    return
                
                try:
                    import json
                    if isinstance(members, str):
                        members = json.loads(members)
                    
                    size = int(params.get("size", "4"))
                    result = self.binary_ops.create_enum(name, members, size)
                    self._send_json_response(result)
                except (json.JSONDecodeError, ValueError) as e:
                    self._send_json_response({"error": f"Invalid parameter format: {e}"}, 400)

            elif path == "/createUnion":
                name = params.get("name")
                members = params.get("members")
                
                if not name or not members:
                    self._send_json_response(
                        {"error": "Missing required parameters: name and members"}, 400
                    )
                    return
                
                try:
                    import json
                    if isinstance(members, str):
                        members = json.loads(members)
                    
                    result = self.binary_ops.create_union(name, members)
                    self._send_json_response(result)
                except json.JSONDecodeError:
                    self._send_json_response({"error": "Invalid JSON format for members"}, 400)

            elif path == "/createTypedef":
                name = params.get("name")
                target_type = params.get("targetType")
                
                if not name or not target_type:
                    self._send_json_response(
                        {"error": "Missing required parameters: name and targetType"}, 400
                    )
                    return
                
                result = self.binary_ops.create_typedef(name, target_type)
                self._send_json_response(result)

            elif path == "/deleteUserType":
                name = params.get("name")
                if not name:
                    self._send_json_response(
                        {"error": "Missing required parameter: name"}, 400
                    )
                    return
                
                result = self.binary_ops.delete_user_type(name)
                self._send_json_response(result)

            else:
                self._send_json_response({"error": "Not found"}, 404)
        except Exception as e:
            bn.log_error(f"Error handling POST request: {e}")
            self._send_json_response({"error": str(e)}, 500)


class MCPServer:
    """HTTP server for Binary Ninja MCP plugin.

    Provides REST API endpoints for:
    - Binary analysis and manipulation
    - Function decompilation
    - Symbol renaming
    - Data inspection
    """

    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.thread = None
        self.binary_ops = BinaryOperations(config.binary_ninja)

    def start(self):
        """Start the HTTP server in a background thread."""
        server_address = (self.config.server.host, self.config.server.port)

        # Create handler with access to binary operations
        handler_class = type(
            "MCPRequestHandlerWithOps",
            (MCPRequestHandler,),
            {"binary_ops": self.binary_ops},
        )

        self.server = HTTPServer(server_address, handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        bn.log_info(
            f"Server started on {self.config.server.host}:{self.config.server.port}"
        )

    def stop(self):
        """Stop the HTTP server and clean up resources."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join()
            bn.log_info("Server stopped")
