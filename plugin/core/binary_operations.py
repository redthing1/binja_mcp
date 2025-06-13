import binaryninja as bn
from typing import Optional, List, Dict, Any, Union
from .config import BinaryNinjaConfig
from binaryninja.enums import TypeClass, StructureVariant



class BinaryOperations:
    def __init__(self, config: BinaryNinjaConfig):
        self.config = config
        self._current_view: Optional[bn.BinaryView] = None

    @property
    def current_view(self) -> Optional[bn.BinaryView]:
        return self._current_view

    @current_view.setter
    def current_view(self, bv: Optional[bn.BinaryView]):
        self._current_view = bv
        if bv:
            bn.log_info(f"Set current binary view: {bv.file.filename}")
        else:
            bn.log_info("Cleared current binary view")

    def load_binary(self, filepath: str) -> bn.BinaryView:
        """Load a binary file using Binary Ninja's modern open_view API"""
        try:
            bn.log_info(f"Loading binary: {filepath}")
            # Use the modern bn.open_view method which is the recommended approach
            self._current_view = bn.open_view(filepath)
            
            if self._current_view is None:
                raise Exception(f"Failed to open binary file: {filepath}")
                
            bn.log_info(f"Successfully loaded binary: {self._current_view.file.filename}")
            return self._current_view
            
        except Exception as e:
            bn.log_error(f"Failed to load binary: {e}")
            raise

    def get_function_by_name_or_address(
        self, identifier: Union[str, int]
    ) -> Optional[bn.Function]:
        """Get a function by either its name or address.

        Args:
            identifier: Function name or address (can be int, hex string, or decimal string)

        Returns:
            Function object if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Handle address-based lookup
        try:
            if isinstance(identifier, str) and identifier.startswith("0x"):
                addr = int(identifier, 16)
            elif isinstance(identifier, (int, str)):
                addr = int(identifier) if isinstance(identifier, str) else identifier

            func = self._current_view.get_function_at(addr)
            if func:
                bn.log_info(f"Found function at address {hex(addr)}: {func.name}")
                return func
        except ValueError:
            pass

        # Handle name-based lookup - try exact match first, then case-insensitive
        exact_match = None
        case_insensitive_match = None
        
        for func in self._current_view.functions:
            if func.name == identifier:
                exact_match = func
                break
            elif func.name.lower() == str(identifier).lower():
                # Store first case-insensitive match but keep looking for exact match
                if case_insensitive_match is None:
                    case_insensitive_match = func
        
        # Prefer exact match, but use case-insensitive if available
        if exact_match:
            bn.log_info(f"Found function by exact name: {exact_match.name}")
            return exact_match
        elif case_insensitive_match:
            bn.log_info(f"Found function by case-insensitive name: {case_insensitive_match.name}")
            return case_insensitive_match

        # Try symbol table lookup as last resort
        symbol = self._current_view.get_symbol_by_raw_name(str(identifier))
        if symbol and symbol.address:
            func = self._current_view.get_function_at(symbol.address)
            if func:
                bn.log_info(f"Found function through symbol lookup: {func.name}")
                return func

        bn.log_error(f"Could not find function: {identifier}")
        return None

    def get_function_names(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, str]]:
        """Get list of function names with addresses"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        functions = []
        for func in self._current_view.functions:
            functions.append(
                {
                    "name": func.name,
                    "address": hex(func.start),
                    "raw_name": func.raw_name
                    if hasattr(func, "raw_name")
                    else func.name,
                }
            )

        return functions[offset : offset + limit]

    def get_class_names(self, offset: int = 0, limit: int = 100) -> List[str]:
        """Get list of class names with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        class_names = set()

        try:
            # Try different methods to identify classes
            for type_obj in self._current_view.types.values():
                try:
                    # Skip None or invalid types
                    if not type_obj or not hasattr(type_obj, "name"):
                        continue

                    # Method 1: Check type_class attribute
                    if hasattr(type_obj, "type_class"):
                        class_names.add(type_obj.name)
                        continue

                    # Method 2: Check structure attribute
                    if hasattr(type_obj, "structure") and type_obj.structure:
                        structure = type_obj.structure

                        # Check various attributes that indicate a class
                        if any(
                            hasattr(structure, attr)
                            for attr in [
                                "vtable",
                                "base_structures",
                                "members",
                                "functions",
                            ]
                        ):
                            class_names.add(type_obj.name)
                            continue

                        # Check type attribute if available
                        if hasattr(structure, "type"):
                            type_str = str(structure.type).lower()
                            if "class" in type_str or "struct" in type_str:
                                class_names.add(type_obj.name)
                                continue

                except Exception as e:
                    bn.log_debug(
                        f"Error processing type {getattr(type_obj, 'name', '<unknown>')}: {e}"
                    )
                    continue

            bn.log_info(f"Found {len(class_names)} classes")
            sorted_names = sorted(list(class_names))
            return sorted_names[offset : offset + limit]

        except Exception as e:
            bn.log_error(f"Error getting class names: {e}")
            return []

    def get_segments(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of segments with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        segments = []
        for segment in self._current_view.segments:
            segment_info = {
                "start": hex(segment.start),
                "end": hex(segment.end),
                "name": "",
                "flags": [],
            }

            # Try to get segment name if available
            if hasattr(segment, "name"):
                segment_info["name"] = segment.name
            elif hasattr(segment, "data_name"):
                segment_info["name"] = segment.data_name

            # Try to get segment flags safely
            if hasattr(segment, "flags"):
                try:
                    if isinstance(segment.flags, (list, tuple)):
                        segment_info["flags"] = list(segment.flags)
                    else:
                        segment_info["flags"] = [str(segment.flags)]
                except (AttributeError, TypeError, ValueError):
                    pass

            # Add segment permissions if available
            if hasattr(segment, "readable"):
                segment_info["readable"] = bool(segment.readable)
            if hasattr(segment, "writable"):
                segment_info["writable"] = bool(segment.writable)
            if hasattr(segment, "executable"):
                segment_info["executable"] = bool(segment.executable)

            segments.append(segment_info)

        return segments[offset : offset + limit]

    def rename_function(self, old_name: str, new_name: str) -> bool:
        """Rename a function using multiple fallback methods.

        Args:
            old_name: Current function name or address
            new_name: New name for the function

        Returns:
            True if rename succeeded, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(old_name)
            if not func:
                bn.log_error(f"Function not found: {old_name}")
                return False

            bn.log_info(f"Found function to rename: {func.name} at {hex(func.start)}")

            if not new_name or not isinstance(new_name, str):
                bn.log_error(f"Invalid new name: {new_name}")
                return False

            if not hasattr(func, "name") or not hasattr(func, "__setattr__"):
                bn.log_error(f"Function {func.name} cannot be renamed (read-only)")
                return False

            try:
                # Try direct name assignment first
                old_name = func.name
                func.name = new_name

                if func.name == new_name:
                    bn.log_info(
                        f"Successfully renamed function from {old_name} to {new_name}"
                    )
                    return True

                # Try symbol-based renaming if direct assignment fails
                if hasattr(func, "symbol") and func.symbol:
                    try:
                        new_symbol = bn.Symbol(
                            func.symbol.type,
                            func.start,
                            new_name,
                            namespace=func.symbol.namespace
                            if hasattr(func.symbol, "namespace")
                            else None,
                        )
                        self._current_view.define_user_symbol(new_symbol)
                        bn.log_info("Successfully renamed function using symbol table")
                        return True
                    except Exception as e:
                        bn.log_error(f"Symbol-based rename failed: {e}")

                # Try function update method as last resort
                if hasattr(self._current_view, "update_function"):
                    try:
                        func_copy = func
                        func_copy.name = new_name
                        self._current_view.update_function(func)
                        bn.log_info("Successfully renamed function using update method")
                        return True
                    except Exception as e:
                        bn.log_error(f"Function update rename failed: {e}")

                bn.log_error(
                    f"All rename methods failed - function name unchanged: {func.name}"
                )
                return False

            except Exception as e:
                bn.log_error(f"Error during rename operation: {e}")
                return False

        except Exception as e:
            bn.log_error(f"Error in rename_function: {e}")
            return False

    def get_function_info(
        self, identifier: Union[str, int]
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information about a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        bn.log_info(f"Found function: {func.name} at {hex(func.start)}")

        info = {
            "name": func.name,
            "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
            "address": hex(func.start),
            "symbol": None,
        }

        if func.symbol:
            info["symbol"] = {
                "type": str(func.symbol.type),
                "full_name": func.symbol.full_name
                if hasattr(func.symbol, "full_name")
                else func.symbol.name,
            }

        return info

    def decompile_function(self, identifier: Union[str, int]) -> Optional[str]:
        """Decompile a function to its high-level representation.

        Args:
            identifier: Function name or address

        Returns:
            Decompiled function code as string, or None if decompilation fails
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # analyze func in case it was skipped
        func.analysis_skipped = False
        self._current_view.update_analysis_and_wait()

        try:
            # Try high-level IL first for best readability
            hlil = func.hlil_if_available
            if hlil:
                return str(hlil)
            # Fall back to medium-level IL if available
            mlil = func.mlil_if_available
            if mlil:
                return str(mlil)
            # Use basic function representation as last resort
            else:
                return str(func)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {str(e)}")
            return None

    def rename_data(self, address: int, new_name: str) -> bool:
        """Rename data at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.define_user_symbol(
                    bn.Symbol(bn.SymbolType.DataSymbol, address, new_name)
                )
                return True
        except Exception as e:
            bn.log_error(f"Failed to rename data: {e}")
        return False

    def get_defined_data(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self._current_view.data_vars:
            data_type = None
            value = None

            try:
                # Try to get data type safely
                if hasattr(self._current_view, "get_type_at"):
                    data_type = self._current_view.get_type_at(var)
                elif hasattr(self._current_view, "get_data_var_at"):
                    data_type = self._current_view.get_data_var_at(var)

                # Try to read value if type is available and small enough
                if data_type and hasattr(data_type, "width") and data_type.width <= 8:
                    try:
                        value = str(self._current_view.read_int(var, data_type.width))
                    except (ValueError, RuntimeError):
                        value = "(unreadable)"
                else:
                    value = "(complex data)"
            except (AttributeError, TypeError, ValueError, RuntimeError):
                value = "(unknown)"
                data_type = None

            # Get symbol information
            sym = self._current_view.get_symbol_at(var)
            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name
                    if sym and hasattr(sym, "raw_name")
                    else None,
                    "value": value,
                    "type": str(data_type) if data_type else None,
                }
            )

        return data_items[offset : offset + limit]

    def set_comment(self, address: int, comment: str) -> bool:
        """Set a comment at a specific address.

        Args:
            address: The address to set the comment at
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return False

            self._current_view.set_comment_at(address, comment)
            bn.log_info(f"Set comment at {hex(address)}: {comment}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set comment: {e}")
            return False

    def set_function_comment(self, identifier: Union[str, int], comment: str) -> bool:
        """Set a comment for a function.

        Args:
            identifier: Function name or address
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return False

            self._current_view.set_comment_at(func.start, comment)
            bn.log_info(f"Set comment for function {func.name} at {hex(func.start)}: {comment}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set function comment: {e}")
            return False

    def get_comment(self, address: int) -> Optional[str]:
        """Get the comment at a specific address.

        Args:
            address: The address to get the comment from

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return None

            comment = self._current_view.get_comment_at(address)
            return comment if comment else None
        except Exception as e:
            bn.log_error(f"Failed to get comment: {e}")
            return None

    def get_function_comment(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the comment for a function.

        Args:
            identifier: Function name or address

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None

            comment = self._current_view.get_comment_at(func.start)
            return comment if comment else None
        except Exception as e:
            bn.log_error(f"Failed to get function comment: {e}")
            return None

    def delete_comment(self, address: int) -> bool:
        """Delete a comment at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.set_comment_at(address, None)
                return True
        except Exception as e:
            bn.log_error(f"Failed to delete comment: {e}")
        return False

    def delete_function_comment(self, identifier: Union[str, int]) -> bool:
        """Delete a comment for a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                return False
                
            func.comment = None
            return True
        except Exception as e:
            bn.log_error(f"Failed to delete function comment: {e}")
        return False
        

    def get_assembly_function(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the assembly representation of a function with practical annotations.

        Args:
            identifier: Function name or address

        Returns:
            Assembly code as string, or None if the function cannot be found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None
                
            bn.log_info(f"Found function: {func.name} at {hex(func.start)}")
            
            var_map = {}    # TODO: Implement this functionality (issues with var.storage not returning the correst sp offset)
            assembly_blocks = {}
            
            if not hasattr(func, "basic_blocks") or not func.basic_blocks:
                bn.log_error(f"Function {func.name} has no basic blocks")
                # Try alternate approach with linear disassembly
                start_addr = func.start
                try:
                    func_length = func.total_bytes
                    if func_length <= 0:
                        func_length = 1024  # Use a reasonable default if length not available
                except:
                    func_length = 1024  # Use a reasonable default if error
                    
                try:
                    # Create one big block for the entire function
                    block_lines = []
                    current_addr = start_addr
                    end_addr = start_addr + func_length
                    
                    while current_addr < end_addr:
                        try:
                            # Get instruction length
                            instr_len = self._current_view.get_instruction_length(current_addr)
                            if instr_len <= 0:
                                instr_len = 4  # Default to a reasonable instruction length
                                
                            # Get disassembly for this instruction
                            line = self._get_instruction_with_annotations(current_addr, instr_len, var_map)
                            if line:
                                block_lines.append(line)
                                
                            current_addr += instr_len
                        except Exception as e:
                            bn.log_error(f"Error processing address {hex(current_addr)}: {str(e)}")
                            block_lines.append(f"# Error at {hex(current_addr)}: {str(e)}")
                            current_addr += 1  # Skip to next byte
                    
                    assembly_blocks[start_addr] = [f"# Block at {hex(start_addr)}"] + block_lines + [""]
                    
                except Exception as e:
                    bn.log_error(f"Linear disassembly failed: {str(e)}")
                    return None
            else:
                for i, block in enumerate(func.basic_blocks):
                    try:
                        block_lines = []
                        
                        # Process each address in the block
                        addr = block.start
                        while addr < block.end:
                            try:
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    instr_len = 4  # Default to a reasonable instruction length
                                
                                # Get disassembly for this instruction
                                line = self._get_instruction_with_annotations(addr, instr_len, var_map)
                                if line:
                                    block_lines.append(line)
                                    
                                addr += instr_len
                            except Exception as e:
                                bn.log_error(f"Error processing address {hex(addr)}: {str(e)}")
                                block_lines.append(f"# Error at {hex(addr)}: {str(e)}")
                                addr += 1  # Skip to next byte
                        
                        # Store block with its starting address as key
                        assembly_blocks[block.start] = [f"# Block {i+1} at {hex(block.start)}"] + block_lines + [""]
                        
                    except Exception as e:
                        bn.log_error(f"Error processing block {i+1} at {hex(block.start)}: {str(e)}")
                        assembly_blocks[block.start] = [f"# Error processing block {i+1} at {hex(block.start)}: {str(e)}", ""]
            
            # Sort blocks by address and concatenate them
            sorted_blocks = []
            for addr in sorted(assembly_blocks.keys()):
                sorted_blocks.extend(assembly_blocks[addr])
            
            return "\n".join(sorted_blocks)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function {identifier}: {str(e)}")
            import traceback
            bn.log_error(traceback.format_exc())
            return None

    def _get_instruction_with_annotations(self, addr: int, instr_len: int, var_map: Dict[int, str]) -> Optional[str]:
        """Get a single instruction with practical annotations.
        
        Args:
            addr: Address of the instruction
            instr_len: Length of the instruction
            var_map: Dictionary mapping offsets to variable names
            
        Returns:
            Formatted instruction string with annotations
        """
        if not self._current_view:
            return None
            
        try:
            # Get raw bytes for fallback
            try:
                raw_bytes = self._current_view.read(addr, instr_len)
                hex_bytes = ' '.join(f'{b:02x}' for b in raw_bytes)
            except:
                hex_bytes = "??"
                
            # Get basic disassembly
            disasm_text = ""
            try:
                if hasattr(self._current_view, "get_disassembly"):
                    disasm = self._current_view.get_disassembly(addr)
                    if disasm:
                        disasm_text = disasm
            except:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            if not disasm_text:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            # Check if this is a call instruction and try to get target function name
            if "call" in disasm_text.lower():
                try:
                    # Extract the address from the call instruction
                    import re
                    addr_pattern = r'0x[0-9a-fA-F]+'
                    match = re.search(addr_pattern, disasm_text)
                    if match:
                        call_addr_str = match.group(0)
                        call_addr = int(call_addr_str, 16)
                        
                        # Look up the target function name
                        sym = self._current_view.get_symbol_at(call_addr)
                        if sym and hasattr(sym, "name"):
                            # Replace the address with the function name
                            disasm_text = disasm_text.replace(call_addr_str, sym.name)
                except:
                    pass
                    
            # Try to annotate memory references with variable names
            try:
                # Look for memory references like [reg+offset]
                import re
                mem_ref_pattern = r'\[([^\]]+)\]'
                mem_refs = re.findall(mem_ref_pattern, disasm_text)
                
                # For each memory reference, check if it's a known variable
                for mem_ref in mem_refs:
                    # Parse for ebp relative references
                    offset_pattern = r'(ebp|rbp)(([+-]0x[0-9a-fA-F]+)|([+-]\d+))'
                    offset_match = re.search(offset_pattern, mem_ref)
                    if offset_match:
                        # Extract base register and offset
                        base_reg = offset_match.group(1)
                        offset_str = offset_match.group(2)
                        
                        # Convert offset to integer
                        try:
                            offset = int(offset_str, 16) if offset_str.startswith('0x') or offset_str.startswith('-0x') else int(offset_str)      
                            
                            # Try to find variable name
                            var_name = var_map.get(offset)
                            
                            # If found, add it to the memory reference
                            if var_name:
                                old_ref = f"[{mem_ref}]"
                                new_ref = f"[{mem_ref} {{{var_name}}}]"
                                disasm_text = disasm_text.replace(old_ref, new_ref)
                        except:
                            pass
            except:
                pass
                
            # Get comment if any
            comment = None
            try:
                comment = self._current_view.get_comment_at(addr)
            except:
                pass
                
            # Format the final line
            addr_str = f"{addr:08x}"
            line = f"0x{addr_str}  {disasm_text}"
            
            # Add comment at the end if any
            if comment:
                line += f"  ; {comment}"
                
            return line
        except Exception as e:
            bn.log_error(f"Error annotating instruction at {hex(addr)}: {str(e)}")
            return f"0x{addr:08x}  {hex_bytes} ; [Error: {str(e)}]"
            
    def get_functions_containing_address(self, address: int) -> list:
        """Get functions containing a specific address.
        
        Args:
            address: The instruction address to find containing functions for
            
        Returns:
            List of function names containing the address
        """
        if not self.current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            functions = list(self.current_view.get_functions_containing(address))
            return [func.name for func in functions]
        except Exception as e:
            bn.log_error(f"Error getting functions containing address {hex(address)}: {e}")
            return []
            
    def get_function_code_references(self, function_name: str) -> list:
        """Get all code references to a function.
        
        Args:
            function_name: Name of the function to find references to
            
        Returns:
            List of dictionaries containing function names and addresses that reference the target function
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # First, get the function by name
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                bn.log_error(f"Function not found: {function_name}")
                return []
                
            # Get all code references to the function's start address
            code_refs = []
            for ref in self._current_view.get_code_refs(func.start):
                try:
                    # For each reference, get the containing function and address
                    if ref.function:
                        code_refs.append({
                            "function": ref.function.name,
                            "address": hex(ref.address)
                        })
                except Exception as e:
                    bn.log_error(f"Error processing reference at {hex(ref.address)}: {e}")
                    
            return code_refs
        except Exception as e:
            bn.log_error(f"Error getting code references for function {function_name}: {e}")
            return []
            
    def get_user_defined_type(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Get the definition of a user-defined type (struct, enum, etc.)
        
        Args:
            type_name: Name of the user-defined type to retrieve
            
        Returns:
            Dictionary with type information and definition, or None if not found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if we have a user type container
            if not hasattr(self._current_view, "user_type_container") or not self._current_view.user_type_container:
                bn.log_info(f"No user type container available")
                return None
                
            # Search for the requested type by name
            found_type = None
            found_type_id = None
            
            for type_id in self._current_view.user_type_container.types.keys():
                current_type = self._current_view.user_type_container.types[type_id]
                type_name_from_container = current_type[0]
                
                if type_name_from_container == type_name:
                    found_type = current_type
                    found_type_id = type_id
                    break
                    
            if not found_type or not found_type_id:
                bn.log_info(f"Type not found: {type_name}")
                return None
                
            # Determine the type category (struct, enum, etc.)
            type_category = "unknown"
            type_object = found_type[1]
            bn.log_info(f"Stage1")
            bn.log_info(f"Stage1.5 {type_object.type_class} {StructureVariant.StructStructureType}")
            if type_object.type_class == TypeClass.EnumerationTypeClass:
                type_category = "enum"
            elif type_object.type_class == TypeClass.StructureTypeClass:
                if type_object.type == StructureVariant.StructStructureType:
                    type_category = "struct"
                elif type_object.type == StructureVariant.UnionStructureType:
                    type_category = "union"
                elif type_object.type == StructureVariant.ClassStructureType:
                    type_category = "class"
            elif type_object.type_class == TypeClass.NamedTypeReferenceClass:
                type_category = "typedef"

            # Generate the C++ style definition
            definition_lines = []
            
            try:
                if type_category == "struct" or type_category == "class" or type_category == "union":
                    definition_lines.append(f"{type_category} {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "type"):
                            definition_lines.append(f"    {member.type} {member.name};")
                    definition_lines.append("};")
                elif type_category == "enum":
                    definition_lines.append(f"enum {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "value"):
                            definition_lines.append(f"    {member.name} = {member.value},")
                    definition_lines.append("};")
                elif type_category == "typedef":
                    str_type_object = str(type_object)
                    definition_lines.append(f"typedef {str_type_object};")
            except Exception as e:
                bn.log_error(f"Error getting type lines: {e}")

            # Construct the final definition string
            definition = "\n".join(definition_lines)
            
            return {
                "name": type_name,
                "type": type_category,
                "definition": definition
            }
        except Exception as e:
            bn.log_error(f"Error getting user-defined type {type_name}: {e}")
            return None

    # ========== STRING ANALYSIS METHODS ==========
    
    def get_strings(self, min_length: int = 4, encoding: str = 'utf-8', offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all strings found in the binary with pagination.
        
        Args:
            min_length: Minimum string length to include
            encoding: String encoding to search for ('utf-8', 'utf-16', 'ascii')
            offset: Pagination offset
            limit: Maximum number of strings to return
            
        Returns:
            List of dictionaries containing string information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            strings_found = []
            
            # Get all strings from Binary Ninja
            for string_ref in self._current_view.strings:
                try:
                    if len(string_ref.value) >= min_length:
                        # Get cross-references to this string
                        xrefs = []
                        for ref in self._current_view.get_code_refs(string_ref.start):
                            if ref.function:
                                xrefs.append({
                                    "function": ref.function.name,
                                    "address": hex(ref.address)
                                })
                        
                        strings_found.append({
                            "address": hex(string_ref.start),
                            "length": string_ref.length,
                            "value": string_ref.value,
                            "type": str(string_ref.type) if hasattr(string_ref, 'type') else 'unknown',
                            "xrefs": xrefs,
                            "xref_count": len(xrefs)
                        })
                except Exception as e:
                    bn.log_error(f"Error processing string at {hex(string_ref.start)}: {e}")
                    continue
                    
            # Sort by address and apply pagination
            strings_found.sort(key=lambda x: int(x["address"], 16))
            return strings_found[offset:offset + limit]
            
        except Exception as e:
            bn.log_error(f"Error getting strings: {e}")
            return []

    def search_strings(self, pattern: str, regex: bool = False, case_sensitive: bool = False, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for strings matching a pattern.
        
        Args:
            pattern: Search pattern
            regex: Whether to treat pattern as regex
            case_sensitive: Whether search should be case sensitive
            offset: Pagination offset
            limit: Maximum results to return
            
        Returns:
            List of matching string dictionaries
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            import re
            matches = []
            
            # Compile regex pattern if needed
            if regex:
                flags = 0 if case_sensitive else re.IGNORECASE
                compiled_pattern = re.compile(pattern, flags)
            
            for string_ref in self._current_view.strings:
                try:
                    string_value = string_ref.value
                    match_found = False
                    
                    if regex:
                        match_found = bool(compiled_pattern.search(string_value))
                    else:
                        if case_sensitive:
                            match_found = pattern in string_value
                        else:
                            match_found = pattern.lower() in string_value.lower()
                    
                    if match_found:
                        # Get cross-references
                        xrefs = []
                        for ref in self._current_view.get_code_refs(string_ref.start):
                            if ref.function:
                                xrefs.append({
                                    "function": ref.function.name,
                                    "address": hex(ref.address)
                                })
                        
                        matches.append({
                            "address": hex(string_ref.start),
                            "length": string_ref.length,
                            "value": string_value,
                            "type": str(string_ref.type) if hasattr(string_ref, 'type') else 'unknown',
                            "xrefs": xrefs,
                            "xref_count": len(xrefs)
                        })
                except Exception as e:
                    bn.log_error(f"Error processing string at {hex(string_ref.start)}: {e}")
                    continue
                    
            # Sort by address and apply pagination
            matches.sort(key=lambda x: int(x["address"], 16))
            return matches[offset:offset + limit]
            
        except Exception as e:
            bn.log_error(f"Error searching strings: {e}")
            return []

    def get_string_references(self, string_address: int) -> List[Dict[str, Any]]:
        """Get all references to a specific string.
        
        Args:
            string_address: Address of the string
            
        Returns:
            List of reference information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            references = []
            
            # Get code references
            for ref in self._current_view.get_code_refs(string_address):
                ref_info = {
                    "type": "code",
                    "address": hex(ref.address),
                    "function": ref.function.name if ref.function else None
                }
                
                # Try to get the instruction that references the string
                try:
                    disasm = self._current_view.get_disassembly(ref.address)
                    if disasm:
                        ref_info["instruction"] = disasm
                except:
                    pass
                    
                references.append(ref_info)
            
            # Get data references
            for ref in self._current_view.get_data_refs(string_address):
                references.append({
                    "type": "data",
                    "address": hex(ref),
                    "function": None
                })
                
            return references
            
        except Exception as e:
            bn.log_error(f"Error getting string references: {e}")
            return []

    def analyze_string_usage(self) -> Dict[str, Any]:
        """Analyze string usage patterns in the binary.
        
        Returns:
            Dictionary with string usage statistics
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            stats = {
                "total_strings": 0,
                "referenced_strings": 0,
                "unreferenced_strings": 0,
                "avg_string_length": 0,
                "common_patterns": [],
                "encoding_distribution": {},
                "length_distribution": {}
            }
            
            total_length = 0
            length_buckets = {
                "1-10": 0, "11-50": 0, "51-100": 0, "101-500": 0, "500+": 0
            }
            
            for string_ref in self._current_view.strings:
                stats["total_strings"] += 1
                total_length += len(string_ref.value)
                
                # Count references
                ref_count = sum(1 for _ in self._current_view.get_code_refs(string_ref.start))
                if ref_count > 0:
                    stats["referenced_strings"] += 1
                else:
                    stats["unreferenced_strings"] += 1
                
                # Length distribution
                length = len(string_ref.value)
                if length <= 10:
                    length_buckets["1-10"] += 1
                elif length <= 50:
                    length_buckets["11-50"] += 1
                elif length <= 100:
                    length_buckets["51-100"] += 1
                elif length <= 500:
                    length_buckets["101-500"] += 1
                else:
                    length_buckets["500+"] += 1
                
                # Encoding type
                encoding_type = str(string_ref.type) if hasattr(string_ref, 'type') else 'unknown'
                stats["encoding_distribution"][encoding_type] = stats["encoding_distribution"].get(encoding_type, 0) + 1
            
            if stats["total_strings"] > 0:
                stats["avg_string_length"] = total_length / stats["total_strings"]
            
            stats["length_distribution"] = length_buckets
            
            return stats
            
        except Exception as e:
            bn.log_error(f"Error analyzing string usage: {e}")
            return {}

    # ========== TAG MANAGEMENT METHODS ==========
    
    def _find_tag_type(self, tag_type_name: str) -> bool:
        """Helper method to find tag type by name (case insensitive).
        
        Args:
            tag_type_name: Name of the tag type to find
            
        Returns:
            True if tag type exists, False otherwise
        """
        tag_type_name_lower = tag_type_name.lower()
        for tt in self._current_view.tag_types.values():
            if tt.name.lower() == tag_type_name_lower:
                return True
        return False

    def get_tag_types(self) -> List[Dict[str, Any]]:
        """Get all available tag types in the binary view.
        
        Returns:
            List of dictionaries containing tag type information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            tag_types = []
            for tag_type in self._current_view.tag_types.values():
                tag_types.append({
                    "id": tag_type.id,
                    "name": tag_type.name,
                    "icon": tag_type.icon,
                    "visible": tag_type.visible,
                    "type": str(tag_type.type) if hasattr(tag_type, 'type') else 'unknown'
                })
            
            return sorted(tag_types, key=lambda x: x["name"])
            
        except Exception as e:
            bn.log_error(f"Error getting tag types: {e}")
            return []

    def create_tag_type(self, name: str, icon: str = "🏷️", visible: bool = True) -> Dict[str, Any]:
        """Create a new tag type.
        
        Args:
            name: Name of the tag type
            icon: Icon character for the tag type
            visible: Whether the tag type should be visible
            
        Returns:
            Dictionary with the created tag type information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if tag type already exists
            for existing_type in self._current_view.tag_types.values():
                if existing_type.name == name:
                    return {
                        "success": False,
                        "error": f"Tag type '{name}' already exists",
                        "existing_id": existing_type.id
                    }
            
            # Create new tag type
            tag_type = self._current_view.create_tag_type(name, icon)
            if tag_type:
                tag_type.visible = visible
                return {
                    "success": True,
                    "id": tag_type.id,
                    "name": tag_type.name,
                    "icon": tag_type.icon,
                    "visible": tag_type.visible
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create tag type"
                }
                
        except Exception as e:
            bn.log_error(f"Error creating tag type: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_tags(self, tag_type_name: str = None, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get tags in the binary, optionally filtered by tag type.
        
        Args:
            tag_type_name: Optional tag type name to filter by
            offset: Pagination offset
            limit: Maximum number of tags to return
            
        Returns:
            List of dictionaries containing tag information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            all_tags = []
            tag_type_name_lower = tag_type_name.lower() if tag_type_name else None
            
            # Get all data tags using the correct Binary Ninja API
            # tags property returns list of (address, Tag) pairs
            for address, tag in self._current_view.tags:
                if tag_type_name_lower is None or tag.type.name.lower() == tag_type_name_lower:
                    # Determine what's at this address
                    location_type = "data"
                    function_name = None
                    
                    # Check if this address is in a function
                    func = self._current_view.get_function_at(address)
                    if func:
                        location_type = "function"
                        function_name = func.name
                    
                    all_tags.append({
                        "id": tag.id,
                        "type": tag.type.name,
                        "type_id": tag.type.id,
                        "address": hex(address),
                        "location_type": location_type,
                        "function_name": function_name,
                        "data": tag.data if hasattr(tag, 'data') else None
                    })
            
            # Get function-specific tags
            for func in self._current_view.functions:
                # Function tags return (arch, address, Tag) tuples
                for arch, tag_addr, tag in func.tags:
                    if tag_type_name_lower is None or tag.type.name.lower() == tag_type_name_lower:
                        all_tags.append({
                            "id": tag.id,
                            "type": tag.type.name,
                            "type_id": tag.type.id,
                            "address": hex(tag_addr),
                            "location_type": "function",
                            "function_name": func.name,
                            "data": tag.data if hasattr(tag, 'data') else None
                        })
            
            # Remove duplicates (a tag might appear in both data tags and function tags)
            seen_ids = set()
            unique_tags = []
            for tag in all_tags:
                if tag["id"] not in seen_ids:
                    seen_ids.add(tag["id"])
                    unique_tags.append(tag)
            
            # Sort by address and apply pagination
            unique_tags.sort(key=lambda x: int(x["address"], 16))
            return unique_tags[offset:offset + limit]
            
        except Exception as e:
            bn.log_error(f"Error getting tags: {e}")
            return []

    def create_address_tag(self, tag_type_name: str, address: int, data: str = None) -> Dict[str, Any]:
        """Create a tag at a specific address.
        
        Args:
            tag_type_name: Name of the tag type
            address: Address to tag
            data: Optional data associated with the tag
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if tag type exists (case insensitive)
            if not self._find_tag_type(tag_type_name):
                return {
                    "success": False,
                    "error": f"Tag type '{tag_type_name}' not found"
                }
            
            # Create the tag using add_tag method
            self._current_view.add_tag(address, tag_type_name, data or "", True)
            
            return {
                "success": True,
                "address": hex(address),
                "type": tag_type_name,
                "data": data
            }
                
        except Exception as e:
            bn.log_error(f"Error creating address tag: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_function_tag(self, tag_type_name: str, function_name: str, data: str = None) -> Dict[str, Any]:
        """Create a tag on a function.
        
        Args:
            tag_type_name: Name of the tag type
            function_name: Name of the function to tag
            data: Optional data associated with the tag
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Find the function
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Check if tag type exists (case insensitive)
            if not self._find_tag_type(tag_type_name):
                return {
                    "success": False,
                    "error": f"Tag type '{tag_type_name}' not found"
                }
            
            # Create the tag using function's add_tag method
            func.add_tag(tag_type_name, data or "")
            
            return {
                "success": True,
                "function": function_name,
                "address": hex(func.start),
                "type": tag_type_name,
                "data": data
            }
                
        except Exception as e:
            bn.log_error(f"Error creating function tag: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_data_tag(self, tag_type_name: str, address: int, data: str = None) -> Dict[str, Any]:
        """Create a tag on data at a specific address.
        
        Args:
            tag_type_name: Name of the tag type
            address: Address of the data to tag
            data: Optional data associated with the tag
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if tag type exists (case insensitive)
            if not self._find_tag_type(tag_type_name):
                return {
                    "success": False,
                    "error": f"Tag type '{tag_type_name}' not found"
                }
            
            # Create the data tag using add_tag method (same as address tag)
            self._current_view.add_tag(address, tag_type_name, data or "", True)
            
            return {
                "success": True,
                "address": hex(address),
                "type": tag_type_name,
                "data": data
            }
                
        except Exception as e:
            bn.log_error(f"Error creating data tag: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_tags_at_address(self, address: int) -> List[Dict[str, Any]]:
        """Get all tags at a specific address.
        
        Args:
            address: Address to check for tags
            
        Returns:
            List of tags at the address
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            tags_at_address = []
            
            # Get tags at the address
            for tag in self._current_view.get_tags_at(address):
                tags_at_address.append({
                    "id": tag.id,
                    "type": tag.type.name,
                    "location_type": "address",
                    "data": tag.data if hasattr(tag, 'data') else None
                })
            
            # Check if address is in a function and get function tags
            func = self._current_view.get_function_at(address)
            if func:
                # Function tags return (arch, address, Tag) tuples
                for arch, tag_addr, tag in func.tags:
                    if tag_addr == address:  # Only include tags at this specific address
                        tags_at_address.append({
                            "id": tag.id,
                            "type": tag.type.name,
                            "location_type": "function",
                            "function_name": func.name,
                            "data": tag.data if hasattr(tag, 'data') else None
                        })
            
            return tags_at_address
            
        except Exception as e:
            bn.log_error(f"Error getting tags at address: {e}")
            return []

    def remove_tag(self, tag_id: str) -> Dict[str, Any]:
        """Remove a tag by its ID.
        
        NOTE: Binary Ninja's tag removal API is complex and requires knowing
        the tag's address and type. This is a simplified implementation.
        
        Args:
            tag_id: ID of the tag to remove
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # This is a limitation of the current Binary Ninja API
            # We cannot easily remove tags by ID alone
            return {
                "success": False,
                "error": "Tag removal by ID is not supported in current Binary Ninja API. Use remove_user_data_tag() or similar methods with address and tag object.",
                "note": "Binary Ninja requires address and tag object for removal, not just tag ID"
            }
                
        except Exception as e:
            bn.log_error(f"Error removing tag: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def search_tags(self, query: str) -> List[Dict[str, Any]]:
        """Search tags by their data content.
        
        Args:
            query: Search query to match against tag data
            
        Returns:
            List of matching tags
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            matching_tags = []
            query_lower = query.lower()
            
            # Search all tags for matching data
            for tag_info in self.get_tags():
                if tag_info.get("data") and query_lower in tag_info["data"].lower():
                    matching_tags.append(tag_info)
            
            return matching_tags
            
        except Exception as e:
            bn.log_error(f"Error searching tags: {e}")
            return []

    # ========== ENHANCED CROSS-REFERENCE ANALYSIS METHODS ==========
    
    def get_all_references_to(self, address: int) -> Dict[str, List[Dict[str, Any]]]:
        """Get all references (code and data) to a specific address.
        
        Args:
            address: Target address to find references to
            
        Returns:
            Dictionary with 'code_refs' and 'data_refs' lists
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            result = {
                "code_refs": [],
                "data_refs": []
            }
            
            # Get code references
            for ref in self._current_view.get_code_refs(address):
                ref_info = {
                    "address": hex(ref.address),
                    "function": ref.function.name if ref.function else None,
                    "function_address": hex(ref.function.start) if ref.function else None
                }
                
                # Try to get the instruction
                try:
                    disasm = self._current_view.get_disassembly(ref.address)
                    if disasm:
                        ref_info["instruction"] = disasm
                except:
                    pass
                    
                result["code_refs"].append(ref_info)
            
            # Get data references
            for ref_addr in self._current_view.get_data_refs(address):
                ref_info = {
                    "address": hex(ref_addr),
                    "type": "data"
                }
                
                # Check if this data reference is in a function
                func = self._current_view.get_function_at(ref_addr)
                if func:
                    ref_info["function"] = func.name
                    ref_info["function_address"] = hex(func.start)
                
                result["data_refs"].append(ref_info)
            
            return result
            
        except Exception as e:
            bn.log_error(f"Error getting references to {hex(address)}: {e}")
            return {"code_refs": [], "data_refs": []}

    def get_all_references_from(self, address: int) -> Dict[str, List[Dict[str, Any]]]:
        """Get all references from a specific address.
        
        Args:
            address: Source address to find references from
            
        Returns:
            Dictionary with references made from this address
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            result = {
                "code_refs": [],
                "data_refs": []
            }
            
            # Check if this address is in a function
            func = self._current_view.get_function_at(address)
            if func:
                # Get all code references made from this function
                for ref_addr in self._current_view.get_code_refs_from(address, func):
                    target_func = self._current_view.get_function_at(ref_addr)
                    result["code_refs"].append({
                        "target_address": hex(ref_addr),
                        "target_function": target_func.name if target_func else None,
                        "source_address": hex(address),
                        "source_function": func.name
                    })
                
                # Get all data references made from this function
                for ref_addr in self._current_view.get_data_refs_from(address):
                    result["data_refs"].append({
                        "target_address": hex(ref_addr),
                        "source_address": hex(address),
                        "source_function": func.name
                    })
            
            return result
            
        except Exception as e:
            bn.log_error(f"Error getting references from {hex(address)}: {e}")
            return {"code_refs": [], "data_refs": []}

    def find_constant_usage(self, value: int, size: int = None) -> List[Dict[str, Any]]:
        """Find all uses of a specific constant value.
        
        Args:
            value: Constant value to search for
            size: Optional size constraint (1, 2, 4, 8 bytes)
            
        Returns:
            List of locations where the constant is used
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            constant_uses = []
            
            # Search through all functions for the constant
            for func in self._current_view.functions:
                try:
                    # Check HLIL for constant usage
                    hlil = func.hlil_if_available
                    if hlil:
                        for block in hlil:
                            for instr in block:
                                # Look for constant operands
                                if hasattr(instr, 'operands'):
                                    for operand in instr.operands:
                                        if hasattr(operand, 'constant') and operand.constant == value:
                                            constant_uses.append({
                                                "address": hex(instr.address),
                                                "function": func.name,
                                                "instruction": str(instr),
                                                "value": value,
                                                "context": "hlil"
                                            })
                    
                    # Also check disassembly for immediate values
                    for block in func.basic_blocks:
                        addr = block.start
                        while addr < block.end:
                            try:
                                disasm = self._current_view.get_disassembly(addr)
                                if disasm and (hex(value) in disasm or str(value) in disasm):
                                    constant_uses.append({
                                        "address": hex(addr),
                                        "function": func.name,
                                        "instruction": disasm,
                                        "value": value,
                                        "context": "disassembly"
                                    })
                                
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    instr_len = 1
                                addr += instr_len
                            except:
                                addr += 1
                                
                except Exception as e:
                    bn.log_error(f"Error searching function {func.name}: {e}")
                    continue
            
            return constant_uses
            
        except Exception as e:
            bn.log_error(f"Error finding constant usage: {e}")
            return []

    def get_call_graph(self, function_name: str, depth: int = 2, direction: str = "both") -> Dict[str, Any]:
        """Get call graph relationships for a function.
        
        Args:
            function_name: Name of the function to analyze
            depth: Maximum depth to traverse
            direction: 'callers', 'callees', or 'both'
            
        Returns:
            Dictionary with call graph information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {"error": f"Function '{function_name}' not found"}
            
            call_graph = {
                "root_function": {
                    "name": func.name,
                    "address": hex(func.start)
                },
                "callers": {},
                "callees": {}
            }
            
            def get_callers(target_func, current_depth):
                if current_depth > depth:
                    return {}
                
                callers = {}
                for ref in self._current_view.get_code_refs(target_func.start):
                    if ref.function and ref.function != target_func:
                        caller_info = {
                            "name": ref.function.name,
                            "address": hex(ref.function.start),
                            "call_address": hex(ref.address),
                            "depth": current_depth
                        }
                        
                        # Recursively get callers if we haven't reached depth limit
                        if current_depth < depth:
                            caller_info["callers"] = get_callers(ref.function, current_depth + 1)
                        
                        callers[ref.function.name] = caller_info
                
                return callers
            
            def get_callees(source_func, current_depth):
                if current_depth > depth:
                    return {}
                
                callees = {}
                try:
                    hlil = source_func.hlil_if_available
                    if hlil:
                        for block in hlil:
                            for instr in block:
                                if hasattr(instr, 'dest') and hasattr(instr.dest, 'constant'):
                                    target_addr = instr.dest.constant
                                    target_func = self._current_view.get_function_at(target_addr)
                                    if target_func and target_func != source_func:
                                        callee_info = {
                                            "name": target_func.name,
                                            "address": hex(target_func.start),
                                            "call_address": hex(instr.address),
                                            "depth": current_depth
                                        }
                                        
                                        # Recursively get callees if we haven't reached depth limit
                                        if current_depth < depth:
                                            callee_info["callees"] = get_callees(target_func, current_depth + 1)
                                        
                                        callees[target_func.name] = callee_info
                except:
                    pass
                
                return callees
            
            if direction in ["callers", "both"]:
                call_graph["callers"] = get_callers(func, 1)
            
            if direction in ["callees", "both"]:
                call_graph["callees"] = get_callees(func, 1)
            
            return call_graph
            
        except Exception as e:
            bn.log_error(f"Error getting call graph: {e}")
            return {"error": str(e)}

    def find_function_callers(self, function_name: str, recursive: bool = False) -> List[Dict[str, Any]]:
        """Enhanced function caller analysis.
        
        Args:
            function_name: Name of the function to find callers for
            recursive: Whether to find callers recursively
            
        Returns:
            List of caller information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return []
            
            callers = []
            visited = set()
            
            def find_callers_recursive(target_func, depth=0):
                if target_func.name in visited:
                    return
                
                visited.add(target_func.name)
                
                for ref in self._current_view.get_code_refs(target_func.start):
                    if ref.function and ref.function != target_func:
                        caller_info = {
                            "function": ref.function.name,
                            "function_address": hex(ref.function.start),
                            "call_address": hex(ref.address),
                            "depth": depth
                        }
                        
                        # Try to get the call instruction
                        try:
                            disasm = self._current_view.get_disassembly(ref.address)
                            if disasm:
                                caller_info["instruction"] = disasm
                        except:
                            pass
                        
                        callers.append(caller_info)
                        
                        # Recursive search if enabled
                        if recursive and depth < 5:  # Limit depth to prevent infinite recursion
                            find_callers_recursive(ref.function, depth + 1)
            
            find_callers_recursive(func)
            
            # Sort by depth and function name
            callers.sort(key=lambda x: (x["depth"], x["function"]))
            
            return callers
            
        except Exception as e:
            bn.log_error(f"Error finding function callers: {e}")
            return []

    def analyze_cross_references_summary(self) -> Dict[str, Any]:
        """Get a summary of cross-reference patterns in the binary.
        
        Returns:
            Dictionary with cross-reference statistics
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            summary = {
                "total_functions": len(self._current_view.functions),
                "functions_with_callers": 0,
                "functions_without_callers": 0,
                "max_callers": 0,
                "most_called_function": None,
                "orphaned_functions": [],
                "highly_called_functions": []
            }
            
            function_call_counts = {}
            
            for func in self._current_view.functions:
                caller_count = sum(1 for _ in self._current_view.get_code_refs(func.start))
                function_call_counts[func.name] = caller_count
                
                if caller_count > 0:
                    summary["functions_with_callers"] += 1
                    if caller_count > summary["max_callers"]:
                        summary["max_callers"] = caller_count
                        summary["most_called_function"] = func.name
                else:
                    summary["functions_without_callers"] += 1
                    summary["orphaned_functions"].append({
                        "name": func.name,
                        "address": hex(func.start)
                    })
            
            # Find highly called functions (top 10% by call count)
            sorted_functions = sorted(function_call_counts.items(), key=lambda x: x[1], reverse=True)
            top_10_percent = max(1, len(sorted_functions) // 10)
            
            for func_name, call_count in sorted_functions[:top_10_percent]:
                if call_count > 0:
                    func = self.get_function_by_name_or_address(func_name)
                    if func:
                        summary["highly_called_functions"].append({
                            "name": func_name,
                            "address": hex(func.start),
                            "caller_count": call_count
                        })
            
            return summary
            
        except Exception as e:
            bn.log_error(f"Error analyzing cross-references: {e}")
            return {}

    # ========== MEMORY & DATA ANALYSIS METHODS ==========
    
    def read_bytes(self, address: int, length: int) -> Dict[str, Any]:
        """Read raw bytes from the binary at a specific address.
        
        Args:
            address: Address to read from
            length: Number of bytes to read
            
        Returns:
            Dictionary with bytes data and metadata
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            if not self._current_view.is_offset_readable(address):
                return {
                    "success": False,
                    "error": f"Address not readable: {hex(address)}"
                }
            
            # Check if we can read the requested length
            max_readable = min(length, self._current_view.end - address)
            if max_readable <= 0:
                return {
                    "success": False,
                    "error": f"Cannot read {length} bytes from {hex(address)}"
                }
            
            raw_bytes = self._current_view.read(address, max_readable)
            if raw_bytes is None:
                return {
                    "success": False,
                    "error": "Failed to read data"
                }
            
            # Convert to hex string for JSON serialization
            hex_data = raw_bytes.hex()
            
            return {
                "success": True,
                "address": hex(address),
                "length": max_readable,
                "requested_length": length,
                "data": hex_data,
                "ascii": "".join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
            }
            
        except Exception as e:
            bn.log_error(f"Error reading bytes: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def write_bytes(self, address: int, data: str) -> Dict[str, Any]:
        """Write bytes to the binary at a specific address.
        
        Args:
            address: Address to write to
            data: Hex string of data to write (e.g., "41424344")
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            if not self._current_view.is_offset_writable(address):
                return {
                    "success": False,
                    "error": f"Address not writable: {hex(address)}"
                }
            
            # Convert hex string to bytes
            try:
                if data.startswith("0x"):
                    data = data[2:]
                bytes_data = bytes.fromhex(data)
            except ValueError:
                return {
                    "success": False,
                    "error": "Invalid hex data format"
                }
            
            # Write the data
            bytes_written = self._current_view.write(address, bytes_data)
            
            if bytes_written == len(bytes_data):
                return {
                    "success": True,
                    "address": hex(address),
                    "bytes_written": bytes_written,
                    "data": data
                }
            else:
                return {
                    "success": False,
                    "error": f"Only wrote {bytes_written} of {len(bytes_data)} bytes"
                }
                
        except Exception as e:
            bn.log_error(f"Error writing bytes: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_instruction_at(self, address: int) -> Dict[str, Any]:
        """Get detailed instruction information at a specific address.
        
        Args:
            address: Address of the instruction
            
        Returns:
            Dictionary with instruction details
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            # Get instruction length and disassembly
            instr_len = self._current_view.get_instruction_length(address)
            if instr_len <= 0:
                return {
                    "success": False,
                    "error": "No instruction at address"
                }
            
            # Get disassembly
            disasm = self._current_view.get_disassembly(address)
            
            # Get raw bytes
            raw_bytes = self._current_view.read(address, instr_len)
            hex_bytes = raw_bytes.hex() if raw_bytes else ""
            
            # Get function context
            func = self._current_view.get_function_at(address)
            function_name = func.name if func else None
            
            # Get any comments
            comment = self._current_view.get_comment_at(address)
            
            result = {
                "success": True,
                "address": hex(address),
                "length": instr_len,
                "disassembly": disasm,
                "bytes": hex_bytes,
                "function": function_name,
                "comment": comment
            }
            
            # Try to get instruction operands if available
            try:
                # Get instruction info using Binary Ninja's instruction API
                instr_info = []
                arch = self._current_view.arch
                if arch:
                    instr_tokens = arch.get_instruction_info(self._current_view.read(address, instr_len), address)
                    if instr_tokens:
                        result["instruction_info"] = {
                            "length": instr_tokens.length,
                            "branch_delay": instr_tokens.branch_delay if hasattr(instr_tokens, 'branch_delay') else False
                        }
            except:
                pass
            
            return result
            
        except Exception as e:
            bn.log_error(f"Error getting instruction: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_data_type_at(self, address: int) -> Dict[str, Any]:
        """Get data type information at a specific address.
        
        Args:
            address: Address to check
            
        Returns:
            Dictionary with type information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            # Get type at address
            data_type = self._current_view.get_data_var_at(address)
            
            result = {
                "success": True,
                "address": hex(address),
                "has_type": data_type is not None
            }
            
            if data_type:
                result.update({
                    "type": str(data_type.type) if data_type.type else "unknown",
                    "confidence": data_type.confidence,
                    "auto_discovered": data_type.auto_discovered
                })
                
                # Try to get the value if it's a simple type
                try:
                    if data_type.type and hasattr(data_type.type, 'width') and data_type.type.width <= 8:
                        raw_value = self._current_view.read_int(address, data_type.type.width)
                        result["value"] = raw_value
                        result["hex_value"] = hex(raw_value)
                except:
                    pass
            
            # Check if there's a symbol at this address
            symbol = self._current_view.get_symbol_at(address)
            if symbol:
                result["symbol"] = {
                    "name": symbol.name,
                    "type": str(symbol.type),
                    "full_name": symbol.full_name if hasattr(symbol, 'full_name') else symbol.name
                }
            
            return result
            
        except Exception as e:
            bn.log_error(f"Error getting data type: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def define_data_type(self, address: int, type_string: str) -> Dict[str, Any]:
        """Define data at an address as a specific type.
        
        Args:
            address: Address to define
            type_string: Type string (e.g., "int32_t", "char[16]", "struct MyStruct")
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            # Parse the type string
            parsed_type, _ = self._current_view.parse_type_string(type_string)
            if not parsed_type:
                return {
                    "success": False,
                    "error": f"Failed to parse type: {type_string}"
                }
            
            # Define the data variable
            self._current_view.define_data_var(address, parsed_type)
            
            # Verify it was set correctly
            data_var = self._current_view.get_data_var_at(address)
            
            if data_var:
                return {
                    "success": True,
                    "address": hex(address),
                    "type": str(data_var.type),
                    "size": data_var.type.width if hasattr(data_var.type, 'width') else 0
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to define data type"
                }
                
        except Exception as e:
            bn.log_error(f"Error defining data type: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    # ========== IL (INTERMEDIATE LANGUAGE) ACCESS METHODS ==========
    
    def get_hlil_function(self, function_name: str) -> Dict[str, Any]:
        """Get High Level IL representation of a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with HLIL representation and metadata
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Use hlil_if_available to avoid exceptions when IL is not ready
            hlil = func.hlil_if_available
            if hlil is None:
                return {
                    "success": False,
                    "error": "HLIL not available for this function (may need analysis completion)"
                }
            instructions = []
            
            # Process each basic block
            for block in hlil:
                block_instructions = []
                for instr in block:
                    instr_data = {
                        "address": hex(instr.address),
                        "index": instr.instr_index,
                        "operation": str(instr.operation),
                        "text": str(instr),
                        "size": instr.size if hasattr(instr, 'size') else 0
                    }
                    
                    # Add operand information if available
                    if hasattr(instr, 'operands'):
                        instr_data["operands"] = [str(op) for op in instr.operands]
                    
                    block_instructions.append(instr_data)
                
                instructions.append({
                    "block_start": hex(block.start),
                    "block_end": hex(block.end),
                    "instructions": block_instructions
                })
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "hlil_instructions": instructions,
                "instruction_count": len(hlil),
                "basic_block_count": len(hlil.basic_blocks) if hasattr(hlil, 'basic_blocks') else 0
            }
            
        except Exception as e:
            bn.log_error(f"Error getting HLIL: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_mlil_function(self, function_name: str) -> Dict[str, Any]:
        """Get Medium Level IL representation of a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with MLIL representation and metadata
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Use mlil_if_available to avoid exceptions when IL is not ready
            mlil = func.mlil_if_available
            if mlil is None:
                return {
                    "success": False,
                    "error": "MLIL not available for this function (may need analysis completion)"
                }
            instructions = []
            
            # Process each basic block
            for block in mlil:
                block_instructions = []
                for instr in block:
                    instr_data = {
                        "address": hex(instr.address),
                        "index": instr.instr_index,
                        "operation": str(instr.operation),
                        "text": str(instr),
                        "size": instr.size if hasattr(instr, 'size') else 0
                    }
                    
                    # Add operand information if available
                    if hasattr(instr, 'operands'):
                        instr_data["operands"] = [str(op) for op in instr.operands]
                    
                    block_instructions.append(instr_data)
                
                instructions.append({
                    "block_start": hex(block.start),
                    "block_end": hex(block.end),
                    "instructions": block_instructions
                })
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "mlil_instructions": instructions,
                "instruction_count": len(mlil),
                "basic_block_count": len(mlil.basic_blocks) if hasattr(mlil, 'basic_blocks') else 0
            }
            
        except Exception as e:
            bn.log_error(f"Error getting MLIL: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_llil_function(self, function_name: str) -> Dict[str, Any]:
        """Get Low Level IL representation of a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with LLIL representation and metadata
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Use llil_if_available to avoid exceptions when IL is not ready
            llil = func.llil_if_available
            if llil is None:
                return {
                    "success": False,
                    "error": "LLIL not available for this function (may need analysis completion)"
                }
            instructions = []
            
            # Process each basic block
            for block in llil:
                block_instructions = []
                for instr in block:
                    instr_data = {
                        "address": hex(instr.address),
                        "index": instr.instr_index,
                        "operation": str(instr.operation),
                        "text": str(instr),
                        "size": instr.size if hasattr(instr, 'size') else 0
                    }
                    
                    # Add operand information if available
                    if hasattr(instr, 'operands'):
                        instr_data["operands"] = [str(op) for op in instr.operands]
                    
                    block_instructions.append(instr_data)
                
                instructions.append({
                    "block_start": hex(block.start),
                    "block_end": hex(block.end),
                    "instructions": block_instructions
                })
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "llil_instructions": instructions,
                "instruction_count": len(llil),
                "basic_block_count": len(llil.basic_blocks) if hasattr(llil, 'basic_blocks') else 0
            }
            
        except Exception as e:
            bn.log_error(f"Error getting LLIL: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def find_il_instructions(self, function_name: str, operation_type: str, il_level: str = "hlil") -> List[Dict[str, Any]]:
        """Find specific IL operations in a function.
        
        Args:
            function_name: Name or address of the function
            operation_type: Type of operation to find (e.g., "HLIL_CALL", "HLIL_ASSIGN")
            il_level: IL level to search ("hlil", "mlil", "llil")
            
        Returns:
            List of matching IL instructions
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return []
            
            # Get the appropriate IL level using *_if_available
            if il_level.lower() == "hlil":
                il_func = func.hlil_if_available
            elif il_level.lower() == "mlil":
                il_func = func.mlil_if_available
            elif il_level.lower() == "llil":
                il_func = func.llil_if_available
            else:
                return []
            
            if il_func is None:
                return []
            
            matching_instructions = []
            
            for block in il_func:
                for instr in block:
                    if str(instr.operation) == operation_type:
                        instr_data = {
                            "address": hex(instr.address),
                            "index": instr.instr_index,
                            "operation": str(instr.operation),
                            "text": str(instr),
                            "il_level": il_level.upper()
                        }
                        
                        # Add operand information
                        if hasattr(instr, 'operands'):
                            instr_data["operands"] = [str(op) for op in instr.operands]
                        
                        # For calls, try to get the target
                        if "CALL" in operation_type and hasattr(instr, 'dest'):
                            try:
                                if hasattr(instr.dest, 'constant'):
                                    target_addr = instr.dest.constant
                                    target_func = self._current_view.get_function_at(target_addr)
                                    if target_func:
                                        instr_data["target_function"] = target_func.name
                                        instr_data["target_address"] = hex(target_addr)
                            except:
                                pass
                        
                        matching_instructions.append(instr_data)
            
            return matching_instructions
            
        except Exception as e:
            bn.log_error(f"Error finding IL instructions: {e}")
            return []

    # ========== BASIC BLOCK & CONTROL FLOW ANALYSIS METHODS ==========
    
    def get_basic_blocks(self, function_name: str) -> Dict[str, Any]:
        """Get basic blocks information for a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with basic blocks information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            blocks = []
            for i, block in enumerate(func.basic_blocks):
                block_info = {
                    "index": i,
                    "start": hex(block.start),
                    "end": hex(block.end),
                    "length": block.end - block.start,
                    "instruction_count": len(block)
                }
                
                # Get outgoing edges
                outgoing_edges = []
                for edge in block.outgoing_edges:
                    edge_info = {
                        "target": hex(edge.target.start),
                        "type": str(edge.type) if hasattr(edge, 'type') else "unknown"
                    }
                    outgoing_edges.append(edge_info)
                
                block_info["outgoing_edges"] = outgoing_edges
                
                # Get incoming edges
                incoming_edges = []
                for edge in block.incoming_edges:
                    edge_info = {
                        "source": hex(edge.source.start),
                        "type": str(edge.type) if hasattr(edge, 'type') else "unknown"
                    }
                    incoming_edges.append(edge_info)
                
                block_info["incoming_edges"] = incoming_edges
                
                # Check if this is a terminal block
                block_info["is_terminal"] = len(outgoing_edges) == 0
                
                blocks.append(block_info)
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "basic_blocks": blocks,
                "block_count": len(blocks)
            }
            
        except Exception as e:
            bn.log_error(f"Error getting basic blocks: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_control_flow_graph(self, function_name: str) -> Dict[str, Any]:
        """Get control flow graph information for a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with CFG information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Build CFG representation
            nodes = []
            edges = []
            
            # Create nodes (basic blocks)
            block_map = {}
            for i, block in enumerate(func.basic_blocks):
                node_id = f"bb_{i}"
                block_map[block.start] = node_id
                
                node = {
                    "id": node_id,
                    "start": hex(block.start),
                    "end": hex(block.end),
                    "length": block.end - block.start,
                    "instruction_count": len(block)
                }
                nodes.append(node)
            
            # Create edges
            for i, block in enumerate(func.basic_blocks):
                source_id = f"bb_{i}"
                for edge in block.outgoing_edges:
                    target_start = edge.target.start
                    if target_start in block_map:
                        target_id = block_map[target_start]
                        edge_info = {
                            "source": source_id,
                            "target": target_id,
                            "type": str(edge.type) if hasattr(edge, 'type') else "unknown"
                        }
                        edges.append(edge_info)
            
            # Identify special blocks
            entry_blocks = [node for node in nodes if node["id"] == "bb_0"]
            terminal_blocks = []
            
            for node in nodes:
                # Check if this node has no outgoing edges
                has_outgoing = any(edge["source"] == node["id"] for edge in edges)
                if not has_outgoing:
                    terminal_blocks.append(node)
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "nodes": nodes,
                "edges": edges,
                "entry_blocks": entry_blocks,
                "terminal_blocks": terminal_blocks,
                "complexity": len(edges) - len(nodes) + 2  # Cyclomatic complexity
            }
            
        except Exception as e:
            bn.log_error(f"Error getting CFG: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def find_loops(self, function_name: str) -> Dict[str, Any]:
        """Identify loop structures in a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with loop information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            loops = []
            
            # Simple loop detection: look for back edges
            # A back edge is an edge from a block to a block that dominates it
            for block in func.basic_blocks:
                for edge in block.outgoing_edges:
                    target = edge.target
                    
                    # Check if target dominates source (simple heuristic: target comes before source)
                    if target.start <= block.start:
                        # Potential loop found
                        loop_info = {
                            "header": hex(target.start),
                            "latch": hex(block.start),
                            "type": "back_edge_detected"
                        }
                        
                        # Try to find loop body by collecting blocks between header and latch
                        body_blocks = []
                        for body_block in func.basic_blocks:
                            if target.start <= body_block.start <= block.end:
                                body_blocks.append(hex(body_block.start))
                        
                        loop_info["body_blocks"] = body_blocks
                        loop_info["estimated_size"] = len(body_blocks)
                        
                        loops.append(loop_info)
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "loops": loops,
                "loop_count": len(loops)
            }
            
        except Exception as e:
            bn.log_error(f"Error finding loops: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_dominance_tree(self, function_name: str) -> Dict[str, Any]:
        """Get dominance tree information for a function.
        
        Args:
            function_name: Name or address of the function
            
        Returns:
            Dictionary with dominance information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            dominance_info = []
            
            # Simple dominance analysis
            # A block A dominates block B if all paths from entry to B go through A
            blocks = list(func.basic_blocks)
            
            for i, block in enumerate(blocks):
                dominated_blocks = []
                
                # Check which blocks this block dominates
                for j, other_block in enumerate(blocks):
                    if i != j:
                        # Simple heuristic: if block comes before other_block in sequence
                        # and there's a path between them, it might dominate
                        if block.start < other_block.start:
                            # Check if there's a path
                            has_path = False
                            for edge in block.outgoing_edges:
                                if edge.target.start <= other_block.start:
                                    has_path = True
                                    break
                            
                            if has_path:
                                dominated_blocks.append(hex(other_block.start))
                
                dom_info = {
                    "block": hex(block.start),
                    "dominated_blocks": dominated_blocks,
                    "dominance_count": len(dominated_blocks)
                }
                dominance_info.append(dom_info)
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "dominance_info": dominance_info,
                "note": "Simplified dominance analysis - not a full dominator tree"
            }
            
        except Exception as e:
            bn.log_error(f"Error getting dominance tree: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    # ========== SEARCH & PATTERN MATCHING METHODS ==========
    
    def search_bytes(self, pattern: str, mask: str = None) -> List[Dict[str, Any]]:
        """Search for byte patterns in the binary.
        
        Args:
            pattern: Hex string pattern to search for (e.g., "41424344")
            mask: Optional mask string (e.g., "FFFF00FF") to ignore certain bytes
            
        Returns:
            List of matches with addresses and context
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Convert pattern to bytes
            if pattern.startswith("0x"):
                pattern = pattern[2:]
            
            try:
                pattern_bytes = bytes.fromhex(pattern)
            except ValueError:
                return []
            
            # Convert mask if provided
            mask_bytes = None
            if mask:
                if mask.startswith("0x"):
                    mask = mask[2:]
                try:
                    mask_bytes = bytes.fromhex(mask)
                    if len(mask_bytes) != len(pattern_bytes):
                        mask_bytes = None
                except ValueError:
                    mask_bytes = None
            
            matches = []
            
            # Search through all segments
            for segment in self._current_view.segments:
                if segment.readable:
                    start_addr = segment.start
                    end_addr = segment.end
                    
                    # Read segment data
                    segment_data = self._current_view.read(start_addr, end_addr - start_addr)
                    if not segment_data:
                        continue
                    
                    # Search for pattern
                    for i in range(len(segment_data) - len(pattern_bytes) + 1):
                        match_found = True
                        
                        for j in range(len(pattern_bytes)):
                            if mask_bytes:
                                # Apply mask
                                if (segment_data[i + j] & mask_bytes[j]) != (pattern_bytes[j] & mask_bytes[j]):
                                    match_found = False
                                    break
                            else:
                                # Exact match
                                if segment_data[i + j] != pattern_bytes[j]:
                                    match_found = False
                                    break
                        
                        if match_found:
                            match_addr = start_addr + i
                            
                            # Get context
                            func = self._current_view.get_function_at(match_addr)
                            symbol = self._current_view.get_symbol_at(match_addr)
                            
                            match_info = {
                                "address": hex(match_addr),
                                "segment": segment.name if hasattr(segment, 'name') else "unknown",
                                "function": func.name if func else None,
                                "symbol": symbol.name if symbol else None,
                                "pattern": pattern,
                                "matched_bytes": segment_data[i:i+len(pattern_bytes)].hex()
                            }
                            
                            matches.append(match_info)
            
            return matches
            
        except Exception as e:
            bn.log_error(f"Error searching bytes: {e}")
            return []

    def find_immediate_values(self, value: int, size: int = None) -> List[Dict[str, Any]]:
        """Find immediate values in instructions.
        
        Args:
            value: Value to search for
            size: Optional size constraint (1, 2, 4, 8 bytes)
            
        Returns:
            List of locations where the immediate value is used
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            matches = []
            
            # Convert value to different representations
            hex_value = hex(value)
            
            # Search through all functions
            for func in self._current_view.functions:
                try:
                    # Check each basic block
                    for block in func.basic_blocks:
                        addr = block.start
                        while addr < block.end:
                            try:
                                # Get instruction
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    addr += 1
                                    continue
                                
                                # Get disassembly
                                disasm = self._current_view.get_disassembly(addr)
                                if not disasm:
                                    addr += instr_len
                                    continue
                                
                                # Check if our value appears in the instruction
                                if (hex_value in disasm or 
                                    str(value) in disasm or 
                                    f"0x{value:x}" in disasm):
                                    
                                    match_info = {
                                        "address": hex(addr),
                                        "function": func.name,
                                        "instruction": disasm,
                                        "value": value,
                                        "hex_value": hex_value
                                    }
                                    
                                    # Try to get more context
                                    comment = self._current_view.get_comment_at(addr)
                                    if comment:
                                        match_info["comment"] = comment
                                    
                                    matches.append(match_info)
                                
                                addr += instr_len
                                
                            except Exception:
                                addr += 1
                                
                except Exception as e:
                    bn.log_error(f"Error processing function {func.name}: {e}")
                    continue
            
            return matches
            
        except Exception as e:
            bn.log_error(f"Error finding immediate values: {e}")
            return []

    def search_instructions(self, mnemonic: str, operand_pattern: str = None) -> List[Dict[str, Any]]:
        """Search for specific instruction patterns.
        
        Args:
            mnemonic: Instruction mnemonic to search for (e.g., "call", "mov")
            operand_pattern: Optional operand pattern to match
            
        Returns:
            List of matching instructions
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            matches = []
            mnemonic_lower = mnemonic.lower()
            
            # Search through all functions
            for func in self._current_view.functions:
                try:
                    for block in func.basic_blocks:
                        addr = block.start
                        while addr < block.end:
                            try:
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    addr += 1
                                    continue
                                
                                disasm = self._current_view.get_disassembly(addr)
                                if not disasm:
                                    addr += instr_len
                                    continue
                                
                                disasm_lower = disasm.lower()
                                
                                # Check if mnemonic matches
                                if disasm_lower.startswith(mnemonic_lower):
                                    # If operand pattern specified, check it too
                                    if operand_pattern:
                                        if operand_pattern.lower() not in disasm_lower:
                                            addr += instr_len
                                            continue
                                    
                                    match_info = {
                                        "address": hex(addr),
                                        "function": func.name,
                                        "instruction": disasm,
                                        "mnemonic": mnemonic
                                    }
                                    
                                    if operand_pattern:
                                        match_info["operand_pattern"] = operand_pattern
                                    
                                    # Get instruction bytes
                                    raw_bytes = self._current_view.read(addr, instr_len)
                                    if raw_bytes:
                                        match_info["bytes"] = raw_bytes.hex()
                                    
                                    matches.append(match_info)
                                
                                addr += instr_len
                                
                            except Exception:
                                addr += 1
                                
                except Exception as e:
                    bn.log_error(f"Error processing function {func.name}: {e}")
                    continue
            
            return matches
            
        except Exception as e:
            bn.log_error(f"Error searching instructions: {e}")
            return []

    def find_apis_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Find API calls matching a pattern.
        
        Args:
            pattern: Pattern to match against API names (case insensitive)
            
        Returns:
            List of API call locations
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            api_calls = []
            pattern_lower = pattern.lower()
            
            # Get all imported functions
            for symbol in self._current_view.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol):
                if pattern_lower in symbol.name.lower():
                    # Find all references to this API
                    for ref in self._current_view.get_code_refs(symbol.address):
                        if ref.function:
                            api_info = {
                                "api_name": symbol.name,
                                "api_address": hex(symbol.address),
                                "call_address": hex(ref.address),
                                "function": ref.function.name,
                                "pattern_matched": pattern
                            }
                            
                            # Get the calling instruction
                            try:
                                disasm = self._current_view.get_disassembly(ref.address)
                                if disasm:
                                    api_info["instruction"] = disasm
                            except:
                                pass
                            
                            api_calls.append(api_info)
            
            return api_calls
            
        except Exception as e:
            bn.log_error(f"Error finding APIs: {e}")
            return []

    # ========== ANALYSIS CONTROL METHODS ==========
    
    def run_analysis(self, analysis_type: str = "auto") -> Dict[str, Any]:
        """Run or control Binary Ninja analysis.
        
        Args:
            analysis_type: Type of analysis to run ("auto", "linear", "full")
            
        Returns:
            Dictionary with analysis status
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if analysis_type == "auto":
                # Run automatic analysis (this is usually done by default)
                self._current_view.update_analysis_and_wait()
            elif analysis_type == "linear":
                # Run linear analysis on entire binary
                self._current_view.create_user_function(self._current_view.start)
            elif analysis_type == "full":
                # Force full analysis
                self._current_view.update_analysis_and_wait()
                
                # Analyze all functions
                for func in self._current_view.functions:
                    func.reanalyze()
                
                self._current_view.update_analysis_and_wait()
            else:
                return {
                    "success": False,
                    "error": f"Unknown analysis type: {analysis_type}"
                }
            
            return {
                "success": True,
                "analysis_type": analysis_type,
                "function_count": len(self._current_view.functions),
                "status": "Analysis completed"
            }
            
        except Exception as e:
            bn.log_error(f"Error running analysis: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def analyze_function(self, function_name: str) -> Dict[str, Any]:
        """Force reanalysis of a specific function.
        
        Args:
            function_name: Name or address of function to reanalyze
            
        Returns:
            Dictionary with analysis result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            # Force reanalysis
            func.reanalyze()
            self._current_view.update_analysis_and_wait()
            
            return {
                "success": True,
                "function": func.name,
                "address": hex(func.start),
                "basic_blocks": len(func.basic_blocks),
                "status": "Function reanalyzed"
            }
            
        except Exception as e:
            bn.log_error(f"Error analyzing function: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_function_at(self, address: int) -> Dict[str, Any]:
        """Create a function at the specified address.
        
        Args:
            address: Address where to create the function
            
        Returns:
            Dictionary with creation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            if not self._current_view.is_valid_offset(address):
                return {
                    "success": False,
                    "error": f"Invalid address: {hex(address)}"
                }
            
            # Check if function already exists
            existing_func = self._current_view.get_function_at(address)
            if existing_func:
                return {
                    "success": False,
                    "error": f"Function already exists at {hex(address)}: {existing_func.name}"
                }
            
            # Create the function
            new_func = self._current_view.create_user_function(address)
            if new_func:
                return {
                    "success": True,
                    "function": new_func.name,
                    "address": hex(address),
                    "status": "Function created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create function (may not be valid code)"
                }
            
        except Exception as e:
            bn.log_error(f"Error creating function: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def undefine_function(self, function_name: str) -> Dict[str, Any]:
        """Remove a function definition.
        
        Args:
            function_name: Name or address of function to undefine
            
        Returns:
            Dictionary with operation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found"
                }
            
            func_name = func.name
            func_addr = hex(func.start)
            
            # Remove the function
            self._current_view.remove_user_function(func)
            
            return {
                "success": True,
                "function": func_name,
                "address": func_addr,
                "status": "Function undefined successfully"
            }
            
        except Exception as e:
            bn.log_error(f"Error undefining function: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_analysis_info(self) -> Dict[str, Any]:
        """Get information about the current analysis state.
        
        Returns:
            Dictionary with analysis information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            info = {
                "binary_file": self._current_view.file.filename if self._current_view.file else None,
                "architecture": str(self._current_view.arch) if self._current_view.arch else None,
                "platform": str(self._current_view.platform) if self._current_view.platform else None,
                "entry_point": hex(self._current_view.entry_point) if self._current_view.entry_point else None,
                "function_count": len(self._current_view.functions),
                "segment_count": len(self._current_view.segments),
                "analysis_progress": {
                    "state": "complete" if len(self._current_view.functions) > 0 else "pending",
                    "functions_analyzed": len(self._current_view.functions)
                }
            }
            
            # Get basic statistics
            total_instructions = 0
            total_basic_blocks = 0
            
            for func in self._current_view.functions:
                total_basic_blocks += len(func.basic_blocks)
                for block in func.basic_blocks:
                    total_instructions += len(block)
            
            info["statistics"] = {
                "total_basic_blocks": total_basic_blocks,
                "total_instructions": total_instructions,
                "average_blocks_per_function": total_basic_blocks / len(self._current_view.functions) if self._current_view.functions else 0
            }
            
            return info
            
        except Exception as e:
            bn.log_error(f"Error getting analysis info: {e}")
            return {
                "error": str(e)
            }

    def get_file_metadata(self) -> Dict[str, Any]:
        """Get comprehensive file metadata information.
        
        Returns:
            Dictionary with complete file metadata including file info, 
            binary properties, architecture details, and checksums
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            metadata = {}
            
            # File information
            if self._current_view.file:
                file_info = {
                    "filename": self._current_view.file.filename,
                    "original_filename": self._current_view.file.original_filename,
                    "modified": self._current_view.file.modified,
                    "has_database": self._current_view.file.has_database,
                }
                
                # Get file size if available
                import os
                try:
                    if os.path.exists(self._current_view.file.original_filename):
                        file_info["file_size"] = os.path.getsize(self._current_view.file.original_filename)
                        
                        # Get file timestamps
                        stat = os.stat(self._current_view.file.original_filename)
                        file_info["created_time"] = stat.st_ctime
                        file_info["modified_time"] = stat.st_mtime
                        file_info["accessed_time"] = stat.st_atime
                except (OSError, IOError):
                    pass
                    
                metadata["file"] = file_info
            
            # Binary view properties
            binary_info = {
                "start_offset": hex(self._current_view.start),
                "end_offset": hex(self._current_view.end),
                "length": self._current_view.end - self._current_view.start,
                "view_type": str(self._current_view.view_type) if hasattr(self._current_view, 'view_type') else None,
            }
            
            # Architecture information
            if self._current_view.arch:
                arch_info = {
                    "name": str(self._current_view.arch),
                    "endianness": str(self._current_view.endianness),
                }
                
                # Safely add architecture properties that might exist
                try:
                    if hasattr(self._current_view.arch, 'address_size'):
                        arch_info["address_size"] = self._current_view.arch.address_size
                    if hasattr(self._current_view.arch, 'max_instr_length'):
                        arch_info["max_instruction_length"] = self._current_view.arch.max_instr_length
                except:
                    pass
                    
                metadata["architecture"] = arch_info
            
            # Platform information
            if self._current_view.platform:
                platform_info = {
                    "name": str(self._current_view.platform),
                }
                
                # Safely add platform properties
                try:
                    if hasattr(self._current_view.platform, 'calling_conventions'):
                        platform_info["calling_conventions"] = [str(cc) for cc in self._current_view.platform.calling_conventions]
                    if hasattr(self._current_view.platform, 'system_call_convention') and self._current_view.platform.system_call_convention:
                        platform_info["system_call_convention"] = str(self._current_view.platform.system_call_convention)
                except:
                    pass
                    
                metadata["platform"] = platform_info
            
            # Entry point information
            if self._current_view.entry_point:
                entry_info = {
                    "address": hex(self._current_view.entry_point),
                    "function_name": None
                }
                
                # Try to get entry function name
                entry_func = self._current_view.get_function_at(self._current_view.entry_point)
                if entry_func:
                    entry_info["function_name"] = entry_func.name
                    
                metadata["entry_point"] = entry_info
            
            # Segment information
            segments_info = []
            try:
                for segment in self._current_view.segments:
                    try:
                        seg_info = {
                            "start": hex(segment.start),
                            "end": hex(segment.end),
                            "length": segment.end - segment.start,
                            "data_length": segment.data_length,
                            "executable": segment.executable,
                            "readable": segment.readable,
                            "writable": segment.writable,
                        }
                        segments_info.append(seg_info)
                    except Exception:
                        # Skip malformed segments
                        continue
            except Exception:
                pass
            metadata["segments"] = segments_info
            
            # Section information
            sections_info = []
            try:
                for section in self._current_view.sections.values():
                    try:
                        sect_info = {
                            "name": section.name,
                            "start": hex(section.start),
                            "end": hex(section.end),
                            "length": section.end - section.start,
                            "type": section.type,
                        }
                        sections_info.append(sect_info)
                    except Exception:
                        # Skip malformed sections
                        continue
            except Exception:
                pass
            metadata["sections"] = sections_info
            
            # Import/Export information
            try:
                metadata["imports"] = [str(sym) for sym in self._current_view.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol)]
            except Exception:
                metadata["imports"] = []
            
            try:
                metadata["exports"] = [str(sym) for sym in self._current_view.get_symbols_of_type(bn.SymbolType.ExportedFunctionSymbol)]
            except Exception:
                metadata["exports"] = []
            
            # Basic statistics
            stats = {
                "function_count": len(self._current_view.functions),
                "symbol_count": len(self._current_view.symbols),
                "string_count": len(self._current_view.strings),
                "data_variable_count": len(self._current_view.data_vars),
            }
            metadata["statistics"] = stats
            
            # Add the binary_info to metadata
            metadata["binary"] = binary_info
            
            return metadata
            
        except Exception as e:
            bn.log_error(f"Error getting file metadata: {e}")
            return {
                "error": str(e)
            }

    # ========== ENHANCED STRUCT AND TYPE MANAGEMENT METHODS ==========
    
    def list_user_types(self, offset: int = 0, limit: int = 100) -> Dict[str, Any]:
        """List all user-defined types with metadata and pagination.
        
        Args:
            offset: Pagination offset (default: 0)
            limit: Maximum number of types to return (default: 100)
            
        Returns:
            Dictionary with user-defined types and metadata
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            all_types = []
            
            # Get all user-defined types
            for type_name in self._current_view.types:
                try:
                    type_obj = self._current_view.types[type_name]
                    
                    # Determine type category
                    type_category = "unknown"
                    size = 0
                    members = []
                    
                    if hasattr(type_obj, 'type_class'):
                        if type_obj.type_class == bn.TypeClass.StructureTypeClass:
                            type_category = "struct"
                            if hasattr(type_obj, 'structure'):
                                size = type_obj.structure.width
                                members = [{"name": member.name, "offset": member.offset, "type": str(member.type)} 
                                         for member in type_obj.structure.members]
                        elif type_obj.type_class == bn.TypeClass.EnumerationTypeClass:
                            type_category = "enum"
                            if hasattr(type_obj, 'enumeration'):
                                members = [{"name": member.name, "value": member.value} 
                                         for member in type_obj.enumeration.members]
                        elif type_obj.type_class == bn.TypeClass.NamedTypeReferenceClass:
                            type_category = "typedef"
                        else:
                            type_category = str(type_obj.type_class)
                    
                    type_info = {
                        "name": type_name,
                        "category": type_category,
                        "size": size,
                        "member_count": len(members),
                        "members": members[:10] if len(members) > 10 else members,  # Limit to first 10 members
                        "has_more_members": len(members) > 10,
                        "definition": str(type_obj)
                    }
                    
                    all_types.append(type_info)
                    
                except Exception as e:
                    bn.log_error(f"Error processing type {type_name}: {e}")
                    continue
            
            # Sort by name for consistent ordering
            all_types.sort(key=lambda x: x["name"])
            
            # Apply pagination
            total_count = len(all_types)
            start_idx = offset
            end_idx = min(offset + limit, total_count)
            paginated_types = all_types[start_idx:end_idx]
            
            return {
                "success": True,
                "types": paginated_types,
                "pagination": {
                    "offset": offset,
                    "limit": limit,
                    "total": total_count,
                    "has_more": end_idx < total_count
                }
            }
            
        except Exception as e:
            bn.log_error(f"Error listing user types: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_struct(self, name: str, members: List[Dict[str, Any]], packed: bool = False) -> Dict[str, Any]:
        """Create a new structure type with specified members.
        
        Args:
            name: Name of the structure
            members: List of member dictionaries with 'name', 'type', and optional 'offset'
            packed: Whether the structure should be packed (default: False)
            
        Returns:
            Dictionary with creation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type already exists
            if name in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' already exists"
                }
            
            # Create structure builder
            struct_builder = bn.StructureBuilder.create(packed=packed)
            
            # Add members
            for member in members:
                try:
                    member_name = member.get("name", "")
                    member_type_str = member.get("type", "")
                    member_offset = member.get("offset", None)
                    
                    if not member_name or not member_type_str:
                        continue
                    
                    # Parse the type
                    parsed_types, errors = self._current_view.parse_types_from_string(member_type_str)
                    if errors:
                        bn.log_warn(f"Warning parsing type '{member_type_str}': {errors}")
                        
                    if parsed_types and len(parsed_types) > 0:
                        member_type = list(parsed_types.values())[0]
                        
                        if member_offset is not None:
                            # Add at specific offset
                            struct_builder.add_member_at_offset(member_name, member_type, member_offset)
                        else:
                            # Append to end
                            struct_builder.append(member_type, member_name)
                    else:
                        # Fallback: try to create a basic type
                        if member_type_str in ["int", "int32_t"]:
                            member_type = bn.Type.int(4)
                        elif member_type_str in ["char", "int8_t"]:
                            member_type = bn.Type.int(1)
                        elif member_type_str in ["short", "int16_t"]:
                            member_type = bn.Type.int(2)
                        elif member_type_str in ["long", "int64_t"]:
                            member_type = bn.Type.int(8)
                        elif member_type_str == "void*":
                            member_type = bn.Type.pointer(self._current_view.arch, bn.Type.void())
                        else:
                            bn.log_warn(f"Could not parse type '{member_type_str}', skipping member '{member_name}'")
                            continue
                        
                        if member_offset is not None:
                            struct_builder.add_member_at_offset(member_name, member_type, member_offset)
                        else:
                            struct_builder.append(member_type, member_name)
                            
                except Exception as e:
                    bn.log_error(f"Error adding member '{member.get('name', 'unknown')}': {e}")
                    continue
            
            # Finalize the structure
            structure = struct_builder.immutable_copy()
            struct_type = bn.Type.structure(structure)
            
            # Define the type in the binary view
            self._current_view.define_user_type(name, struct_type)
            
            return {
                "success": True,
                "name": name,
                "size": getattr(structure, 'width', 0),
                "member_count": len(getattr(structure, 'members', [])),
                "members": [{"name": m.name, "offset": m.offset, "type": str(m.type)} for m in getattr(structure, 'members', [])]
            }
            
        except Exception as e:
            bn.log_error(f"Error creating structure: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def modify_struct(self, name: str, operation: str, **kwargs) -> Dict[str, Any]:
        """Modify an existing structure type.
        
        Args:
            name: Name of the structure to modify
            operation: Operation to perform ("add_member", "remove_member", "modify_member")
            **kwargs: Operation-specific parameters
            
        Returns:
            Dictionary with modification result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type exists
            if name not in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' not found"
                }
            
            existing_type = self._current_view.types[name]
            
            # Verify it's a structure
            if not hasattr(existing_type, 'structure') or existing_type.type_class != bn.TypeClass.StructureTypeClass:
                return {
                    "success": False,
                    "error": f"Type '{name}' is not a structure"
                }
            
            # Get the existing structure
            existing_struct = existing_type.structure
            
            # Create a new structure builder based on the existing structure
            struct_builder = bn.StructureBuilder.create(packed=existing_struct.packed)
            
            # Copy existing members
            for member in existing_struct.members:
                struct_builder.append(member.type, member.name)
            
            # Perform the operation
            if operation == "add_member":
                member_name = kwargs.get("member_name", "")
                member_type_str = kwargs.get("member_type", "")
                insert_index = kwargs.get("index", None)
                
                if not member_name or not member_type_str:
                    return {
                        "success": False,
                        "error": "member_name and member_type are required for add_member operation"
                    }
                
                # Parse the new member type
                parsed_types, errors = self._current_view.parse_types_from_string(member_type_str)
                if errors or not parsed_types:
                    return {
                        "success": False,
                        "error": f"Could not parse member type '{member_type_str}': {errors}"
                    }
                
                member_type = list(parsed_types.values())[0]
                
                if insert_index is not None:
                    # Insert at specific index position (not offset)
                    # We need to rebuild the structure with the new member at the right position
                    members_list = []
                    for i, existing_member in enumerate(existing_struct.members):
                        if i == insert_index:
                            members_list.append((member_type, member_name))
                        members_list.append((existing_member.type, existing_member.name))
                    # If inserting at end
                    if insert_index >= len(existing_struct.members):
                        members_list.append((member_type, member_name))
                    
                    # Rebuild structure with new member list
                    struct_builder = bn.StructureBuilder.create(packed=existing_struct.packed)
                    for m_type, m_name in members_list:
                        struct_builder.append(m_type, m_name)
                else:
                    struct_builder.append(member_type, member_name)
                    
            elif operation == "remove_member":
                member_name = kwargs.get("member_name", "")
                
                if not member_name:
                    return {
                        "success": False,
                        "error": "member_name is required for remove_member operation"
                    }
                
                # Find and remove the member by rebuilding without it
                struct_builder = bn.StructureBuilder.create(packed=existing_struct.packed)
                
                found_member = False
                for member in existing_struct.members:
                    if member.name == member_name:
                        found_member = True
                        continue  # Skip this member (remove it)
                    struct_builder.append(member.type, member.name)
                
                if not found_member:
                    return {
                        "success": False,
                        "error": f"Member '{member_name}' not found in structure '{name}'"
                    }
                    
            else:
                return {
                    "success": False,
                    "error": f"Unknown operation: {operation}"
                }
            
            # Finalize the modified structure
            new_structure = struct_builder.immutable_copy()
            new_struct_type = bn.Type.structure(new_structure)
            
            # Update the type definition
            self._current_view.define_user_type(name, new_struct_type)
            
            return {
                "success": True,
                "name": name,
                "operation": operation,
                "size": getattr(new_structure, 'width', 0),
                "member_count": len(getattr(new_structure, 'members', [])),
                "members": [{"name": m.name, "offset": m.offset, "type": str(m.type)} for m in getattr(new_structure, 'members', [])]
            }
            
        except Exception as e:
            bn.log_error(f"Error modifying structure: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_enum(self, name: str, members: List[Dict[str, Any]], size: int = 4) -> Dict[str, Any]:
        """Create a new enumeration type.
        
        Args:
            name: Name of the enumeration
            members: List of member dictionaries with 'name' and 'value'
            size: Size of the enumeration in bytes (default: 4)
            
        Returns:
            Dictionary with creation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type already exists
            if name in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' already exists"
                }
            
            # Create enumeration builder
            enum_builder = bn.EnumerationBuilder.create()
            
            # Add members
            for member in members:
                try:
                    member_name = member.get("name", "")
                    member_value = member.get("value", 0)
                    
                    if not member_name:
                        continue
                    
                    # Ensure value is an integer
                    if isinstance(member_value, str):
                        if member_value.startswith("0x"):
                            member_value = int(member_value, 16)
                        else:
                            member_value = int(member_value)
                    
                    enum_builder.append(member_name, member_value)
                    
                except Exception as e:
                    bn.log_error(f"Error adding enum member '{member.get('name', 'unknown')}': {e}")
                    continue
            
            # Create enumeration type from builder
            enum_type = bn.Type.enumeration_type(self._current_view.arch, enum_builder, size)
            
            # Define the type in the binary view
            self._current_view.define_user_type(name, enum_type)
            
            return {
                "success": True,
                "name": name,
                "size": size,
                "member_count": len(getattr(enum_builder, 'members', [])),
                "members": [{"name": m.name, "value": m.value} for m in getattr(enum_builder, 'members', [])]
            }
            
        except Exception as e:
            bn.log_error(f"Error creating enumeration: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_union(self, name: str, members: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new union type.
        
        Args:
            name: Name of the union
            members: List of member dictionaries with 'name' and 'type'
            
        Returns:
            Dictionary with creation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type already exists
            if name in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' already exists"
                }
            
            # Create union using StructureBuilder with Union type
            # Create the union structure builder
            struct_builder = bn.StructureBuilder.create(
                type=StructureVariant.UnionStructureType
            )
            
            # Add union members
            for member in members:
                try:
                    member_name = member.get("name", "")
                    member_type_str = member.get("type", "")
                    
                    if not member_name or not member_type_str:
                        continue
                    
                    # Parse the type
                    parsed_types, errors = self._current_view.parse_types_from_string(member_type_str)
                    if errors:
                        bn.log_warn(f"Warning parsing type '{member_type_str}': {errors}")
                        
                    if parsed_types and len(parsed_types) > 0:
                        member_type = list(parsed_types.values())[0]
                        # Add member to the union structure builder
                        struct_builder.append(member_type, member_name)
                    else:
                        bn.log_warn(f"Could not parse type '{member_type_str}', skipping member '{member_name}'")
                        continue
                        
                except Exception as e:
                    bn.log_error(f"Error processing union member '{member.get('name', 'unknown')}': {e}")
                    continue
            
            # Finalize the union
            structure = struct_builder.immutable_copy()
            union_type = bn.Type.structure(structure)
            
            # Define the type in the binary view
            self._current_view.define_user_type(name, union_type)
            
            return {
                "success": True,
                "name": name,
                "size": getattr(structure, 'width', 0),
                "member_count": len(getattr(structure, 'members', [])),
                "members": [{"name": m.name, "type": str(m.type)} for m in getattr(structure, 'members', [])]
            }
            
        except Exception as e:
            bn.log_error(f"Error creating union: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def create_typedef(self, name: str, target_type: str) -> Dict[str, Any]:
        """Create a type alias (typedef).
        
        Args:
            name: Name of the new type alias
            target_type: Target type string to alias
            
        Returns:
            Dictionary with creation result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type already exists
            if name in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' already exists"
                }
            
            # Parse the target type
            parsed_types, errors = self._current_view.parse_types_from_string(target_type)
            if errors or not parsed_types:
                return {
                    "success": False,
                    "error": f"Could not parse target type '{target_type}': {errors}"
                }
            
            target_type_obj = list(parsed_types.values())[0]
            
            # Create named type reference - typedef is just an alias
            typedef_type = target_type_obj
            
            # Define the type in the binary view
            self._current_view.define_user_type(name, typedef_type)
            
            return {
                "success": True,
                "name": name,
                "target_type": target_type,
                "size": getattr(target_type_obj, 'width', 0),
                "definition": str(typedef_type)
            }
            
        except Exception as e:
            bn.log_error(f"Error creating typedef: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def delete_user_type(self, name: str) -> Dict[str, Any]:
        """Remove a user-defined type.
        
        Args:
            name: Name of the type to remove
            
        Returns:
            Dictionary with deletion result
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type exists
            if name not in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' not found"
                }
            
            # Remove the type
            self._current_view.undefine_user_type(name)
            
            return {
                "success": True,
                "name": name,
                "status": "Type deleted successfully"
            }
            
        except Exception as e:
            bn.log_error(f"Error deleting type: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_type_references(self, name: str) -> Dict[str, Any]:
        """Find where a type is used throughout the binary.
        
        Args:
            name: Name of the type to find references for
            
        Returns:
            Dictionary with reference information
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type exists
            if name not in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' not found"
                }
            
            references = {
                "variables": [],
                "function_parameters": [],
                "function_returns": [],
                "struct_members": [],
                "total_count": 0
            }
            
            # Search through functions for variable usage
            for func in self._current_view.functions:
                try:
                    # Check function signature
                    if hasattr(func, 'type') and func.type:
                        func_type_str = str(func.type)
                        if name in func_type_str:
                            references["function_returns"].append({
                                "function": func.name,
                                "address": hex(func.start),
                                "signature": func_type_str
                            })
                    
                    # Check function variables
                    for var in func.vars:
                        var_type_str = str(var.type)
                        if name in var_type_str:
                            references["variables"].append({
                                "function": func.name,
                                "variable": var.name,
                                "type": var_type_str,
                                "address": hex(func.start)
                            })
                            
                except Exception as e:
                    bn.log_error(f"Error checking function {func.name}: {e}")
                    continue
            
            # Search through other types for member usage
            for type_name, type_obj in self._current_view.types.items():
                if type_name == name:
                    continue
                    
                try:
                    if hasattr(type_obj, 'structure') and type_obj.structure:
                        for member in type_obj.structure.members:
                            member_type_str = str(member.type)
                            if name in member_type_str:
                                references["struct_members"].append({
                                    "struct": type_name,
                                    "member": member.name,
                                    "type": member_type_str
                                })
                except Exception:
                    continue
            
            # Calculate total count
            references["total_count"] = (
                len(references["variables"]) +
                len(references["function_parameters"]) +
                len(references["function_returns"]) +
                len(references["struct_members"])
            )
            
            return {
                "success": True,
                "type_name": name,
                "references": references
            }
            
        except Exception as e:
            bn.log_error(f"Error finding type references: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def analyze_struct_usage(self, name: str) -> Dict[str, Any]:
        """Analyze how a structure is used in the binary.
        
        Args:
            name: Name of the structure to analyze
            
        Returns:
            Dictionary with usage analysis
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if type exists and is a structure
            if name not in self._current_view.types:
                return {
                    "success": False,
                    "error": f"Type '{name}' not found"
                }
            
            type_obj = self._current_view.types[name]
            if not hasattr(type_obj, 'structure') or type_obj.type_class != bn.TypeClass.StructureTypeClass:
                return {
                    "success": False,
                    "error": f"Type '{name}' is not a structure"
                }
            
            structure = type_obj.structure
            analysis = {
                "struct_info": {
                    "name": name,
                    "size": getattr(structure, 'width', 0),
                    "member_count": len(getattr(structure, 'members', [])),
                    "is_packed": getattr(structure, 'packed', False)
                },
                "usage_patterns": {
                    "as_variable": 0,
                    "as_pointer": 0,
                    "as_array": 0,
                    "as_parameter": 0,
                    "as_return_type": 0
                },
                "member_access_patterns": {},
                "frequent_offsets": [],
                "instantiation_locations": []
            }
            
            # Initialize member access tracking
            for member in getattr(structure, 'members', []):
                analysis["member_access_patterns"][member.name] = {
                    "offset": member.offset,
                    "type": str(member.type),
                    "access_count": 0,
                    "functions_using": []
                }
            
            # Analyze usage across functions
            for func in self._current_view.functions:
                try:
                    # Check function variables
                    for var in func.vars:
                        var_type_str = str(var.type)
                        if name in var_type_str:
                            if "*" in var_type_str:
                                analysis["usage_patterns"]["as_pointer"] += 1
                            elif "[" in var_type_str:
                                analysis["usage_patterns"]["as_array"] += 1
                            else:
                                analysis["usage_patterns"]["as_variable"] += 1
                            
                            analysis["instantiation_locations"].append({
                                "function": func.name,
                                "variable": var.name,
                                "type": var_type_str,
                                "address": hex(func.start)
                            })
                    
                    # Analyze HLIL for member access patterns
                    try:
                        hlil = func.hlil_if_available
                        if hlil:
                            for block in hlil:
                                for instr in block:
                                    # Look for struct member accesses
                                    instr_str = str(instr)
                                    for member in getattr(structure, 'members', []):
                                        if f".{member.name}" in instr_str or f"->{member.name}" in instr_str:
                                            analysis["member_access_patterns"][member.name]["access_count"] += 1
                                            if func.name not in analysis["member_access_patterns"][member.name]["functions_using"]:
                                                analysis["member_access_patterns"][member.name]["functions_using"].append(func.name)
                    except Exception:
                        pass
                        
                except Exception as e:
                    bn.log_error(f"Error analyzing function {func.name}: {e}")
                    continue
            
            # Calculate frequently accessed offsets
            offset_counts = {}
            for member_name, member_data in analysis["member_access_patterns"].items():
                offset = member_data["offset"]
                count = member_data["access_count"]
                if count > 0:
                    offset_counts[offset] = offset_counts.get(offset, 0) + count
            
            # Sort by access count
            analysis["frequent_offsets"] = [
                {"offset": offset, "access_count": count}
                for offset, count in sorted(offset_counts.items(), key=lambda x: x[1], reverse=True)
            ]
            
            return {
                "success": True,
                "analysis": analysis
            }
            
        except Exception as e:
            bn.log_error(f"Error analyzing struct usage: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def export_types_as_c_header(self, type_names: List[str] = None) -> Dict[str, Any]:
        """Export type definitions as C header code.
        
        Args:
            type_names: Optional list of specific type names to export. If None, exports all.
            
        Returns:
            Dictionary with C header code
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            header_lines = [
                "/* Generated C Header */",
                "/* Binary Ninja MCP Export */",
                "",
                "#ifndef _BINJA_TYPES_H_",
                "#define _BINJA_TYPES_H_",
                "",
                "#include <stdint.h>",
                "#include <stddef.h>",
                ""
            ]
            
            types_to_export = type_names if type_names else list(self._current_view.types.keys())
            exported_count = 0
            
            for type_name in types_to_export:
                if type_name not in self._current_view.types:
                    continue
                    
                try:
                    type_obj = self._current_view.types[type_name]
                    
                    # Generate C definition based on type
                    if hasattr(type_obj, 'structure') and type_obj.type_class == bn.TypeClass.StructureTypeClass:
                        structure = type_obj.structure
                        
                        # Check if this is a union type using the type property
                        if hasattr(structure, 'type') and structure.type == bn.StructureVariant.UnionStructureType:
                            header_lines.append(f"union {type_name} {{")
                        else:
                            header_lines.append(f"struct {type_name} {{")
                        
                        for member in structure.members:
                            member_type_str = str(member.type).replace("struct ", "").replace("union ", "")
                            header_lines.append(f"    {member_type_str} {member.name}; /* offset: 0x{member.offset:x} */")
                        
                        if structure.packed:
                            header_lines.append("} __attribute__((packed));")
                        else:
                            header_lines.append("};")
                        header_lines.append("")
                        
                    elif hasattr(type_obj, 'enumeration') and type_obj.type_class == bn.TypeClass.EnumerationTypeClass:
                        enumeration = type_obj.enumeration
                        header_lines.append(f"enum {type_name} {{")
                        
                        # Add enum members with safe access pattern
                        members = getattr(enumeration, 'members', [])
                        if hasattr(enumeration, '__iter__'):  # Some enum types are iterable
                            try:
                                for member in enumeration:
                                    if hasattr(member, 'name') and hasattr(member, 'value'):
                                        header_lines.append(f"    {member.name} = {member.value},")
                            except (TypeError, AttributeError):
                                # Fallback: try to access as list
                                for member in members:
                                    if hasattr(member, 'name') and hasattr(member, 'value'):
                                        header_lines.append(f"    {member.name} = {member.value},")
                        else:
                            # Direct member access
                            for member in members:
                                if hasattr(member, 'name') and hasattr(member, 'value'):
                                    header_lines.append(f"    {member.name} = {member.value},")
                        
                        header_lines.append("};")
                        header_lines.append("")
                    
                    elif type_obj.type_class == bn.TypeClass.NamedTypeReferenceClass:
                        # This is a typedef
                        target_type = str(type_obj).replace(f"typedef {type_name}", "").strip()
                        header_lines.append(f"typedef {target_type} {type_name};")
                        header_lines.append("")
                    
                    exported_count += 1
                    
                except Exception as e:
                    bn.log_error(f"Error exporting type {type_name}: {e}")
                    continue
            
            header_lines.extend([
                "#endif /* _BINJA_TYPES_H_ */",
                ""
            ])
            
            return {
                "success": True,
                "header_code": "\n".join(header_lines),
                "exported_count": exported_count,
                "total_types": len(types_to_export)
            }
            
        except Exception as e:
            bn.log_error(f"Error exporting types: {e}")
            return {
                "success": False,
                "error": str(e)
            }
