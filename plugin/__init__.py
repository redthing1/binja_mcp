import binaryninja as bn
from .core.config import Config
from .server.http_server import MCPServer


class BinaryNinjaMCP:
    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)
        self._server_running = False

    def start_server(self, bv):
        try:
            self.server.binary_ops.current_view = bv
            self.server.start()
            self._server_running = True
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
        except Exception as e:
            self._server_running = False  # Ensure state is consistent
            bn.log_error(f"Failed to start MCP server: {str(e)}")

    def stop_server(self, bv):
        try:
            self.server.binary_ops.current_view = None
            self.server.stop()
            self._server_running = False
            bn.log_info("Binary Ninja MCP plugin stopped successfully")
        except Exception as e:
            bn.log_error(f"Failed to stop server: {str(e)}")

    def can_start_server(self, bv):
        """Check if the Start Server menu item should be available"""
        return not self._server_running

    def can_stop_server(self, bv):
        """Check if the Stop Server menu item should be available"""
        return self._server_running

    def show_server_status(self, bv):
        """Show current server status"""
        if self._server_running:
            bn.log_info(
                f"MCP Server Status: RUNNING on http://{self.config.server.host}:{self.config.server.port} "
                f"(Binary loaded: {'Yes' if self.server.binary_ops.current_view else 'No'})"
            )
        else:
            bn.log_info("MCP Server Status: STOPPED")


plugin = BinaryNinjaMCP()

bn.PluginCommand.register(
    "MCP Server\\Start MCP Server",
    "Start the Binary Ninja MCP server",
    plugin.start_server,
    plugin.can_start_server,
)

bn.PluginCommand.register(
    "MCP Server\\Stop MCP Server",
    "Stop the Binary Ninja MCP server",
    plugin.stop_server,
    plugin.can_stop_server,
)

bn.PluginCommand.register(
    "MCP Server\\Show Server Status",
    "Show current MCP server status and configuration",
    plugin.show_server_status,
)

bn.log_info("Binary Ninja MCP plugin loaded successfully")
