import logging

from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypeInt, SimTypeString

from . import io_file_data_for_arch

l = logging.getLogger("angr.procedures.libc.fscanf")

class fscanf(FormatParser):

    def run(self, file_ptr):

        self.return_type = SimTypeInt(self.state.arch.bits, True)

        # The format str is at index 1
        fmt_str = self._parse(1)

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved

        f = self.state.posix.get_file(fileno)
        region = f.content
        start = f.pos

        (end, items) = fmt_str.interpret(start, 1, self.arg, region=region)

        return items
