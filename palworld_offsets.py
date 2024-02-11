import logging
import warnings
from libs.pygg_api import PyGG
from colorama import Fore, init


warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

init(autoreset=True, convert=True)

class GonjectOffsetLogger:
    def __init__(self, log_file='offsets.log'):
        self.log_file = log_file
        logging.basicConfig(filename=self.log_file, level=logging.INFO, filemode='a', format='%(asctime)s - %(message)s')

    def log_offset(self, class_name, address, type="Not found"):
        if address != "Not Found":
            logging.info(f'{class_name} Offset: {hex(address)} | Type {type}')
        else:
            logging.info(f'{class_name} Offset: {address}')


class PalworldOffsets:
    def __init__(self, pygg: PyGG = None) -> None:
        self.pygg = pygg or PyGG()

        # Update Patterns here
        self._patterns = {
            "GObject": b"\x48\x8B\x05....\x48\x8B\x0C\xC8\x4C\x8D\x04\xD1\xEB\x03",
            "GWorld": b"\x48\x8B\x1D....\x48\x85\xDB\x74\x33\x41\xB0",
            "FName": b"\x48\x8D\x05....\xEB\x13\x48\x8D\x0D....\xE8....\xC6\x05.....\x0F\x10",
            "AppendString": b"\xC3\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x80",
            "ProcessEvent": b"\x40\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x10\x01\x00\x00\x48\x8D",
            "Tick": b"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x60\x48\x8B\xF9\xE8\x00\x00\x00\x00\x48\x8B"
        }
        self.palworld_pid = self._get_palworld_pid()
        self._init_memory()
        self.logging = GonjectOffsetLogger() # you can input a file here if you want to example output.log
        self.module_base = self.pygg.GetModuleBaseAddress(self.palworld_pid, "Palworld-Win64-Shipping.exe")
        self._scan_tick_event()
        self._scan_proc_event()
        self._scan_append_string()
        self._scan_fname()

        self.gobject_address = self._scan_gobjects()
        self.gworld_address = self._scan_gworld()
       
        self._log_gobject_address()
        self._log_gworld_address()
        self.pygg.close_handle()

    def _get_palworld_pid(self):
        palworld_pid = self.pygg.get_process_id("Palworld-Win64-Shipping.exe")
        if palworld_pid is None:
            raise Exception("Please start Palworld, as it is required to run to use this dumper!")
        return palworld_pid

    def _init_memory(self):
        self.pygg.init_memory(self.palworld_pid)


    def cac_offset(self, address, offset):
        return address + 7 + offset - self.module_base

    def _scan_gobjects(self):
        gobjects = self.pygg.aob_scan(self._patterns["GObject"], False)
        if gobjects:
            gobject_offset = self.pygg.read_int(gobjects + 3)
            return self.cac_offset(gobjects, gobject_offset)
        return None

    def _log_gobject_address(self):
        if self.gobject_address:
            print(f"{Fore.YELLOW}GObject: {Fore.BLUE}{hex(self.gobject_address)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("GObject", self.gobject_address, "uint32")
        else:
            self.logging.log_offset("GObject", "Not Found")

    def _scan_gworld(self):
        gworld = self.pygg.aob_scan(self._patterns["GWorld"], False)
        if gworld:
            gworld_offset = self.pygg.read_int(gworld + 3)
            return self.cac_offset(gworld, gworld_offset)
        return None
    
    def _scan_fname(self):
        fname = self.pygg.aob_scan(self._patterns["FName"], False)
        if fname:
            fname_offset = fname - self.module_base
            print(f"{Fore.YELLOW}FName: {Fore.BLUE}{hex(fname_offset)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("FName", fname_offset, "uint32")
        else:
            self.logging.log_offset("FName", "Not Found")


    def _scan_append_string(self):
        append_string = self.pygg.aob_scan(self._patterns["AppendString"], False)
        if append_string:
            append_offset = append_string + 1 - self.module_base
            print(f"{Fore.YELLOW}FName: {Fore.BLUE}{hex(append_offset)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("AppendString", append_offset, "uint32")
        else:
            self.logging.log_offset("AppendString", "Not Found")


    def _scan_proc_event(self):
        proc_event = self.pygg.aob_scan(self._patterns["ProcessEvent"], False)
        if proc_event:
            proc_event_offset = proc_event - self.module_base
            print(f"{Fore.YELLOW}ProcessEvent: {Fore.BLUE}{hex(proc_event_offset)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("ProcessEvent", proc_event_offset, "uint32")
        else:
            self.logging.log_offset("ProcessEvent", "Not Found")

    def _scan_tick_event(self):
        tick_address = self.pygg.aob_scan(self._patterns["Tick"], True)
    
        if tick_address:
            tick_address_offset = tick_address[1] - self.module_base
            print(f"{Fore.YELLOW}Tick: {Fore.BLUE}{hex(tick_address_offset)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("Tick", tick_address_offset, "uint32")
        else:
            self.logging.log_offset("Tick", "Not Found")
        
    def _log_gworld_address(self):
        if self.gworld_address:
            print(f"{Fore.YELLOW}GWorld: {Fore.BLUE}{hex(self.gworld_address)} {Fore.RESET}| Type:{Fore.GREEN} uint32 ")
            self.logging.log_offset("GWorld", self.gworld_address, "uint32")
        else:
            self.logging.log_offset("GWorld", "Not Found")

if __name__ == "__main__":
    PalworldOffsets()
