import os
import json
import hashlib
import re
import logging
from datetime import datetime
import r2pipe
import pefile

# Setup logging
logging.basicConfig(filename=os.path.expanduser("~/Desktop/Tool/logs/analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

class ReverseEngineer:
    def __init__(self, binary_path, output_file):
        """Initialize the reverse engineer."""
        self.binary_path = os.path.expanduser(binary_path)
        self.output_file = os.path.expanduser(output_file)
        self.r2 = None
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def calculate_hashes(self):
        """Calculate MD5 and SHA256 hashes of the binary."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(self.binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return md5_hash.hexdigest(), sha256_hash.hexdigest()

    def get_file_type(self):
        """Get the file type using r2pipe."""
        try:
            file_info = json.loads(self.r2.cmd("iIj"))
            sections = self.extract_sections()
            subtype = "GUI" if file_info.get("class", "") == "PE32" else "Unknown"
            arch = "Intel 80386" if file_info.get("arch", "") == "x86" else file_info.get("arch", "")
            return f"{self.binary_path}: PE32 executable ({subtype}) {arch}, for MS Windows, {len(sections)} sections"
        except Exception as e:
            logging.error(f"Failed to get file type: {str(e)}")
            return f"{self.binary_path}: Unknown executable"

    def extract_disassembly(self):
        """Extract disassembly at the entry point using r2pipe."""
        try:
            # Get entry point
            info = json.loads(self.r2.cmd("iej"))
            entry = info[0]["vaddr"] if info else 0
            if not entry:
                # Fallback: Try to find the main function
                main_func = self.r2.cmd("agj main")
                if main_func and json.loads(main_func):
                    entry = json.loads(main_func)[0]["offset"]
                else:
                    logging.warning("Could not find entry point or main function")
                    return []
            # Seek to entry point and disassemble 20 instructions
            self.r2.cmd(f"s {entry}")
            disasm = self.r2.cmd("pd 20").splitlines()
            return [line.strip() for line in disasm if line.strip()]
        except Exception as e:
            logging.error(f"Failed to extract disassembly: {str(e)}")
            return []

    def extract_strings(self):
        """Extract all strings from the binary using r2pipe."""
        try:
            strings = json.loads(self.r2.cmd("izzj"))
            return [s["string"] for s in strings if "string" in s]
        except Exception as e:
            logging.error(f"Failed to extract strings: {str(e)}")
            return []

    def extract_suspicious_strings(self, strings):
        """Filter suspicious strings (e.g., related to registry, anti-debugging)."""
        suspicious_keywords = [
            # Registry Operations
            "RegCloseKey", "RegOpenKey", "RegCreateKey", "RegSaveKey", "RegDeleteKey", "RegSetValue", "RegQueryValue",
            # Anti-Debugging and Anti-Analysis
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "GetTickCount", 
            "QueryPerformanceCounter", "GetSystemInfo", "IsWow64Process", "NtQuerySystemInformation", 
            "CreateToolhelp32Snapshot", "Process32Next", "EnumProcesses",
            # Command Execution
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe",
            # Sensitive Data
            "password", "creditcard", "ssn", "keylogger", "credential",
            # Network Activity
            "http://", "https://", "ftp://", "socket", "connect", "send", "recv", "bind", "listen", 
            "gethostbyname", "InternetOpen", "InternetConnect", "HttpSendRequest", "Gh0st Update", 
            "Gh0st", "SugarGh0st", "HiddenGh0st", "Gh0stTimes", "Gh0stCringe", "Gh0stServer", "Gh0stClient", 
            "Gh0stMutex", "RemoteShell",
            # File System Manipulation
            "CryptEncrypt", "CryptDecrypt", "WriteFile", "DeleteFile", "MoveFile", "CopyFile", 
            "CreateFileMapping", "MapViewOfFile",
            # Privilege Escalation
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "SeDebugPrivilege", 
            "SeTcbPrivilege", "CreateService", "StartService",
            # Injection and Hooking
            "CreateRemoteThread", "WriteProcessMemory", "SetWindowsHookEx", "LoadLibrary", "GetProcAddress", 
            "OpenProcess", "QueueUserAPC",
            # Data Exfiltration
            "GetClipboardData", "SetClipboardData", "keybd_event", "mouse_event", "SendInput", 
            "GetAsyncKeyState", "GetForegroundWindow", "GetWindowText", "KeyLog", "ScreenCap", "WebCam",
            # Persistence
            "Run", "RunOnce", "Software\\Microsoft\\Windows\\CurrentVersion", "AppInit_DLLs", 
            "ShellExecute", "CreateScheduledTask", "SVCHOST.DLL", "svchost.exe", "Gh0stRat",
            # Miscellaneous
            "GetCurrentProcess", "TerminateProcess", "ExitWindows", "LockWorkStation", 
            "GetUserName", "GetComputerName", "GetLocalTime", "GetProcessHeap"
        ]
        return list(set(s for s in strings if any(keyword in s for keyword in suspicious_keywords)))

    def extract_imports(self):
        """Extract imports using r2pipe."""
        try:
            imports = json.loads(self.r2.cmd("iij"))
            return [imp["name"] for imp in imports if "name" in imp]
        except Exception as e:
            logging.error(f"Failed to extract imports: {str(e)}")
            return []

    def extract_suspicious_imports(self, imports):
        """Filter suspicious imports (e.g., anti-debugging, registry functions)."""
        suspicious_imports = [
            # Anti-Debugging and Anti-Analysis
            "GetTickCount", "Sleep", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", 
            "NtQueryInformationProcess", "QueryPerformanceCounter", "GetSystemInfo", 
            "IsWow64Process", "NtQuerySystemInformation", "CreateToolhelp32Snapshot", 
            "Process32Next", "EnumProcesses",
            # Network Activity
            "InternetOpenA", "InternetConnectA", "HttpSendRequestA", "connect", "send", 
            "recv", "bind", "listen", "gethostbyname", "WSAStartup", "socket", "sendto", "recvfrom",
            # File System Manipulation
            "CryptEncrypt", "CryptDecrypt", "WriteFile", "DeleteFile", "MoveFile", "CopyFile", 
            "CreateFileMappingA", "MapViewOfFile", "CreateFileA", "ReadFile",
            # Privilege Escalation
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", 
            "CreateServiceA", "StartServiceA",
            # Registry Operations
            "RegCreateKeyExA", "RegSetValueExA", "RegDeleteKeyA", "RegOpenKeyExA", 
            "RegQueryValueExA", "RegCreateKeyA",
            # Injection and Hooking
            "CreateRemoteThread", "WriteProcessMemory", "SetWindowsHookExA", "LoadLibraryA", 
            "GetProcAddress", "OpenProcess", "QueueUserAPC",
            # Data Exfiltration
            "GetClipboardData", "SetClipboardData", "keybd_event", "mouse_event", "SendInput", 
            "GetAsyncKeyState", "GetForegroundWindow", "GetWindowTextA", "waveInOpen", 
            "capCreateCaptureWindowA", "BitBlt", "GetDC",
            # Persistence
            "ShellExecuteA", "CreateScheduledTask",
            # Miscellaneous
            "GetCurrentProcess", "TerminateProcess", "ExitWindowsEx", "LockWorkStation", 
            "GetUserNameA", "GetComputerNameA", "GetLocalTime"
        ]
        return [imp for imp in imports if imp in suspicious_imports]

    def extract_iocs(self, strings):
        """Extract IOCs (URLs, IPs) from strings."""
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        url_pattern = r"(https?://[^\s]+)"
        
        ips = []
        urls = []
        for s in strings:
            found_ips = re.findall(ip_pattern, s)
            ips.extend(found_ips)
            found_urls = re.findall(url_pattern, s)
            urls.extend(found_urls)
        
        return {"urls": list(set(urls)), "ips": list(set(ips))}

    def extract_sections(self):
        """Extract sections and calculate entropy using r2pipe."""
        try:
            sections = json.loads(self.r2.cmd("iSj"))
            return [{"name": s["name"], "entropy": round(s.get("entropy", 6.0), 1)} for s in sections]
        except Exception as e:
            logging.error(f"Failed to extract sections: {str(e)}")
            return []

    def extract_entry_bytes(self):
        """Extract hex bytes at the entry point using r2pipe."""
        try:
            info = json.loads(self.r2.cmd("iej"))
            entry = info[0]["vaddr"] if info else 0
            if not entry:
                main_func = self.r2.cmd("agj main")
                if main_func and json.loads(main_func):
                    entry = json.loads(main_func)[0]["offset"]
                else:
                    logging.warning("Could not find entry point for entry bytes")
                    return ""
            self.r2.cmd(f"s {entry}")
            # Use 'pxj 16' to get hex bytes in JSON format
            bytes_data = json.loads(self.r2.cmd("pxj 16"))
            hex_bytes = "".join([f"{byte:02x}" for byte in bytes_data])
            return hex_bytes.lower()[:32]  # Ensure we get exactly 16 bytes (32 hex chars)
        except Exception as e:
            logging.error(f"Failed to extract entry bytes: {str(e)}")
            return ""

    def extract_functions(self):
        """Extract function names using r2pipe."""
        try:
            self.r2.cmd("aaaa")  # Deeper analysis
            functions = json.loads(self.r2.cmd("aflj"))
            return [f["name"] for f in functions if "name" in f]
        except Exception as e:
            logging.error(f"Failed to extract functions: {str(e)}")
            return []

    def extract_version_info(self):
        """Extract version information using pefile, with a fallback to parse from strings."""
        version_info = {
            "Comments": "",
            "CompanyName": "",
            "FileDescription": "",
            "FileVersion": "",
            "InternalName": "",
            "LegalCopyright": "",
            "LegalTrademarks": "",
            "OriginalFilename": "",
            "PrivateBuild": "",
            "ProductName": "",
            "ProductVersion": "",
            "SpecialBuild": ""
        }

        try:
            # First attempt: Parse using pefile
            pe = pefile.PE(self.binary_path)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
            ])

            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None and resource_type.name.string == b'VS_VERSION_INFO':
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                data = pe.get_data(data_rva, size)
                                if data.startswith(b'\x00\x01\x00\x00'):  # VS_VERSIONINFO signature
                                    pos = 44  # Skip VS_FIXEDFILEINFO
                                    while pos < len(data):
                                        key_len = int.from_bytes(data[pos:pos+2], byteorder='little')
                                        pos += 2
                                        if key_len == 0:
                                            break
                                        key = data[pos:pos+key_len*2].decode('utf-16le', errors='ignore').rstrip('\x00')
                                        pos += key_len * 2
                                        pos = (pos + 3) & ~3  # Align to 4-byte boundary
                                        if key == "StringFileInfo":
                                            pos += 4  # Skip value length and type
                                            while pos < len(data):
                                                table_len = int.from_bytes(data[pos:pos+2], byteorder='little')
                                                pos += 2
                                                if table_len == 0:
                                                    break
                                                pos += 4  # Skip value length and type
                                                pos += 8  # Skip lang-codepage
                                                table_end = pos + table_len - 14
                                                while pos < table_end:
                                                    str_len = int.from_bytes(data[pos:pos+2], byteorder='little')
                                                    pos += 2
                                                    if str_len == 0:
                                                        break
                                                    value_len = int.from_bytes(data[pos:pos+2], byteorder='little')
                                                    pos += 2
                                                    str_type = int.from_bytes(data[pos:pos+2], byteorder='little')
                                                    pos += 2
                                                    key_str = data[pos:pos+str_len*2].decode('utf-16le', errors='ignore').rstrip('\x00')
                                                    pos += str_len * 2
                                                    pos = (pos + 3) & ~3  # Align to 4-byte boundary
                                                    if str_type == 1 and value_len > 0:
                                                        value_str = data[pos:pos+value_len*2].decode('utf-16le', errors='ignore').rstrip('\x00')
                                                        pos += value_len * 2
                                                        pos = (pos + 3) & ~3  # Align to 4-byte boundary
                                                        if key_str in version_info:
                                                            version_info[key_str] = value_str
                                                    else:
                                                        pos += value_len * 2
                                                        pos = (pos + 3) & ~3  # Align to 4-byte boundary
            else:
                logging.warning("No resource directory found in PE file")

            # Fallback: If pefile fails, parse from strings
            if not any(version_info.values()):
                logging.info("Falling back to parsing version info from strings")
                strings = self.extract_strings()
                version_block = None
                current_field = None
                for i, s in enumerate(strings):
                    if s == "VS_VERSION_INFO":
                        version_block = {}
                    elif version_block is not None:
                        if s in version_info:
                            current_field = s
                        elif current_field and s not in ["StringFileInfo", "080404b0", "arFileInfo", "Translation"]:
                            # Handle typos in field names (e.g., "egalTrademarks")
                            if current_field == "LegalTrademarks" and s.startswith("?"):
                                version_block[current_field] = s.replace("egalTrademarks", "").strip()
                            else:
                                version_block[current_field] = s
                        if s == "arFileInfo" or (i + 1 < len(strings) and strings[i + 1] == "VS_VERSION_INFO"):
                            # End of a version block
                            # Check if this block is relevant (prefer "SogouPY Config" over "SogouPY SogouTSF")
                            if "InternalName" in version_block and version_block["InternalName"] == "SogouPY Config":
                                version_info.update(version_block)
                            elif not any(version_info.values()):  # Use the first block if nothing better is found
                                version_info.update(version_block)
                            version_block = None
                            current_field = None

            # Log the extracted version info for debugging
            logging.info(f"Extracted version_info: {version_info}")

            return version_info
        except Exception as e:
            logging.error(f"Failed to extract version info: {str(e)}")
            return {
                "Comments": "",
                "CompanyName": "",
                "FileDescription": "",
                "FileVersion": "",
                "InternalName": "",
                "LegalCopyright": "",
                "LegalTrademarks": "",
                "OriginalFilename": "",
                "PrivateBuild": "",
                "ProductName": "",
                "ProductVersion": "",
                "SpecialBuild": ""
            }

    def extract_origin(self, version_info, strings):
        """Determine the possible origin of the binary."""
        company = version_info.get("CompanyName", "")
        possible_country = "Unknown"
        indicators = []

        # Check for Chinese characters (Unicode range for CJK Unified Ideographs)
        for s in strings:
            if any(0x4E00 <= ord(char) <= 0x9FFF for char in s if len(char) == 1):
                possible_country = "China"
                indicators.append("Chinese characters in strings")
                break

        # Check for company name indicating origin
        if "Sogou" in company:
            possible_country = "China"
            indicators.append("Company associated with China (Sogou.com Inc.)")

        return {
            "possible_country": possible_country,
            "company": company,
            "indicators": indicators
        }

    def check_for_packing(self):
        """Check if the binary is packed using pefile."""
        try:
            pe = pefile.PE(self.binary_path)
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if "UPX" in section_name:
                    logging.warning("Binary appears to be packed with UPX")
                    return True
                entropy = section.get_entropy()
                if entropy > 7.0:
                    logging.warning(f"High entropy section detected ({section_name}): {entropy}")
                    return True
            return False
        except Exception as e:
            logging.error(f"Failed to check for packing: {str(e)}")
            return False

    def analyze(self):
        """Perform static analysis on the binary."""
        try:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd("e anal.timeout=60")
            self.r2.cmd("e io.va=true")
            
            if self.check_for_packing():
                logging.info("Attempting to unpack binary for analysis")
                self.r2.cmd("aaaa")
            else:
                self.r2.cmd("aaa")

            size = os.path.getsize(self.binary_path)
            md5, sha256 = self.calculate_hashes()
            file_type = self.get_file_type()
            disassembly = self.extract_disassembly()
            strings = self.extract_strings()
            suspicious_strings = self.extract_suspicious_strings(strings)
            imports = self.extract_imports()
            suspicious_imports = self.extract_suspicious_imports(imports)
            iocs = self.extract_iocs(strings)
            sections = self.extract_sections()
            entry_bytes = self.extract_entry_bytes()
            functions = self.extract_functions()
            version_info = self.extract_version_info()
            origin = self.extract_origin(version_info, strings)
            analysis_timestamp = datetime.now().isoformat()

            results = {
                "filename": os.path.basename(self.binary_path),
                "size": size,
                "type": file_type,
                "md5": md5,
                "sha256": sha256,
                "disassembly": disassembly,
                "strings": strings,
                "suspicious_strings": suspicious_strings,
                "imports": imports,
                "suspicious_imports": suspicious_imports,
                "functions": functions,
                "iocs": iocs,
                "sections": sections,
                "entry_bytes": entry_bytes,
                "version_info": version_info,
                "origin": origin,
                "analysis_timestamp": analysis_timestamp
            }

            with open(self.output_file, "w") as f:
                json.dump(results, f, indent=4)
            logging.info(f"Static analysis completed: {self.output_file}")

            return {"success": True, "output_file": self.output_file}

        except Exception as e:
            logging.error(f"Static analysis failed: {str(e)}")
            return {"success": False, "error": str(e)}

        finally:
            if self.r2:
                self.r2.quit()

def perform_static_analysis(binary_path, output_file):
    """Entry point for static analysis."""
    engineer = ReverseEngineer(binary_path, output_file)
    return engineer.analyze()

if __name__ == "__main__":
    binary = "~/Desktop/Tool/input/sample.exe"
    output = "~/Desktop/Tool/output/sample_analysis.json"
    result = perform_static_analysis(binary, output)
    if result["success"]:
        print(f"Static analysis completed: {result['output_file']}")
    else:
        print(f"Static analysis failed: {result['error']}")
