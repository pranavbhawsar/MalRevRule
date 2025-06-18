rule bdcad3bd0023fcab3e03c7ab767f67f0c5763bb6d5a8da1a03a3b1ada3643889_exe_20250618 {
    meta:
        author = "Malware Analysis Tool"
        date = "2025-06-18"
        description = "Detects bdcad3bd0023fcab3e03c7ab767f67f0c5763bb6d5a8da1a03a3b1ada3643889.exe and potential variants, including Gh0st RAT"
    strings:
        $s1 = "GetTickCount64" nocase
        $s1_hex = {47 65 74 54 69 63 6B 43 6F 75 6E 74 36 34}
        $s2 = "CopyFileW" nocase
        $s2_hex = {43 6F 70 79 46 69 6C 65 57}
        $s3 = "https://www.dropbox.com/s/zhp1b06imehwylq/Synaptics.rar?dl=1" nocase
        $s3_hex = {68 74 74 70 73 3A 2F 2F 77 77 77 2E 64 72 6F 70 62 6F 78 2E 63 6F 6D 2F 73 2F 7A 68 70 31 62 30 36 69 6D 65 68 77 79 6C 71 2F 53 79 6E 61 70 74 69 63 73 2E 72 61 72 3F 64 6C 3D 31}
        $s4 = "CreateFileMappingA" nocase
        $s4_hex = {43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41}
        $s5 = "ShellExecuteExW" nocase
        $s5_hex = {53 68 65 6C 6C 45 78 65 63 75 74 65 45 78 57}
        $s6 = "This program must be run under Win32\r\n$7" nocase
        $s7 = "CODE" nocase
        $s8 = "`DATA" nocase
        $s9 = ".idata" nocase
        $s10 = ".tls" nocase
        $ip1 = "1.0.0.0"
        $ip2 = "1.0.0.4"
        $ip3 = "1.0.0.1"
        $ip4 = "3.3.14.2"
        $ip5 = "255.255.255.255"
        $domain1 = "malicious.example.com"
        $imp1 = "GetTickCount"
        $imp2 = "QueryPerformanceCounter"
        $imp3 = "GetProcAddress"
        $imp4 = "WriteFile"
        $imp5 = "ReadFile"
        $section1 = "CODE"
        $section2 = "DATA"
        $section3 = "BSS"
        $section4 = ".idata"
        $section5 = ".tls"
        $entry = { 558bec83c4f0b878a74900e898c1f6ff }
    condition:
        uint16(0) == 0x5A4D and (
2 of ($s*) or 1 of ($ip*) or 1 of ($domain*) or 2 of ($imp*) or #imp > 3 or $entry at entrypoint
        )