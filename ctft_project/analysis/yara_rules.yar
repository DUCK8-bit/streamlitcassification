/*
PyMal YARA Rules for Malware Detection
Custom rules for detecting suspicious patterns in PE files
*/

rule SuspiciousImports
{
    meta:
        description = "Detects suspicious Windows API imports commonly used in malware"
        author = "PyMal"
        date = "2024"
    
    strings:
        $create_remote_thread = "CreateRemoteThread"
        $virtual_alloc_ex = "VirtualAllocEx"
        $write_process_memory = "WriteProcessMemory"
        $open_process = "OpenProcess"
        $get_proc_address = "GetProcAddress"
        $load_library = "LoadLibrary"
        $url_download = "URLDownloadToFile"
        $internet_open = "InternetOpen"
        $reg_create_key = "RegCreateKey"
        $create_service = "CreateService"
    
    condition:
        any of them
}

rule NetworkActivity
{
    meta:
        description = "Detects network-related functions"
        author = "PyMal"
        date = "2024"
    
    strings:
        $connect = "connect"
        $send = "send"
        $recv = "recv"
        $socket = "socket"
        $bind = "bind"
        $listen = "listen"
        $accept = "accept"
        $gethostbyname = "gethostbyname"
        $dns_query = "DnsQuery"
    
    condition:
        any of them
}

rule ProcessInjection
{
    meta:
        description = "Detects process injection techniques"
        author = "PyMal"
        date = "2024"
    
    strings:
        $create_remote_thread = "CreateRemoteThread"
        $virtual_alloc_ex = "VirtualAllocEx"
        $write_process_memory = "WriteProcessMemory"
        $open_process = "OpenProcess"
        $nt_create_thread_ex = "NtCreateThreadEx"
        $nt_allocate_virtual_memory = "NtAllocateVirtualMemory"
        $nt_write_virtual_memory = "NtWriteVirtualMemory"
    
    condition:
        any of them
}

rule RegistryModification
{
    meta:
        description = "Detects registry modification functions"
        author = "PyMal"
        date = "2024"
    
    strings:
        $reg_create_key = "RegCreateKey"
        $reg_set_value = "RegSetValue"
        $reg_delete_key = "RegDeleteKey"
        $reg_open_key = "RegOpenKey"
        $reg_query_value = "RegQueryValue"
        $reg_enum_value = "RegEnumValue"
    
    condition:
        any of them
}

rule FileOperations
{
    meta:
        description = "Detects file system operations"
        author = "PyMal"
        date = "2024"
    
    strings:
        $create_file = "CreateFile"
        $write_file = "WriteFile"
        $read_file = "ReadFile"
        $delete_file = "DeleteFile"
        $copy_file = "CopyFile"
        $move_file = "MoveFile"
        $find_first_file = "FindFirstFile"
        $find_next_file = "FindNextFile"
    
    condition:
        any of them
}

rule AntiAnalysis
{
    meta:
        description = "Detects anti-analysis techniques"
        author = "PyMal"
        date = "2024"
    
    strings:
        $is_debugger_present = "IsDebuggerPresent"
        $check_remote_debugger = "CheckRemoteDebuggerPresent"
        $get_tick_count = "GetTickCount"
        $query_performance_counter = "QueryPerformanceCounter"
        $sleep = "Sleep"
        $get_system_time = "GetSystemTime"
    
    condition:
        any of them
}

rule EncryptionStrings
{
    meta:
        description = "Detects encryption-related strings"
        author = "PyMal"
        date = "2024"
    
    strings:
        $aes = "AES"
        $des = "DES"
        $rc4 = "RC4"
        $md5 = "MD5"
        $sha1 = "SHA1"
        $sha256 = "SHA256"
        $base64 = "Base64"
        $xor = "XOR"
    
    condition:
        any of them
}

rule SuspiciousStrings
{
    meta:
        description = "Detects suspicious strings commonly found in malware"
        author = "PyMal"
        date = "2024"
    
    strings:
        $cmd_exe = "cmd.exe"
        $powershell = "powershell"
        $wget = "wget"
        $curl = "curl"
        $nc = "nc"
        $netcat = "netcat"
        $reverse_shell = "reverse"
        $backdoor = "backdoor"
        $trojan = "trojan"
        $keylogger = "keylog"
        $spyware = "spy"
    
    condition:
        any of them
}

rule PackedExecutable
{
    meta:
        description = "Detects potential packed executables"
        author = "PyMal"
        date = "2024"
    
    strings:
        $upx = "UPX"
        $aspack = "ASPack"
        $upack = "UPack"
        $petite = "Petite"
        $nspack = "NSPack"
        $fsg = "FSG"
        $pecompact = "PECompact"
        $winupack = "WinUpack"
    
    condition:
        any of them
}

rule HighEntropySection
{
    meta:
        description = "Detects sections with high entropy (potential encryption/packing)"
        author = "PyMal"
        date = "2024"
    
    condition:
        // This is a placeholder - actual entropy calculation would be done in Python
        // YARA doesn't have built-in entropy calculation
        false
} 