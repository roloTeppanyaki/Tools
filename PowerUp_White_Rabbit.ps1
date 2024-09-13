    [DllImport("advapi32.dll")]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID Luid);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
    
    [DllImport("advapi32.dll")]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll")]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, out TOKEN_TYPE TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("advapi32.dll")]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, out IMPERSONATION_LEVEL TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll")]
    public static extern bool GetTokenGroups(IntPtr TokenHandle, Int32 TokenInformationLength, ref TOKEN_GROUPS TokenInformation, out Int32 ReturnLength);
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern NtStatus RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, out bool Enabled);
' -Types $Types
HelperFunctions = @'
    private static TOKEN_PRIVILEGES GetTokenPrivileges() {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), (UInt32)Win32Constant.TOKEN_ADJUST_PRIVILEGES | (UInt32)Win32Constant.TOKEN_QUERY, out tokenHandle)) {
            throw new Win32Exception();
        }
        
        TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES() { PrivilegeCount = 1 };
        LUID luid;
        LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
        
        var attributes = new LUID_AND_ATTRIBUTES[] { new LUID_AND_ATTRIBUTES() { Attributes = (UInt32)Win32Constant.SE_PRIVILEGE_ENABLED, Luid = luid } };
        privileges.Privileges = attributes;
        
        int returnLengthInBytes;
        if (!AdjustTokenPrivileges(tokenHandle, false, ref privileges, 0, IntPtr.Zero, out returnLengthInBytes)) {
            throw new Win32Exception();
        }
        CloseHandle(tokenHandle);
        
        return privileges;
    }
    
    private static TOKEN_TYPE GetTokenType() {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), (UInt32)Win32Constant.TOKEN_QUERY, out tokenHandle)) {
            throw new Win32Exception();
        }
        
        TOKEN_TYPE type = new TOKEN_TYPE();
        int returnLength;
        if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenType, out type, Marshal.SizeOf(type), out returnLength)) {
            throw new Win32Exception();
        }
        
        CloseHandle(tokenHandle);
        
        return type;
    }
    
    private static IMPERSONATION_LEVEL GetTokenImpersonationLevel() {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), (UInt32)Win32Constant.TOKEN_QUERY, out tokenHandle)) {
            throw new Win32Exception();
        }
        
        IMPERSONATION_LEVEL impersonationLevel = new IMPERSONATION_LEVEL();
        int returnLength;
        if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, out impersonationLevel, Marshal.SizeOf(impersonationLevel), out returnLength)) {
            throw new Win32Exception();
        }
        
        CloseHandle(tokenHandle);
        
        return impersonationLevel;
    }
    
    private static TOKEN_GROUPS GetTokenGroups() {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), (UInt32)Win32Constant.TOKEN_QUERY, out tokenHandle)) {
            throw new Win32Exception();
        }
        
        TOKEN_GROUPS groups = new TOKEN_GROUPS();
        Int32 returnLength;
        if (!GetTokenGroups(tokenHandle, Marshal.SizeOf(groups), ref groups, out returnLength)) {
            throw new Win32Exception();
        }
        
        CloseHandle(tokenHandle);
        
        return groups;
    }
    
    public static void EnableDebugPrivilege() {
        var privileges = GetTokenPrivileges();
        bool enabled;
        RtlAdjustPrivilege((ulong)Win32Constant.SE_DEBUG_PRIVILEGE, true, false, out enabled);
    }
    
    public static TOKEN_TYPE GetProcessTokenType() {
        return GetTokenType();
    }
    
    public static IMPERSONATION_LEVEL GetProcessImpersonationLevel() {
        return GetTokenImpersonationLevel();
    }
    
    public static TOKEN_GROUPS GetProcessTokenGroup(string sid) {
        var groups = GetTokenGroups();
        
        for (int i = 0; i < groups.GroupCount; ++i) {
            var group = groups.Groups[i];
            
            try {
                SecurityIdentifier sidObj = new SecurityIdentifier(group.Sid, 0);
                
                if (!StringComparer.OrdinalIgnoreCase.Equals(sidObj.Value, sid)) {
                    continue;
                }
            } catch (Exception e) {
                // If we can't parse the SID as a SecurityIdentifier object, just move on to the next one.
                continue;
            }
            
            return groups;
        }
        
        return null;
    }
    
    public static void InvokePrivescAudit(string userSid) {
        if (!String.IsNullOrEmpty(userSid)) {
            var groups = GetProcessTokenGroup(userSid);
            
            if (groups == null) {
                Console.WriteLine("The specified SID is not part of the process token's groups.");
                return;
            }
        } else {
            Console.WriteLine("No user SID provided, skipping check for group membership.");
        }
        
        TOKEN_TYPE type = GetProcessTokenType();
        IMPERSONATION_LEVEL impersonationLevel = GetProcessImpersonationLevel();
        
        if (type.TokenType == (UInt32)TOKEN_TYPE_.TokenPrimary && impersonationLevel != 0) {
            Console.WriteLine("This process is running under an Impersonated token, which may be a security risk.");
        } else {
            Console.WriteLine("This process is running with the correct primary token and no impersonation.");
        }
    }
