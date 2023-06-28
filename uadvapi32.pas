unit uadvapi32;

{$Define UsePacked}

interface

uses
  Classes, SysUtils,windows,utils{,jwawincrypt};

const
  LOGON_WITH_PROFILE = $00000001;

  //https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto_system.h
  const
  MD4_DIGEST_LENGTH=	16;
  MD5_DIGEST_LENGTH=	16;
  SHA_DIGEST_LENGTH=	20;

  DES_KEY_LENGTH=	7;
  DES_BLOCK_LENGTH=	8;
  AES_128_KEY_LENGTH=	16;
  AES_256_KEY_LENGTH=	32;

  //https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/mimikatz/modules/kuhl_m_lsadump_struct.h
  SYSKEY_LENGTH	=16;
  SAM_KEY_DATA_SALT_LENGTH=	16 ;
  SAM_KEY_DATA_KEY_LENGTH=	16;

type
 tbyte16__=array[0..15] of byte;

type
   TIntegrityLevel = (UnknownIntegrityLevel=0, LowIntegrityLevel, MediumIntegrityLevel, HighIntegrityLevel, SystemIntegrityLevel);



function ImpersonateAsSystemW_Vista(IntegrityLevel: TIntegrityLevel;pid:cardinal): Boolean;

function impersonatepid(pid:dword):boolean;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString): LongWord;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;

//***************************************************************************


function CreateProcessWithLogonW(
  lpUsername,
  lpDomain,
  lpPassword:PWideChar;
  dwLogonFlags:dword;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation
): BOOL; stdcall; external 'advapi32.dll';


type
   MD4_CTX  = packed record
    _Buf    : array[0..3] of LongWord;
    _I      : array[0..1] of LongWord;
    input   : array[0..63] of byte;
    digest  : Array[0..MD4_DIGEST_LENGTH-1] of Byte;
   end;


//function MD4_Selftest:Boolean;


type
  MD5_DIG  = {$IfDef UsePacked} packed {$EndIf} array[0..15] of byte;
  MD5_CTX  = {$IfDef UsePacked} packed {$EndIf} record
    i:      Array[0.. 1] of LongWord;
    buf:    Array[0.. 3] of LongWord;
    input:  Array[0..63] of Byte;
    digest: MD5_DIG;
  End;

  type _CRYPTO_BUFFER = {packed} record
  	 Length:dword;
  	 MaximumLength:dword;
  	 Buffer:PBYTE;
  end;
  PCRYPTO_BUFFER=^_CRYPTO_BUFFER;
  PCCRYPTO_BUFFER=^_CRYPTO_BUFFER; //? to be verified...



//SystemFunction004
//extern NTSTATUS WINAPI RtlEncryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
//SystemFunction005  -> use to decrypt lsasecrets on NT5
//extern NTSTATUS WINAPI RtlDecryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
function RtlDecryptDESblocksECB(const data:_CRYPTO_BUFFER;const key:_CRYPTO_BUFFER;var output:_CRYPTO_BUFFER):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction005';
//SystemFunction032 or SystemFunction033?
//extern NTSTATUS WINAPI RtlEncryptDecryptRC4(IN OUT PCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key);
function RtlEncryptDecryptRC4(var  data:_CRYPTO_BUFFER;   const key:_CRYPTO_BUFFER):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction032';

//extern NTSTATUS WINAPI RtlDecryptDES2blocks1DWORD(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
function RtlDecryptDES2blocks1DWORD(const data:pointer; key:pdword;var output:array of byte):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction025';


// The MD5Init function initializes an MD5 message digest context.
procedure MD5Init(var ctx : MD5_CTX); stdcall;external 'advapi32.dll';
// The MD5Update function updates the MD5 context by using the supplied buffer for the message whose MD5 digest is being generated
procedure MD5Update(var ctx : MD5_CTX; const Buffer; const BufferSize : LongInt); stdcall;external 'advapi32.dll';
//The MD5Final function ends an MD5 message digest previously started by a call to the MD5Init function
procedure MD5Final(var ctx : MD5_CTX); stdcall;external 'advapi32.dll';
//function MD5string(const data : Ansistring):AnsiString;
//function MD5_Selftest:Boolean;

{lets go late binding
function CreateProcessWithTokenW(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;external 'advapi32.dll';
  }

  function RevertToSelf: BOOL; stdcall;external 'advapi32.dll';

//function ConvertStringSidToSidA(StringSid: LPCSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidW(StringSid: LPCWSTR; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll';
//function ConvertStringSidToSid(StringSid: LPCTSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidA(StringSid: pchar; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll';// name 'ConvertStringSidToSidA';

function ConvertSidToStringSidA(SID: PSID; var StringSid: pchar): Boolean; stdcall;
    external 'advapi32.dll';// name 'ConvertSidToStringSidA';
function ConvertSidToStringSidW(SID: PSID; var StringSid: pwidechar): Boolean; stdcall;
    external 'advapi32.dll';// name 'ConvertSidToStringSidA';

// SHA1

type
  SHA_CTX = packed record
   	Unknown : array[0..5] of LongWord;
	   State   : array[0..4] of LongWord;
	   Count   : array[0..1] of LongWord;
    	Buffer  : array[0..63] of Byte;
  end;

  SHA_DIG = packed record
	   Dig     : array[0..19] of Byte;
  end;

procedure A_SHAInit(var Context: SHA_CTX); StdCall;external 'advapi32.dll';
procedure A_SHAUpdate(var Context: SHA_CTX; const Input; inlen: LongWord); StdCall;external 'advapi32.dll';
procedure A_SHAFinal(var Context: SHA_CTX; out Digest:SHA_DIG); StdCall;external 'advapi32.dll';

//function SHA_Selftest:Boolean;

implementation

const
  LOW_INTEGRITY_SID: PWideChar = ('S-1-16-4096');
  MEDIUM_INTEGRITY_SID: PWideChar = ('S-1-16-8192');
  HIGH_INTEGRITY_SID: PWideChar = ('S-1-16-12288');
  SYSTEM_INTEGRITY_SID: PWideChar = ('S-1-16-16384');

  SE_GROUP_INTEGRITY = $00000020;

type
  _TOKEN_MANDATORY_LABEL = record
    Label_: SID_AND_ATTRIBUTES;
  end;
  TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL;
  PTOKEN_MANDATORY_LABEL = ^TOKEN_MANDATORY_LABEL;

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;  //2
    MaximumLength: USHORT; //2
    //in x64 an extra dword fiedl may be needed to align to 8 bytes !!!!!!!!!
    {$ifdef CPU64}dummy:dword; {$endif cpu64} //4
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;






function GetCurrUserName: string;
var
  Size              : DWORD;
begin
  Size := MAX_COMPUTERNAME_LENGTH + 1;
  SetLength(Result, Size);
  if GetUserName(PChar(Result), Size) then
    SetLength(Result, Size-1)
  else
    Result := '';
end;

function ImpersonateUser(const User, PW: string): Boolean;
var
 LogonType         : Integer;
 LogonProvider     : Integer;
 TokenHandle       : THandle;
 strAdminUser      : string;
 strAdminDomain    : string;
 strAdminPassword  : string;
begin
 LogonType := LOGON32_LOGON_INTERACTIVE;
 LogonProvider := LOGON32_PROVIDER_DEFAULT;
 strAdminUser := USER;
 strAdminDomain := '';
 strAdminPassword := PW;
 Result := LogonUser(PChar(strAdminUser), nil,
   PChar(strAdminPassword), LogonType, LogonProvider, TokenHandle);
 if Result then
 begin
   Result := ImpersonateLoggedOnUser(TokenHandle);
 end;
end;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString):
  LongWord;
var
  si           : TStartupInfoW;
  pif          : TProcessInformation;
begin
  //writeln(user+':'+pw);
  ZeroMemory(@si, sizeof(si));
  si.cb := sizeof(si);
  si.dwFlags := STARTF_USESHOWWINDOW;
  si.wShowWindow := 1;

  SetLastError(0);
  CreateProcessWithLogonW(PWideChar(User), nil, PWideChar(PW),
    LOGON_WITH_PROFILE, nil, PWideChar(Application+' "'+CmdLine+'"'),
    CREATE_DEFAULT_ERROR_MODE, nil, nil, @si, @pif);
  Result := GetLastError;
end;

function GetWinlogonProcessId: Cardinal;
begin
 //TBD
end;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;
type
  TCreateProcessWithTokenW=function(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
  CreateProcessWithTokenW:pointer;
begin
  Result := False;
  CreateProcessWithTokenW:=getprocaddress(loadlibrary('advapi32.dll'),'CreateProcessWithTokenW');
  if (@CreateProcessWithTokenW = nil) then
    Exit;
  try
    if pid=0
      then ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, GetWinlogonProcessId)
      else ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            //writeln('OpenProcessToken OK');
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                writeln('DuplicateTokenEx OK');
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  //writeln('GetTokenInformation OK');
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        //writeln('GetTokenInformation OK');
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := (SYSTEM_INTEGRITY_SID)
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := (HIGH_INTEGRITY_SID)
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := (MEDIUM_INTEGRITY_SID)
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := (LOW_INTEGRITY_SID);

                        writeln('IntegrityLevel: '+strpas(PIntegrityLevel));
                        if ConvertStringSidToSidw(PIntegrityLevel, Sid) then
                        begin
                          //writeln('ConvertStringSidToSidW OK');
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            Result := TCreateProcessWithTokenW(CreateProcessWithTokenW)(ImpersonateToken, 0, ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, @StartupInfo, @ProcessInformation);
                            //writeln(result);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function ImpersonateAsSystemW_Vista(IntegrityLevel: TIntegrityLevel;pid:cardinal): Boolean;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
  //
   StartInfo: TStartupInfoW;
  ProcInfo: TProcessInformation;
begin
  log('**** ImpersonateAsSystemW_Vista ****');
  Result := False;
  if (@ImpersonateLoggedOnUser = nil) then
    Exit;
  try
  ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        //writeln('IntegrityLevel: '+strpas(PIntegrityLevel));
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := SYSTEM_INTEGRITY_SID
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := HIGH_INTEGRITY_SID
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := MEDIUM_INTEGRITY_SID
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := LOW_INTEGRITY_SID;
                        if ConvertStringSidToSidW(PIntegrityLevel, Sid) then
                        begin
                          writeln('[+] IntegrityLevel: '+strpas(PIntegrityLevel));
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            {
                            FillChar(StartInfo, SizeOf(TStartupInfoW), #0);
                            FillChar(ProcInfo, SizeOf(TProcessInformation), #0);
                            StartInfo.cb := SizeOf(TStartupInfo);
                            StartInfo.lpDesktop := pwidechar(widestring('WinSta0\Default'));
                            Result := CreateProcessWithTokenW(ImpersonateToken, 0, '', widestring('c:\windows\system32\cmd.exe'), CREATE_NEW_PROCESS_GROUP or NORMAL_PRIORITY_CLASS, nil, nil, @StartInfo, @ProcInfo);
                            }
                            result:=ImpersonateLoggedOnUser (ImpersonateToken);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;


function impersonatepid(pid:dword):boolean;
var
  i:byte;
begin
log('**** impersonatepid ****');
log('pid:'+inttostr(pid));
if pid=0 then exit;
result:=false;
for i:=4 downto 0 do
  begin
  if ImpersonateAsSystemW_Vista (TIntegrityLevel(i),pid) then begin result:=true;exit;end;
  end;
end;


end.

