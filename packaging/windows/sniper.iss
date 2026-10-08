#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef BinaryDirectory
  #error BinaryDirectory is required
#endif
#ifndef OutputDirectory
  #error OutputDirectory is required
#endif
#ifndef AppArch
  #define AppArch "x64"
#endif

[Setup]
AppId={{60385186-2538-4DB3-9505-2F05F9BD8454}
AppName=Sniper
AppVersion={#AppVersion}
AppPublisher=Sniper
DefaultDirName={localappdata}\Programs\Sniper
DefaultGroupName=Sniper
PrivilegesRequired=lowest
#if AppArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
MinVersion=10.0
OutputDir={#OutputDirectory}
OutputBaseFilename=Sniper-{#AppVersion}-windows-{#AppArch}-setup
SetupIconFile=sniper.ico
UninstallDisplayIcon={app}\sniper-desktop.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
#if FileExists(SourcePath + "..\..\LICENSE")
LicenseFile=..\..\LICENSE
#endif
InfoBeforeFile=README.md

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "clipath"; Description: "Add the bundled sniper-cli to my user PATH (new terminals only)"; Flags: unchecked checkedonce

[Files]
Source: "{#BinaryDirectory}\sniper-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinaryDirectory}\sniper.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinaryDirectory}\sniper-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
#if FileExists(SourcePath + "..\..\LICENSE")
Source: "..\..\LICENSE"; DestDir: "{app}"
#endif
Source: "README.md"; DestDir: "{app}"
; Setup owns this marker, so cancellation/rollback and uninstall handle it with
; the app files. Portable ZIPs intentionally do not contain it.
Source: "installed-by-setup.txt"; DestDir: "{app}"; DestName: ".sniper-installed"; Flags: ignoreversion

[Icons]
Name: "{group}\Sniper"; Filename: "{app}\sniper-desktop.exe"
Name: "{autodesktop}\Sniper"; Filename: "{app}\sniper-desktop.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\sniper-desktop.exe"; Description: "Launch Sniper"; Flags: nowait postinstall skipifsilent

; Session data and user-installed CA trust are intentionally outside the installer.

[Code]
const
  CliPathKey = 'Software\Sniper\CliPath';
  CliPathMutexName = 'Local\SniperCliPathRegistration';
  EnvironmentKey = 'Environment';
  MachineEnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  RegSz = 1;
  RegExpandSz = 2;
  ErrorFileNotFound = 2;
  KeyQueryValue64 = $0101;
  WaitObject0 = 0;
  WaitAbandoned = $80;

function OpenPathRegistryKey(Root: THandle; SubKey: String;
  Options, Access: Cardinal; var Handle: THandle): Longint;
  external 'RegOpenKeyExW@advapi32.dll stdcall';
function ClosePathRegistryKey(Handle: THandle): Longint;
  external 'RegCloseKey@advapi32.dll stdcall';
function QueryRegistryStringSize(Handle: THandle; ValueName: String;
  Reserved: THandle; var ValueType: Cardinal; Data: THandle;
  var DataSize: Cardinal): Longint;
  external 'RegQueryValueExW@advapi32.dll stdcall';
function QueryRegistryStringData(Handle: THandle; ValueName: String;
  Reserved: THandle; var ValueType: Cardinal; Data: String;
  var DataSize: Cardinal): Longint;
  external 'RegQueryValueExW@advapi32.dll stdcall';
function ExpandWindowsEnvironment(Source, Destination: String;
  Size: Cardinal): Cardinal;
  external 'ExpandEnvironmentStringsW@kernel32.dll stdcall';
function CreateCliPathMutex(Attributes: THandle; InitialOwner: Boolean;
  Name: String): THandle;
  external 'CreateMutexW@kernel32.dll stdcall';
function WaitForCliPathMutex(Handle: THandle; Milliseconds: Cardinal): Cardinal;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function ReleaseCliPathMutex(Handle: THandle): Boolean;
  external 'ReleaseMutex@kernel32.dll stdcall';
function CloseCliPathMutex(Handle: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';
function BroadcastPathChange(Window: THandle; Message: Cardinal; WParam: THandle;
  LParam: String; Flags, Timeout: Cardinal; var MessageResult: THandle): THandle;
  external 'SendMessageTimeoutW@user32.dll stdcall';

procedure NotifyPathChange;
var
  Ignored: THandle;
begin
  { ssPostInstall may follow Inno's ChangesEnvironment notification. Notify
    after our own write too, including successful uninstall cleanup. }
  BroadcastPathChange($FFFF, $001A, 0, 'Environment', $0002, 1000, Ignored);
end;

function ReadRawPath(Root: THandle; Key: String; var Present: Boolean;
  var Value: String; var ValueType: Cardinal): Boolean;
var
  Status: Longint;
  Handle: THandle;
  Size, Capacity: Cardinal;
  Buffer: String;
begin
  Result := False;
  Present := False;
  Value := '';
  ValueType := RegExpandSz;
  Status := OpenPathRegistryKey(Root, Key, 0, KeyQueryValue64, Handle);
  if Status = ErrorFileNotFound then begin
    Result := True;
    Exit;
  end;
  if Status <> 0 then
    Exit;
  try
    Size := 0;
    Status := QueryRegistryStringSize(Handle, 'Path', 0, ValueType, 0, Size);
    if Status = ErrorFileNotFound then begin
      ValueType := RegExpandSz;
      Result := True;
      Exit;
    end;
    if (Status <> 0) or (Size < 2) or (Size > 65534) or (Size mod 2 <> 0) then
      Exit;
    Capacity := Size;
    SetLength(Buffer, Capacity div 2);
    { RegQueryValueEx preserves raw bytes, including malformed terminators,
      unlike RegGetValue which can silently add a missing NUL. }
    Status := QueryRegistryStringData(Handle, 'Path', 0, ValueType, Buffer, Size);
    if (Status <> 0) or (Size < 2) or (Size > Capacity) or (Size mod 2 <> 0) then
      Exit;
    if (ValueType <> RegSz) and (ValueType <> RegExpandSz) then
      Exit;
    if Buffer[Size div 2] <> #0 then
      Exit;
    Value := Copy(Buffer, 1, (Size div 2) - 1);
    { Do not rewrite malformed values whose raw bytes cannot be preserved. }
    if Pos(#0, Value) <> 0 then
      Exit;
    Present := True;
    Result := True;
  finally
    ClosePathRegistryKey(Handle);
  end;
end;

function TryExpandPathForComparison(Value: String; ExpandVariables: Boolean;
  var ExpandedValue: String): Boolean;
var
  Required, Written: Cardinal;
  Buffer: String;
begin
  Result := False;
  ExpandedValue := '';
  if not ExpandVariables then begin
    ExpandedValue := Value;
    Result := True;
    Exit;
  end;
  Required := ExpandWindowsEnvironment(Value, '', 0);
  if (Required = 0) or (Required > 32767) then
    Exit;
  SetLength(Buffer, Required);
  Written := ExpandWindowsEnvironment(Value, Buffer, Required);
  if (Written = 0) or (Written > Required) then
    Exit;
  if Buffer[Written] <> #0 then
    Exit;
  ExpandedValue := Copy(Buffer, 1, Written - 1);
  Result := True;
end;

function NormalizePathDirectory(Value: String): String;
begin
  Result := Trim(Value);
  if (Length(Result) >= 2) and (Result[1] = '"') and
     (Result[Length(Result)] = '"') then
    Result := Copy(Result, 2, Length(Result) - 2);
  StringChangeEx(Result, '/', '\', True);
  while (Length(Result) > 3) and (Result[Length(Result)] = '\') do
    Delete(Result, Length(Result), 1);
  Result := Lowercase(Result);
end;

function NextPathSeparator(Path: String): Integer;
var
  Index: Integer;
  Quoted: Boolean;
begin
  Result := 0;
  Quoted := False;
  for Index := 1 to Length(Path) do begin
    if Path[Index] = '"' then
      Quoted := not Quoted
    else if (Path[Index] = ';') and not Quoted then begin
      Result := Index;
      Exit;
    end;
  end;
end;

function PathHasSupportedQuoting(Path: String): Boolean;
var
  Separator: Integer;
  Entry: String;
begin
  Result := False;
  repeat
    Separator := NextPathSeparator(Path);
    if Separator = 0 then
      Entry := Trim(Path)
    else
      Entry := Trim(Copy(Path, 1, Separator - 1));
    { Windows permits quoted directories containing semicolons. Accept those,
      but refuse malformed or mixed quoting rather than miss a CLI conflict. }
    if Pos('"', Entry) <> 0 then begin
      if Length(Entry) < 2 then
        Exit;
      if (Entry[1] <> '"') or (Entry[Length(Entry)] <> '"') then
        Exit;
      if Pos('"', Copy(Entry, 2, Length(Entry) - 2)) <> 0 then
        Exit;
    end;
    if Separator = 0 then begin
      Result := True;
      Exit;
    end;
    Delete(Path, 1, Separator);
  until False;
end;

function PathHasDirectory(Path, Directory: String): Boolean;
var
  Separator: Integer;
  Entry: String;
begin
  Result := False;
  Directory := NormalizePathDirectory(Directory);
  repeat
    Separator := NextPathSeparator(Path);
    if Separator = 0 then
      Entry := Path
    else
      Entry := Copy(Path, 1, Separator - 1);
    if (Entry <> '') and (NormalizePathDirectory(Entry) = Directory) then begin
      Result := True;
      Exit;
    end;
    if Separator = 0 then
      Exit;
    Delete(Path, 1, Separator);
  until False;
end;

function CliExtensionsAreSafe(Extensions: String): Boolean;
var
  Separator, Index: Integer;
  Extension: String;
begin
  Result := False;
  repeat
    Separator := Pos(';', Extensions);
    if Separator = 0 then
      Extension := Trim(Extensions)
    else
      Extension := Trim(Copy(Extensions, 1, Separator - 1));
    if Extension <> '' then begin
      if (Length(Extension) < 2) or (Extension[1] <> '.') then
        Exit;
      for Index := 2 to Length(Extension) do
        { Pascal Script does not accept set-range literals. Keep the same
          ASCII-only extension policy with ordinary character comparisons. }
        if not (((Extension[Index] >= 'a') and (Extension[Index] <= 'z')) or
          ((Extension[Index] >= 'A') and (Extension[Index] <= 'Z')) or
          ((Extension[Index] >= '0') and (Extension[Index] <= '9'))) then
          Exit;
    end;
    if Separator = 0 then begin
      Result := True;
      Exit;
    end;
    Delete(Extensions, 1, Separator);
  until False;
end;

function DirectoryHasOtherCli(Directory: String; AllowBundledExe: Boolean): Boolean;
var
  Separator: Integer;
  Extensions, Extension: String;
begin
  Result := False;
  { Always check the usual executable types, plus this user's safe PATHEXT
    entries. The bundled .exe is the only permitted same-name sibling. }
  Extensions := '.exe;.com;.bat;.cmd;' + GetEnv('PATHEXT');
  repeat
    Separator := Pos(';', Extensions);
    if Separator = 0 then
      Extension := Lowercase(Trim(Extensions))
    else
      Extension := Lowercase(Trim(Copy(Extensions, 1, Separator - 1)));
    if (Extension <> '') and not (AllowBundledExe and (Extension = '.exe')) then begin
      if FileExists(AddBackslash(Directory) + 'sniper-cli' + Extension) then begin
        Result := True;
        Exit;
      end;
    end;
    if Separator = 0 then
      Exit;
    Delete(Extensions, 1, Separator);
  until False;
end;

function PathHasOtherCli(Path, Directory: String): Boolean;
var
  Separator: Integer;
  Entry: String;
begin
  Result := False;
  Directory := NormalizePathDirectory(Directory);
  repeat
    Separator := NextPathSeparator(Path);
    if Separator = 0 then
      Entry := Path
    else
      Entry := Copy(Path, 1, Separator - 1);
    Entry := NormalizePathDirectory(Entry);
    if (Entry <> '') and (Entry <> Directory) then begin
      if DirectoryHasOtherCli(Entry, False) then begin
        Result := True;
        Exit;
      end;
    end;
    if Separator = 0 then
      Exit;
    Delete(Path, 1, Separator);
  until False;
end;

function AppendCliDirectory(BeforePath, Directory: String): String;
begin
  if BeforePath = '' then
    Result := Directory
  else
    Result := BeforePath + ';' + Directory;
end;

function WriteRawUserPath(Value: String; ValueType: Cardinal): Boolean;
begin
  if ValueType = RegSz then
    Result := RegWriteStringValue(HKCU, EnvironmentKey, 'Path', Value)
  else if ValueType = RegExpandSz then
    Result := RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Value)
  else
    Result := False;
end;

function LockCliPath(var Handle: THandle): Boolean;
var
  Status: Cardinal;
begin
  Result := False;
  Handle := CreateCliPathMutex(0, False, CliPathMutexName);
  if Handle = 0 then
    Exit;
  Status := WaitForCliPathMutex(Handle, 5000);
  Result := (Status = WaitObject0) or (Status = WaitAbandoned);
  if not Result then begin
    CloseCliPathMutex(Handle);
    Handle := 0;
  end;
end;

procedure UnlockCliPath(Handle: THandle);
begin
  ReleaseCliPathMutex(Handle);
  CloseCliPathMutex(Handle);
end;

procedure ReportCliPathIssue(Message: String);
begin
  Log('Optional CLI PATH: ' + Message);
  if not WizardSilent then
    MsgBox(Message + #13#10#13#10 +
      'Sniper is installed. You can still run the bundled sniper-cli.exe from the installation folder.',
      mbInformation, MB_OK);
end;

function SaveCliPathOwnership(Directory, BeforePath, AfterPath: String;
  ValueType: Cardinal; BeforePresent: Boolean): Boolean;
var
  PresentValue: Cardinal;
begin
  { The caller checked that this key does not exist. Publish the schema last,
    and finish the complete record before touching PATH. Runtime uses this
    same HKCU64 record and mutex; neither side claims pre-existing entries. }
  PresentValue := 0;
  if BeforePresent then
    PresentValue := 1;
  Result := RegWriteStringValue(HKCU64, CliPathKey, 'Directory', Directory) and
    RegWriteStringValue(HKCU64, CliPathKey, 'OwnerExecutable',
      AddBackslash(Directory) + 'sniper-desktop.exe') and
    RegWriteStringValue(HKCU64, CliPathKey, 'BeforePath', BeforePath) and
    RegWriteStringValue(HKCU64, CliPathKey, 'AfterPath', AfterPath) and
    RegWriteDWordValue(HKCU64, CliPathKey, 'PathType', ValueType) and
    RegWriteDWordValue(HKCU64, CliPathKey, 'BeforePresent', PresentValue) and
    RegWriteDWordValue(HKCU64, CliPathKey, 'SchemaVersion', 1);
  if not Result then
    RegDeleteKeyIncludingSubkeys(HKCU64, CliPathKey);
end;

procedure AddBundledCliToPath;
var
  Handle: THandle;
  Present, MachinePresent, CheckPresent, Changed: Boolean;
  ValueType, MachineType, CheckType: Cardinal;
  BeforePath, AfterPath, MachinePath, Directory, CheckPath: String;
  UserSearchPath, MachineSearchPath: String;
begin
  Changed := False;
  if not LockCliPath(Handle) then begin
    ReportCliPathIssue('The CLI PATH setting is busy. Your PATH was not changed.');
    Exit;
  end;
  try
    Directory := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
    if not ReadRawPath(HKCU, EnvironmentKey, Present, BeforePath, ValueType) or
       not ReadRawPath(HKLM, MachineEnvironmentKey, MachinePresent, MachinePath, MachineType) then begin
      ReportCliPathIssue('The existing PATH could not be read safely. Your PATH was not changed.');
      Exit;
    end;
    if not TryExpandPathForComparison(BeforePath, ValueType = RegExpandSz, UserSearchPath) or
       not TryExpandPathForComparison(MachinePath, MachineType = RegExpandSz, MachineSearchPath) then begin
      ReportCliPathIssue('The effective PATH could not be read safely. Your PATH was not changed.');
      Exit;
    end;
    if not PathHasSupportedQuoting(UserSearchPath) or
       not PathHasSupportedQuoting(MachineSearchPath) or
       not PathHasSupportedQuoting(GetEnv('PATH')) then begin
      ReportCliPathIssue('Existing PATH quoting could not be read safely. Your PATH was not changed.');
      Exit;
    end;
    if not CliExtensionsAreSafe(GetEnv('PATHEXT')) then begin
      ReportCliPathIssue('Existing command extensions could not be checked safely. Your PATH was not changed.');
      Exit;
    end;
    if PathHasDirectory(UserSearchPath, Directory) or
       PathHasDirectory(MachineSearchPath, Directory) then begin
      Log('Optional CLI PATH: installation folder is already present; no ownership claimed.');
      Exit;
    end;
    if RegKeyExists(HKCU64, CliPathKey) then begin
      ReportCliPathIssue('An existing CLI PATH ownership record needs review. Your PATH was not changed.');
      Exit;
    end;
    if (Pos(';', Directory) <> 0) or (Pos(#13, Directory) <> 0) or
       (Pos(#10, Directory) <> 0) or
       ((ValueType = RegExpandSz) and (Pos('%', Directory) <> 0)) then begin
      ReportCliPathIssue('This installation folder cannot be represented safely in PATH. Your PATH was not changed.');
      Exit;
    end;
    if DirectoryHasOtherCli(Directory, True) or
       PathHasOtherCli(MachineSearchPath, Directory) or
       PathHasOtherCli(UserSearchPath, Directory) or
       PathHasOtherCli(GetEnv('PATH'), Directory) then begin
      ReportCliPathIssue('Another sniper-cli command is on PATH or in the installation folder. It was left unchanged, and this copy was not added.');
      Exit;
    end;
    AfterPath := AppendCliDirectory(BeforePath, Directory);
    if Length(AfterPath) > 32766 then begin
      ReportCliPathIssue('The resulting PATH would be too long. Your PATH was not changed.');
      Exit;
    end;
    if not FileExists(AddBackslash(Directory) + 'sniper-cli.exe') then begin
      ReportCliPathIssue('The bundled CLI is unavailable. Your PATH was not changed.');
      Exit;
    end;
    if not SaveCliPathOwnership(Directory, BeforePath, AfterPath, ValueType, Present) then begin
      ReportCliPathIssue('CLI PATH ownership could not be saved. Your PATH was not changed.');
      Exit;
    end;
    { Re-read immediately before writing in case another program changed PATH.
      The mutex coordinates Sniper, but cannot lock other environment editors. }
    if not ReadRawPath(HKCU, EnvironmentKey, CheckPresent, CheckPath, CheckType) or
       (CheckPresent <> Present) or (CheckPath <> BeforePath) or (CheckType <> ValueType) then begin
      RegDeleteKeyIncludingSubkeys(HKCU64, CliPathKey);
      ReportCliPathIssue('PATH changed while Setup was running. Your PATH was not changed by Setup.');
      Exit;
    end;
    if not WriteRawUserPath(AfterPath, ValueType) then begin
      RegDeleteKeyIncludingSubkeys(HKCU64, CliPathKey);
      ReportCliPathIssue('The CLI could not be added to PATH. Your existing PATH was preserved.');
      Exit;
    end;
    Changed := True;
    Log('Optional CLI PATH: added the bundled CLI for new terminals.');
  finally
    UnlockCliPath(Handle);
    if Changed then
      NotifyPathChange;
  end;
end;

procedure RemoveOwnedCliPath;
var
  Handle: THandle;
  Schema, ValueType, CurrentType, BeforePresent: Cardinal;
  CurrentPresent, Removed: Boolean;
  Directory, Owner, BeforePath, AfterPath, CurrentPath, ThisDirectory: String;
  BeforeSearchPath: String;
begin
  Removed := False;
  if not LockCliPath(Handle) then begin
    Log('CLI PATH cleanup skipped because the setting is busy.');
    Exit;
  end;
  try
    if not RegQueryDWordValue(HKCU64, CliPathKey, 'SchemaVersion', Schema) or
       not RegQueryStringValue(HKCU64, CliPathKey, 'Directory', Directory) or
       not RegQueryStringValue(HKCU64, CliPathKey, 'OwnerExecutable', Owner) or
       not RegQueryStringValue(HKCU64, CliPathKey, 'BeforePath', BeforePath) or
       not RegQueryStringValue(HKCU64, CliPathKey, 'AfterPath', AfterPath) or
       not RegQueryDWordValue(HKCU64, CliPathKey, 'PathType', ValueType) or
       not RegQueryDWordValue(HKCU64, CliPathKey, 'BeforePresent', BeforePresent) then
      Exit;
    ThisDirectory := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
    if (Schema <> 1) or (BeforePresent > 1) or
       ((ValueType <> RegSz) and (ValueType <> RegExpandSz)) or
       (NormalizePathDirectory(Directory) <> NormalizePathDirectory(ThisDirectory)) or
       (CompareText(Owner, AddBackslash(ThisDirectory) + 'sniper-desktop.exe') <> 0) or
       ((BeforePresent = 0) and (BeforePath <> '')) or
       (AfterPath <> AppendCliDirectory(BeforePath, Directory)) then
      Exit;
    if not TryExpandPathForComparison(BeforePath, ValueType = RegExpandSz, BeforeSearchPath) then
      Exit;
    if not PathHasSupportedQuoting(BeforeSearchPath) or
       PathHasDirectory(BeforeSearchPath, Directory) then
      Exit;
    if not ReadRawPath(HKCU, EnvironmentKey, CurrentPresent, CurrentPath, CurrentType) then
      Exit;
    { A changed snapshot invalidates ownership. Never remove a manually added
      entry or clobber edits made since registration, even unrelated additions. }
    if not CurrentPresent or (CurrentPath <> AfterPath) or (CurrentType <> ValueType) then begin
      Log('CLI PATH cleanup skipped: PATH changed after registration; leaving it untouched.');
      Exit;
    end;
    if BeforePresent = 1 then
      Removed := WriteRawUserPath(BeforePath, ValueType)
    else
      Removed := RegDeleteValue(HKCU, EnvironmentKey, 'Path');
    if Removed then
      RegDeleteKeyIncludingSubkeys(HKCU64, CliPathKey);
  finally
    UnlockCliPath(Handle);
    if Removed then
      NotifyPathChange;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  { No environment or ownership changes before a successful installation. }
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('clipath') then
    AddBundledCliToPath;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { The user has confirmed uninstall by this point; canceling earlier is inert. }
  if CurUninstallStep = usUninstall then
    RemoveOwnedCliPath;
end;
