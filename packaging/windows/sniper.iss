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
UninstallDisplayIcon={app}\sniper-desktop.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
#if FileExists(SourcePath + "..\..\LICENSE")
LicenseFile=..\..\LICENSE
#endif
InfoBeforeFile=README.md

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#BinaryDirectory}\sniper-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinaryDirectory}\sniper.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinaryDirectory}\sniper-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
#if FileExists(SourcePath + "..\..\LICENSE")
Source: "..\..\LICENSE"; DestDir: "{app}"
#endif
Source: "README.md"; DestDir: "{app}"

[Icons]
Name: "{group}\Sniper"; Filename: "{app}\sniper-desktop.exe"
Name: "{autodesktop}\Sniper"; Filename: "{app}\sniper-desktop.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\sniper-desktop.exe"; Description: "Launch Sniper"; Flags: nowait postinstall skipifsilent

; Session data and user-installed CA trust are intentionally outside the installer.
