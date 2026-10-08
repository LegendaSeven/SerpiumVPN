; Full SerpiumVPN installer. Inno owns the primary installation.
; In-app patches are applied later by SerpiumUpdater.exe from GitHub Releases.

#define MyAppName "SerpiumVPN"
#ifndef MyAppVersion
#define MyAppVersion "1.0.56.8"
#endif
#define MyAppPublisher "Serpium"
#define ProjectRoot AddBackslash(SourcePath) + ".."
#define SourceDir ProjectRoot + "\publish\app"

[Setup]
AppId={{9F8E7D6C-5B4A-3C2B-1A0F-EEDDCCBBAA99}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SerpiumVPN
DefaultGroupName=SerpiumVPN
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#ProjectRoot}\publish\installer
OutputBaseFilename=SerpiumVPN_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#ProjectRoot}\Assets\Serpium.App.ico
UninstallDisplayIcon={app}\Assets\Serpium.App.ico
CloseApplications=yes
CloseApplicationsFilter=SerpiumVPN.exe,SerpiumUpdater.exe
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\SerpiumVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\SerpiumUpdater.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*"; Excludes: "bin_files,SerpiumVPN.exe,SerpiumUpdater.exe,*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\bin_files\relay\*"; Excludes: "logs\*,state\*,cache\*,temp\*,tmp\*,*.log,*.tmp"; DestDir: "{app}\bin_files\relay"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Dirs]
Name: "{app}\licenses"
Name: "{app}\bin_files\logs"

[Icons]
Name: "{group}\SerpiumVPN"; Filename: "{app}\SerpiumVPN.exe"; IconFilename: "{app}\Assets\Serpium.App.ico"; AppUserModelID: "SerpiumVPN.Desktop"
Name: "{autodesktop}\SerpiumVPN"; Filename: "{app}\SerpiumVPN.exe"; IconFilename: "{app}\Assets\Serpium.App.ico"; AppUserModelID: "SerpiumVPN.Desktop"; Tasks: desktopicon

[Run]
Filename: "{app}\SerpiumUpdater.exe"; Parameters: "--cleanup-legacy true --target ""{app}"""; Flags: runhidden waituntilterminated
Filename: "{app}\SerpiumVPN.exe"; Description: "{cm:LaunchProgram,SerpiumVPN}"; Flags: shellexec nowait postinstall skipifsilent
