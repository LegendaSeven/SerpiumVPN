; Full SerpiumVPN installer. Inno owns the primary installation.
; In-app patches are applied later by SerpiumUpdater.exe from GitHub Releases.

#define MyAppName "SerpiumVPN"
#ifndef MyAppVersion
#define MyAppVersion "1.0.0"
#endif
#define MyAppPublisher "Serpium"
#define ProjectRoot "D:\Program\Serpium\SerpiumVPN"
#define SourceDir ProjectRoot + "\publish\app"

[Setup]
AppId={{9F8E7D6C-5B4A-3C2B-1A0F-EEDDCCBBAA99}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SerpiumVPN
DefaultGroupName=SerpiumVPN
PrivilegesRequired=admin
OutputDir={#ProjectRoot}\publish\installer
OutputBaseFilename=SerpiumVPN_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#ProjectRoot}\serpium_vpn.ico
UninstallDisplayIcon={app}\SerpiumVPN.exe

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "runasadmin"; Description: "Запустить SerpiumVPN от имени администратора после установки"; GroupDescription: "Первый запуск:"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\SerpiumVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\SerpiumUpdater.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*"; Excludes: "bin_files,SerpiumVPN.exe,SerpiumUpdater.exe,*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\bin_files\*"; Excludes: "logs\*,serpium.runtime.json,vendor_versions.json,tgws\TgWsProxy_data\*,tgws\*.log,tgws\*.tmp,lists\*-user.txt"; DestDir: "{app}\bin_files"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Dirs]
Name: "{app}\licenses"
Name: "{app}\bin_files\logs"
Name: "{app}\bin_files\tgws"
Name: "{app}\bin_files\tgws\TgWsProxy_data"

[Icons]
Name: "{group}\SerpiumVPN"; Filename: "{app}\SerpiumVPN.exe"
Name: "{autodesktop}\SerpiumVPN"; Filename: "{app}\SerpiumVPN.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SerpiumVPN.exe"; Description: "{cm:LaunchProgram,SerpiumVPN}"; Flags: shellexec nowait postinstall skipifsilent; Tasks: runasadmin; Verb: runas

[Code]
procedure CurUninstallStepChanged(UninstallStep: TUninstallStep);
begin
  if UninstallStep = usPostUninstall then
  begin
    if MsgBox('Хотите удалить ваши сохраненные списки доменов, Telegram-прокси secret и кастомные настройки?', mbConfirmation, MB_YESNO) = IDNO then
    begin
      Log('Пользователь решил сохранить свои изменения.');
    end
    else
    begin
      DelTree(ExpandConstant('{app}\bin_files'), True, True, True);
      RemoveDir(ExpandConstant('{app}'));
    end;
  end;
end;
