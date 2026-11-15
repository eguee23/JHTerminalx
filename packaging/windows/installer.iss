; Instalador de Windows (Inno Setup 6).
; Compilar: iscc /DAppVersion=1.2.3 /DSourceExe=ruta\jhterminalx.exe /DOutputDir=dist packaging\windows\installer.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\target\release\jhterminalx.exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{6C1E9F4A-3B7D-4E2A-9C55-8D0F2A7B1E63}
AppName=JHTerminalx
AppVersion={#AppVersion}
AppPublisher=eguee23
AppPublisherURL=https://github.com/eguee23/JHTerminalx
DefaultDirName={autopf}\JHTerminalx
DefaultGroupName=JHTerminalx
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=JHTerminalx-{#AppVersion}-windows-x64-setup
SetupIconFile=..\..\assets\icon.ico
UninstallDisplayIcon={app}\jhterminalx.exe
LicenseFile=..\..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Permite instalar sin ser administrador (en el perfil del usuario).
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "jhterminalx.exe"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\JHTerminalx"; Filename: "{app}\jhterminalx.exe"
Name: "{autodesktop}\JHTerminalx"; Filename: "{app}\jhterminalx.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\jhterminalx.exe"; Description: "{cm:LaunchProgram,JHTerminalx}"; Flags: nowait postinstall skipifsilent
