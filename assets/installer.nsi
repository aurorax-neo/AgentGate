!include "MUI2.nsh"

Name "AgentGate"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\AgentGate"
RequestExecutionLevel admin
Unicode True

!define MUI_ICON "AppIcon.ico"
!define MUI_UNICON "AppIcon.ico"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Section "Install"
  SetOutPath "$INSTDIR"
  File "AgentGate.exe"
  File "AppIcon.ico"
  File "..\README.md"
  File "..\LICENSE"

  CreateDirectory "$SMPROGRAMS\AgentGate"
  CreateShortcut "$SMPROGRAMS\AgentGate\AgentGate.lnk" "$INSTDIR\AgentGate.exe" "" "$INSTDIR\AppIcon.ico"
  CreateShortcut "$DESKTOP\AgentGate.lnk" "$INSTDIR\AgentGate.exe" "" "$INSTDIR\AppIcon.ico"

  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\AgentGate.exe"
  Delete "$INSTDIR\AppIcon.ico"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$SMPROGRAMS\AgentGate\AgentGate.lnk"
  RMDir "$SMPROGRAMS\AgentGate"
  Delete "$DESKTOP\AgentGate.lnk"
  RMDir "$INSTDIR"
SectionEnd
