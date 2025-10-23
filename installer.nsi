Unicode true
!include "MUI2.nsh"

; Настройки приложения
Name "Vless Wizard"
OutFile "VlessWizard_Setup.exe"
InstallDir "$PROGRAMFILES\Vless Wizard"

; Запрос прав администратора
RequestExecutionLevel admin

; Интерфейс
!define MUI_ABORTWARNING

; Страницы установки
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY

; Страница выбора компонентов (для ярлыка на рабочем столе)
!define MUI_PAGE_HEADER_TEXT "Выбор компонентов"
!define MUI_PAGE_HEADER_SUBTEXT "Выберите дополнительные компоненты для установки."
!define MUI_COMPONENTSPAGE_TEXT_TOP "Выберите, следует ли создавать ярлык на рабочем столе."
!define MUI_COMPONENTSPAGE_TEXT_COMPLIST "Дополнительные компоненты:"
!insertmacro MUI_PAGE_COMPONENTS

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Страницы удаления
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Языки
!insertmacro MUI_LANGUAGE "Russian"

; Настройки
ShowInstDetails show
ShowUnInstDetails show

; Секция установки (обязательная)
Section "Vless Wizard" SecMain
    SectionIn RO
    
    SetOutPath "$INSTDIR"
    
    ; Копирование файлов программы
    File /r "dist\*.*"
    
    ; Создание записи в "Установка и удаление программ"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "DisplayName" "Vless Wizard"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "DisplayIcon" "$INSTDIR\main.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "Publisher" "Vless Wizard"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "DisplayVersion" "1.0.0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" \
        "NoRepair" 1
    
    ; Создание ярлыка в меню "Пуск"
    CreateDirectory "$SMPROGRAMS\Vless Wizard"
    CreateShortCut "$SMPROGRAMS\Vless Wizard\Vless Wizard.lnk" "$INSTDIR\main.exe"
    CreateShortCut "$SMPROGRAMS\Vless Wizard\Удалить Vless Wizard.lnk" "$INSTDIR\uninstall.exe"
    
    ; Создание файла удаления
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Секция ярлыка на рабочем столе (опциональная)
Section "Ярлык на рабочем столе" SecDesktopShortcut
    CreateShortCut "$DESKTOP\Vless Wizard.lnk" "$INSTDIR\main.exe"
SectionEnd

; Описание секций
LangString DESC_SecMain ${LANG_RUSSIAN} "Основные файлы программы Vless Wizard."
LangString DESC_SecDesktopShortcut ${LANG_RUSSIAN} "Создать ярлык на рабочем столе."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopShortcut} $(DESC_SecDesktopShortcut)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Секция удаления
Section "Uninstall"
    ; Удаление файлов
    RMDir /r "$INSTDIR"
    
    ; Удаление ярлыков
    Delete "$SMPROGRAMS\Vless Wizard\Vless Wizard.lnk"
    Delete "$SMPROGRAMS\Vless Wizard\Удалить Vless Wizard.lnk"
    RMDir "$SMPROGRAMS\Vless Wizard"
    
    ; Удаление ярлыка с рабочего стола
    Delete "$DESKTOP\Vless Wizard.lnk"
    
    ; Удаление записи из реестра
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard"
SectionEnd

Function .onInit
    ; Установка русского языка по умолчанию
    !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd