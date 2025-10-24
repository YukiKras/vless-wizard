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

; Страница выбора компонентов (для ярлыков)
!define MUI_PAGE_HEADER_TEXT "Выбор компонентов"
!define MUI_PAGE_HEADER_SUBTEXT "Выберите дополнительные компоненты для установки."
!define MUI_COMPONENTSPAGE_TEXT_TOP "Выберите дополнительные ярлыки для создания."
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

; Секции
Section "Vless Wizard" SecMain
    SectionIn RO
    
    ; Проверка и удаление предыдущей установки
    Call CheckAndRemovePreviousInstall
    
    SetOutPath "$INSTDIR"
    
    ; Копирование файлов программы
    File /r "dist\*.*"
    
    ; Копирование папки xray
    SetOutPath "$INSTDIR\xray"
    File /r "xray\*.*"
    
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
    
    ; Создание файла удаления
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Секция ярлыка в меню "Пуск" (включена по умолчанию)
Section "Ярлык в меню Пуск" SecStartMenu
    SectionIn 1  ; Включено по умолчанию
    
    CreateDirectory "$SMPROGRAMS\Vless Wizard"
    CreateShortCut "$SMPROGRAMS\Vless Wizard\Vless Wizard.lnk" "$INSTDIR\main.exe"
    CreateShortCut "$SMPROGRAMS\Vless Wizard\Удалить Vless Wizard.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

; Секция ярлыка на рабочем столе (опциональная)
Section "Ярлык на рабочем столе" SecDesktopShortcut
    CreateShortCut "$DESKTOP\Vless Wizard.lnk" "$INSTDIR\main.exe"
SectionEnd

; Секция запуска программы после установки (включена по умолчанию)
Section "Запустить Vless Wizard" SecRunProgram
    SectionIn 1  ; Включено по умолчанию
SectionEnd

; Описание секций
LangString DESC_SecMain ${LANG_RUSSIAN} "Основные файлы программы Vless Wizard, включая xray."
LangString DESC_SecStartMenu ${LANG_RUSSIAN} "Создать ярлык в меню Пуск."
LangString DESC_SecDesktopShortcut ${LANG_RUSSIAN} "Создать ярлык на рабочем столе."
LangString DESC_SecRunProgram ${LANG_RUSSIAN} "Запустить Vless Wizard после завершения установки."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} $(DESC_SecStartMenu)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopShortcut} $(DESC_SecDesktopShortcut)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecRunProgram} $(DESC_SecRunProgram)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Функция проверки и удаления предыдущей установки
Function CheckAndRemovePreviousInstall
    ; Проверяем наличие установленной программы
    ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VlessWizard" "UninstallString"
    StrCmp $0 "" done
    
    ; Если нашли предыдущую установку, спрашиваем пользователя
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "Обнаружена предыдущая установка Vless Wizard.$\n$\nХотите удалить предыдущую версию перед установкой новой?" \
        /SD IDYES IDNO done
    
    ; Выполняем удаление
    ExecWait '$0 /S _?=$INSTDIR'
    
    ; Небольшая пауза для завершения удаления
    Sleep 1000
    
    done:
FunctionEnd

; Функция, выполняемая после установки
Function .onInstSuccess
    ; Проверяем, выбрана ли секция запуска программы
    SectionGetFlags ${SecRunProgram} $0
    IntOp $0 $0 & ${SF_SELECTED}
    IntCmp $0 ${SF_SELECTED} 0 no_run
    
    ; Запускаем программу
    Exec "$INSTDIR\main.exe"
    
    no_run:
FunctionEnd

; Секция удаления
Section "Uninstall"
    ; Удаление файлов
    RMDir /r "$INSTDIR"
    
    ; Удаление ярлыков из меню "Пуск"
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
    
    ; Установка выбранных по умолчанию компонентов
    SectionSetFlags ${SecStartMenu} 1
    SectionSetFlags ${SecRunProgram} 1
FunctionEnd