@echo off

rem Get sunshine root directory
for %%I in ("%~dp0\..") do set "ROOT_DIR=%%~fI"

set SERVICE_NAME=RazerRemotePlayHostService
set SERVICE_BIN="%ROOT_DIR%\tools\RazerRemotePlayHostService.exe"

rem Set service to demand start. It will be changed to auto later if the user selected that option.
set SERVICE_START_TYPE=demand

rem Remove the legacy RazerRemotePlayHostService service
net stop RazerRemotePlayHostService
sc delete RazerRemotePlayHostService

rem Check if RazerRemotePlayHostService already exists
sc qc %SERVICE_NAME% > nul 2>&1
if %ERRORLEVEL%==0 (
    rem Stop the existing service if running
    net stop %SERVICE_NAME%

    rem Reconfigure the existing service
    set SC_CMD=config
) else (
    rem Create a new service
    set SC_CMD=create
)

rem Run the sc command to create/reconfigure the service
sc %SC_CMD% %SERVICE_NAME% binPath= %SERVICE_BIN% start= %SERVICE_START_TYPE% DisplayName= "Razer Remote Play Host Service"

rem Set the description of the service
sc description %SERVICE_NAME% "Razer Remote Play Host Service is a self-hosted game stream host for Razer Cortex."
