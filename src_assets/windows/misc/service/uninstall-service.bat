@echo off

rem Stop and delete the legacy RazerRemotePlayHostService service
net stop RazerRemotePlayHostService
sc delete RazerRemotePlayHostService

rem Stop and delete the new RazerRemotePlayHostService service
net stop RazerRemotePlayHostService
sc delete RazerRemotePlayHostService
