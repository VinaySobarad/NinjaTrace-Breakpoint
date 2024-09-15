@ECHO OFF

cl.exe /nologo /O1 /MT /W0 /GS- /DNDEBUG /Tc FinalImplant.cpp /link /OUT:FinalImplant.exe /SUBSYSTEM:CONSOLE
del *.obj