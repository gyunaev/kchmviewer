set NSISPATH="C:\Program Files (x86)\NSIS\"
set VCPATH=C:\Program Files (x86)\VC

:: Stores prebuilt chmlib and libzip
set EXTRALIB=C:\Users\test\Documents\builder\extralibs

set OLDPATH=%PATH%
set BASEINCLUDE=%VCPATH%\include\;C:\Program Files (x86)\Windows Kits\8.1\Include\um\;C:\Program Files (x86)\Windows Kits\8.1\Include\shared

rd /s /q build

mkdir build\x86
mkdir release\x86\

:: 32-bit
cd build\x86

PATH=%OLDPATH%;%VCPATH%\bin\;C:\Program Files (x86)\Windows Kits\8.0\bin\x86\;C:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE\;
set LIB=%VCPATH%\lib\;C:\Program Files (x86)\Windows Kits\8.0\Lib\win8\um\x86\;%EXTRALIB%\x86\lib
set INCLUDE=%BASEINCLUDE%;%EXTRALIB%\x86\include
set QTPATH=C:\Qt\Qt5.5.1-x86\5.5\msvc2013\bin

%QTPATH%\qmake.exe -r ..\..  || exit
"%VCPATH%\bin\nmake.exe"  > build.log  || exit

:: Copy release files
copy src\bin\kchmviewer.exe  ..\..\release\x86\  || exit


:: done 32-bit build
cd ..\..

:: 64-bit
mkdir build\x64
mkdir release\x64\

cd build\x64

PATH=%OLDPATH%;%VCPATH%\bin\amd64\;C:\Program Files (x86)\Windows Kits\8.0\bin\x64\;C:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE\;
set LIB=%VCPATH%\lib\amd64\;C:\Program Files (x86)\Windows Kits\8.0\Lib\win8\um\x64\;%EXTRALIB%\x64\lib;
set INCLUDE=%BASEINCLUDE%;%EXTRALIB%\x64\include
set QTPATH=C:\Qt\Qt5.5.1-x64\5.5\msvc2013_64\bin

%QTPATH%\qmake.exe -r ..\..  || exit
"%VCPATH%\bin\nmake.exe"  > build.log  || exit

:: Copy release files
copy src\bin\kchmviewer.exe  ..\..\release\x64\  || exit

:: done 64-bit build
cd ..\..

:: Create the installers
cd nsis
create_installers.bat
