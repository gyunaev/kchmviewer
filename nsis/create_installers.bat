:: This bat file is used when building on Windows to create installers
set NSIS="C:\Program Files (x86)\NSIS\makensis"

mkdir build
copy ..\release\x64\kchmviewer.exe build
xcopy C:\Users\Test\Documents\redist-kchmviewer\x64 build /S /I
copy installer64.nsis build\installer.nsis
copy kchmviewer.exe.manifest build
copy license.txt build
cd build
%NSIS% installer.nsis || exit
copy InstallKchmViewer.exe ..\..\InstallKchmViewer-64bit.exe || exit
cd ..
rd /s /q build

mkdir build
copy ..\release\x86\kchmviewer.exe build
xcopy C:\Users\Test\Documents\redist-kchmviewer\x86 build /S /I
copy installer.nsis build
copy kchmviewer.exe.manifest build
copy license.txt build
cd build
%NSIS% installer.nsis || exit
copy InstallKchmViewer.exe ..\..\InstallKchmViewer-32bit.exe || exit
cd ..
rd /s /q build
