How to add licenses to the release folder

Before building the Inno Setup installer, copy these files into D:\release:

D:\release\THIRD_PARTY_NOTICES.txt
D:\release\licenses\LICENSE_tg-ws-proxy.txt
D:\release\licenses\LICENSE_zapret-discord-youtube.txt
D:\release\licenses\LICENSE_zapret_bol-van.txt
D:\release\licenses\LICENSE_WinDivert.txt

Expected release structure:

D:\release\
  SerpiumVPN.exe
  THIRD_PARTY_NOTICES.txt
  licenses\
    LICENSE_tg-ws-proxy.txt
    LICENSE_zapret-discord-youtube.txt
    LICENSE_zapret_bol-van.txt
    LICENSE_WinDivert.txt
  bin_files\
    bin\
      winws.exe
      WinDivert.dll
      WinDivert64.sys
    tgws\
      TgWsProxy_windows.exe

Then build the installer using serpium_tgws_licenses.iss.
