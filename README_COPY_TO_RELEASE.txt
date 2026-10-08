SerpiumVPN release license payload

The SerpiumVPN project now copies THIRD_PARTY_NOTICES.txt and the complete
licenses directory into build and publish output automatically.

Expected publish structure:

publish\app\
  SerpiumVPN.exe
  SerpiumUpdater.exe
  THIRD_PARTY_NOTICES.txt
  licenses\
    LICENSE_tg-ws-proxy.txt
    LICENSE_sing-box_GPL-3.0-or-later.txt
    LICENSE_Xray-core_MPL-2.0.txt
  bin_files\
    relay\
      sing-box.exe
      xray.exe
      SerpiumNet.exe
    tgws\
      TgWsProxy_windows.exe

Before publishing a release, verify that the notice and all applicable license
files are present in publish\app and in the installer payload.
