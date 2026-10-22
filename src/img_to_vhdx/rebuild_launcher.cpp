#include <windows.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include "rebuild_launcher.h"

namespace {
std::wstring quote(const std::wstring& value) {
    std::wstring result=L"\"";
    size_t slashes=0;
    for(wchar_t ch:value) {
        if(ch==L'\\') { ++slashes; continue; }
        if(ch==L'\"') { result.append(slashes*2+1,L'\\'); result+=ch; }
        else { result.append(slashes,L'\\'); result+=ch; }
        slashes=0;
    }
    result.append(slashes*2,L'\\'); result+=L'\"'; return result;
}
}

int launchForensicRebuild(int argc,wchar_t* argv[]) {
    std::vector<wchar_t> filename(32768);
    DWORD length=GetModuleFileNameW(nullptr,filename.data(),static_cast<DWORD>(filename.size()));
    if(!length || length>=filename.size()) throw std::runtime_error("Cannot locate rebuild installation");
    std::filesystem::path exe(filename.data());
    auto script=exe.parent_path()/L"tools"/L"rebuild.py";
    if(!std::filesystem::is_regular_file(script)) script=exe.parent_path().parent_path()/L"tools"/L"rebuild.py";
    if(!std::filesystem::is_regular_file(script)) throw std::runtime_error("Rebuild requires the bundled tools directory and Python dependencies; see FORENSIC.md");
    std::wstring python=L"python"; std::vector<std::wstring> arguments;
    for(int i=2;i<argc;++i) {
        if(std::wstring(argv[i])==L"--python") {
            if(++i>=argc) throw std::runtime_error("--python requires an interpreter path");
            python=argv[i];
        } else arguments.emplace_back(argv[i]);
    }
    std::wstring command=quote(python)+L" "+quote(script.wstring())+L" --native "+quote(exe.wstring());
    for(const auto& arg:arguments) command+=L" "+quote(arg);
    std::vector<wchar_t> buffer(command.begin(),command.end());buffer.push_back(0);
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    if(!CreateProcessW(nullptr,buffer.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&startup,&process))
        throw std::runtime_error("Cannot start rebuild Python interpreter (Windows error "+std::to_string(GetLastError())+")");
    CloseHandle(process.hThread);
    if(WaitForSingleObject(process.hProcess,INFINITE)!=WAIT_OBJECT_0) {CloseHandle(process.hProcess);throw std::runtime_error("Rebuild process wait failed");}
    DWORD code=1;BOOL ok=GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);
    if(!ok) throw std::runtime_error("Cannot read rebuild exit status");
    return static_cast<int>(code);
}
