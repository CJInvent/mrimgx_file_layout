#include <string>
#include <iostream>
#include "../src/img_to_vhdx/offline_vhdx.h"
int wmain(int argc,wchar_t** argv) {
    if(argc!=2) return 1;
    HANDLE h=CreateFileW(argv[1],GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
    if(h==INVALID_HANDLE_VALUE) return 2;
    try {
        OfflineVHDX writer; writer.initialize(h,5ull*1024*1024*1024);
        std::vector<unsigned char> a(1024,0xA5), b(1024,0x5A), c(4096,0x37);
        writer.write(0,a.data(),(uint32_t)a.size());
        writer.write(2*1024*1024-512,b.data(),(uint32_t)b.size());
        // Cross the sector-bitmap BAT slot at the 4 GiB chunk boundary.
        writer.write(4ull*1024*1024*1024-2048,c.data(),(uint32_t)c.size());
        bool bounds=false; try { writer.write(5ull*1024*1024*1024,a.data(),1); }
        catch(const std::exception&) { bounds=true; }
        if(!bounds) return 3;
        if(!FlushFileBuffers(h)) return 4;
        CloseHandle(h); return 0;
    } catch(const std::exception& ex) { std::cerr<<ex.what()<<std::endl; CloseHandle(h); return 5; }
}
