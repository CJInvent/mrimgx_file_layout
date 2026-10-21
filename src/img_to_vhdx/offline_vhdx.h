#pragma once
// Writer for a newly created, empty, dynamic VHDX only. No parent, no log replay,
// no existing-image updates. QEMU supplies the standard empty container.
#include <windows.h>
#include <objbase.h>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstring>

class OfflineVHDX {
    HANDLE file=INVALID_HANDLE_VALUE;
    uint64_t diskSize=0, batOffset=0, nextOffset=0, chunkRatio=0;
    uint32_t blockSize=0;
    std::vector<uint64_t> bat;
    template<class T> static T value(const unsigned char* p) { T v; memcpy(&v,p,sizeof(v)); return v; }
    static uint32_t crc(const std::vector<unsigned char>& b) {
        uint32_t c=~0u;
        for(auto x:b) { c^=x; for(int i=0;i<8;++i) c=(c>>1)^((c&1)?0x82f63b78u:0); }
        return ~c;
    }
    static bool guid(const unsigned char* p,const wchar_t* text) {
        GUID g; if(CLSIDFromString(text,&g)!=S_OK) throw std::runtime_error("Invalid internal GUID");
        return !memcmp(p,&g,16);
    }
    void seek(uint64_t off) {
        LARGE_INTEGER p; p.QuadPart=off;
        if(!SetFilePointerEx(file,p,nullptr,FILE_BEGIN)) throw std::runtime_error("VHDX seek failed");
    }
    std::vector<unsigned char> read(uint64_t off,DWORD n) {
        std::vector<unsigned char> b(n); DWORD actual=0; seek(off);
        if(!ReadFile(file,b.data(),n,&actual,nullptr)||actual!=n) throw std::runtime_error("VHDX short read");
        return b;
    }
    void put(uint64_t off,const void* data,DWORD n) {
        DWORD actual=0; seek(off);
        if(!WriteFile(file,data,n,&actual,nullptr)||actual!=n) throw std::runtime_error("VHDX write failed: "+std::to_string(GetLastError()));
    }
    static void checkCrc(std::vector<unsigned char> b) {
        uint32_t expected=value<uint32_t>(b.data()+4); memset(b.data()+4,0,4);
        if(crc(b)!=expected) throw std::runtime_error("VHDX template checksum mismatch");
    }
public:
    void initialize(HANDLE h,uint64_t expectedSize) {
        file=h;
        auto id=read(0,8); if(memcmp(id.data(),"vhdxfile",8)) throw std::runtime_error("VHDX template signature");
        auto regions=read(192*1024,64*1024); checkCrc(regions);
        if(memcmp(regions.data(),"regi",4)) throw std::runtime_error("VHDX regions signature");
        uint32_t count=value<uint32_t>(regions.data()+8),batLength=0,metaLength=0;
        uint64_t metaOffset=0;
        if(count>2047) throw std::runtime_error("VHDX region count");
        LARGE_INTEGER length; if(!GetFileSizeEx(file,&length)) throw std::runtime_error("VHDX length");
        for(uint32_t i=0;i<count;++i) {
            auto e=regions.data()+16+i*32;
            auto off=value<uint64_t>(e+16); auto n=value<uint32_t>(e+24);
            if(off>uint64_t(length.QuadPart)||n>uint64_t(length.QuadPart)-off) throw std::runtime_error("VHDX region bounds");
            if(guid(e,L"{2DC27766-F623-4200-9D64-115E9BFD4A08}")) {batOffset=off;batLength=n;}
            else if(guid(e,L"{8B7CA206-4790-4B9A-B8FE-575F050F886E}")) {metaOffset=off;metaLength=n;}
            else if(value<uint32_t>(e+28)&1) throw std::runtime_error("Unknown required VHDX region");
        }
        if(!batLength||!metaLength||batLength>64*1024*1024||metaLength>1024*1024) throw std::runtime_error("VHDX region lengths");
        auto meta=read(metaOffset,metaLength);
        if(memcmp(meta.data(),"metadata",8)) throw std::runtime_error("VHDX metadata signature");
        count=value<uint16_t>(meta.data()+10); uint32_t sector=0;
        if(count>2047||32ull+count*32ull>meta.size()) throw std::runtime_error("VHDX metadata count");
        for(uint32_t i=0;i<count;++i) {
            auto e=meta.data()+32+i*32; auto off=value<uint32_t>(e+16),n=value<uint32_t>(e+20);
            if(off>meta.size()||n>meta.size()-off) throw std::runtime_error("VHDX metadata bounds");
            if(guid(e,L"{CAA16737-FA36-4D43-B3B6-33F0AA44E76B}")) {
                if(n!=8||value<uint32_t>(meta.data()+off+4)!=0) throw std::runtime_error("Requires dynamic VHDX without parent");
                blockSize=value<uint32_t>(meta.data()+off);
            } else if(guid(e,L"{2FA54224-CD1B-4876-B211-5DBED83BF4B8}")) {
                if(n!=8) throw std::runtime_error("VHDX size metadata"); diskSize=value<uint64_t>(meta.data()+off);
            } else if(guid(e,L"{8141BF1D-A96F-4709-BA47-F233A8FAAB5F}")) {
                if(n!=4) throw std::runtime_error("VHDX sector metadata"); sector=value<uint32_t>(meta.data()+off);
            }
        }
        if(diskSize!=expectedSize||blockSize!=2*1024*1024||sector!=512) throw std::runtime_error("Unexpected VHDX geometry");
        chunkRatio=(uint64_t(1)<<23)*sector/blockSize;
        auto bytes=read(batOffset,batLength); bat.resize(bytes.size()/8); memcpy(bat.data(),bytes.data(),bytes.size());
        for(auto& e:bat) {
            if(e!=0 && e!=2) throw std::runtime_error("VHDX template is not empty");
            e=0; // QEMU explicitly marks new payload blocks ZERO (state 2).
        }
        uint64_t blocks=(diskSize+blockSize-1)/blockSize;
        if(blocks+(blocks-1)/chunkRatio>bat.size()) throw std::runtime_error("VHDX BAT too small");
        nextOffset=(uint64_t(length.QuadPart)+1048575)&~uint64_t(1048575);
        GUID fileGuid,dataGuid; if(CoCreateGuid(&fileGuid)!=S_OK||CoCreateGuid(&dataGuid)!=S_OK) throw std::runtime_error("VHDX GUID generation failed");
        for(uint64_t off:{65536ull,131072ull}) {
            auto header=read(off,4096); checkCrc(header);
            if(memcmp(header.data(),"head",4)) throw std::runtime_error("VHDX header signature");
            for(size_t i=48;i<64;++i) if(header[i]) throw std::runtime_error("VHDX template has active log");
            uint64_t seq=value<uint64_t>(header.data()+8)+2;
            memcpy(header.data()+8,&seq,8); memcpy(header.data()+16,&fileGuid,16); memcpy(header.data()+32,&dataGuid,16);
            memset(header.data()+4,0,4); auto checksum=crc(header); memcpy(header.data()+4,&checksum,4);
            put(off,header.data(),(DWORD)header.size());
        }
        if(!FlushFileBuffers(file)) throw std::runtime_error("VHDX header flush failed");
    }
    void write(uint64_t offset,const unsigned char* data,uint32_t length) {
        if(offset>diskSize||length>diskSize-offset) throw std::runtime_error("VHDX virtual write bounds");
        while(length) {
            uint64_t block=offset/blockSize,within=offset%blockSize,slot=block+block/chunkRatio;
            if(slot>=bat.size()) throw std::runtime_error("VHDX BAT slot bounds");
            if(!bat[slot]) {
                uint64_t allocated=nextOffset; nextOffset+=blockSize;
                seek(nextOffset); if(!SetEndOfFile(file)) throw std::runtime_error("VHDX allocation failed");
                // New file extent is zero-initialized by Windows; never use SetFileValidData.
                bat[slot]=allocated|6;
                put(batOffset+slot*8,&bat[slot],8);
            }
            uint32_t n=(uint32_t)(std::min)(uint64_t(length),uint64_t(blockSize)-within);
            put((bat[slot]&0xfffffffffff00000ull)+within,data,n);
            offset+=n; data+=n; length-=n;
        }
    }
};
