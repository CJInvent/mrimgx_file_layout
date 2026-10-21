#pragma once
// Explicit, single-file, unencrypted full-image recovery. Never edits the source.
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <map>
#include <winioctl.h>
#include "..\libs\file_operations\file_operations.h"
#include "..\libs\file_reader\metadata_block_reader.h"
#include "..\libs\file_reader\metadataheader.h"
#include "zstd\zstd.h"
#include "offline_vhdx.h"
#include "openssl/sha.h"

namespace recovery {
using json = nlohmann::json;
inline std::string hex(const unsigned char* p, size_t n) {
    std::ostringstream s;
    for (size_t i=0;i<n;++i) s << std::hex << std::setw(2) << std::setfill('0') << unsigned(p[i]);
    return s.str();
}
inline std::string md5(const unsigned char* p, size_t n) {
    auto h=computeMD5Hash(p,n); return hex(h.data(),h.size());
}
struct Handle {
    HANDLE h=INVALID_HANDLE_VALUE;
    ~Handle(){if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
};
inline void writeAt(HANDLE h,uint64_t offset,const unsigned char* p,DWORD n) {
    LARGE_INTEGER pos; pos.QuadPart=offset;
    DWORD actual=0;
    if(!SetFilePointerEx(h,pos,nullptr,FILE_BEGIN) || !WriteFile(h,p,n,&actual,nullptr) || actual!=n)
        throw std::runtime_error("Target write failed offset="+std::to_string(offset)+" requested="+std::to_string(n)+" actual="+std::to_string(actual)+" win32="+std::to_string(GetLastError()));
}
// This mode is deliberately separate from strict conversion. A plan is required,
// bound to the source length, verified JSON image id, and exact index byte hashes.
inline int run(const std::wstring& source,const std::wstring& planPath,
               const std::wstring& output,const std::wstring& logPath,bool dryRun,const std::wstring& qemu=L"",bool direct=false) {
    if(std::filesystem::exists(output) && !dryRun) throw std::runtime_error("Refusing to overwrite output");
    if(std::filesystem::equivalent(source,planPath)) throw std::runtime_error("Plan is the source");
    if(std::filesystem::exists(logPath)) throw std::runtime_error("Refusing to overwrite manifest");
    std::ifstream pf{std::filesystem::path(planPath)};
    json plan; pf>>plan;
    std::ofstream log{std::filesystem::path(logPath)};
    if(!log) throw std::runtime_error("Cannot create manifest");
    auto start=std::chrono::steady_clock::now();
    auto event=[&](json j){
        j["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
        j["utc_epoch_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        log<<j.dump()<<std::endl;
        if(!log) throw std::runtime_error("Manifest write failed");
    };
    const uint64_t size=std::filesystem::file_size(source);
    const auto sourceWriteTime=std::filesystem::last_write_time(source);
    if(size!=plan.at("source_size").get<uint64_t>()) throw std::runtime_error("Source length does not match plan");
    auto guard=openFileWithGuard(source,true); auto f=guard.get();
    SHA256_CTX sourceDigest; SHA256_Init(&sourceDigest);
    uint64_t hashedThrough=0;
    auto hashUntil=[&](uint64_t limit) {
        std::vector<unsigned char> buffer;
        while(hashedThrough<limit) {
            size_t n=(size_t)(std::min)(limit-hashedThrough,64ull*1024*1024);
            buffer.resize(n); f->clear(); setFilePointer(f,hashedThrough,std::ios::beg);
            readFile(f,buffer.data(),n); SHA256_Update(&sourceDigest,buffer.data(),n); hashedThrough+=n;
        }
    };
    uint64_t dataEnd=0;
    struct ReadWindow { uint64_t offset=0; std::vector<unsigned char> bytes; };
    ReadWindow windows[2]; unsigned nextWindow=0;
    auto read=[&](uint64_t offset,size_t n) {
        if(offset>size || n>size-offset || n>512ull*1024*1024) throw std::runtime_error("Read bounds");
        // Compression workers can store adjacent logical blocks out of order.
        // Two aligned windows avoid a disk seek per block on rotating media.
        if(dataEnd && offset<dataEnd && n<=8u*1024*1024 && n<=dataEnd-offset) {
            for(auto& w:windows) if(offset>=w.offset && offset-w.offset<=w.bytes.size() && n<=w.bytes.size()-(offset-w.offset))
                return std::vector<unsigned char>(w.bytes.begin()+(offset-w.offset),w.bytes.begin()+(offset-w.offset)+n);
            auto& w=windows[nextWindow++%2];
            w.offset=(offset/(64ull*1024*1024))*(64ull*1024*1024);
            auto length=(std::min)(dataEnd-w.offset,(std::max)(64ull*1024*1024,offset-w.offset+n));
            w.bytes.resize((size_t)length);
            f->clear(); setFilePointer(f,w.offset,std::ios::beg); readFile(f,w.bytes.data(),w.bytes.size());
            hashUntil(w.offset);
            if(hashedThrough<w.offset+w.bytes.size()) {
                size_t skip=(size_t)(hashedThrough-w.offset);
                SHA256_Update(&sourceDigest,w.bytes.data()+skip,w.bytes.size()-skip);
                hashedThrough=w.offset+w.bytes.size();
            }
            return std::vector<unsigned char>(w.bytes.begin()+(offset-w.offset),w.bytes.begin()+(offset-w.offset)+n);
        }
        std::vector<unsigned char> b(n);
        f->clear(); setFilePointer(f,offset,std::ios::beg);
        readFile(f,b.data(),n); return b;
    };
    auto footer=read(size-20,20);
    uint64_t root; memcpy(&root,footer.data(),8);
    if(memcmp(footer.data()+8,"MACRIUM_FILE",12)) throw std::runtime_error("Invalid footer");
    setFilePointer(f,root,std::ios::beg);
    file_structs::fileLayout layout;
    std::string text;
    readFileMetadataData(layout,f,text); // strict original hash check
    layout=json::parse(text);
    auto j=json::parse(text);
    if(md5(reinterpret_cast<const unsigned char*>(text.data()),text.size())!=plan.at("json_md5"))
        throw std::runtime_error("Verified JSON does not match recovery plan");
    if(j["_header"]["imageid"]!=plan["imageid"] ||
       j["_header"]["backup_type"]!="full" || j["_header"]["split_file"]!=false ||
       j["_header"]["delta_index"]!=false || j["_header"]["file_number"]!=0 ||
       j["_encryption"].value("enable",false) || layout.disks.size()!=1)
        throw std::runtime_error("Recovery requires a matching unencrypted single-file full image");
    auto& disk=layout.disks[0];
    uint64_t metadata=j["_header"]["index_file_position"];
    dataEnd=metadata;
    setFilePointer(f,metadata,std::ios::beg);
    readDiskMetadata(layout,f,disk); // track0 remains strictly verified
    if(plan["partitions"].size()!=disk.partitions.size()) throw std::runtime_error("Partition count");
    struct Range { uint64_t begin,end; };
    std::vector<Range> indexRanges;
    for(size_t pi=0;pi<disk.partitions.size();++pi) {
        auto& p=disk.partitions[pi]; auto spec=plan["partitions"][pi];
        uint64_t offset=spec.at("entries_offset"), count=spec.at("count");
        uint64_t reserved=spec.at("reserved_count"), reservedOffset=spec.at("reserved_offset");
        if(count!=j["disks"][0]["partitions"][pi]["_header"]["block_count"].get<uint64_t>() ||
           count>size/sizeof(DataBlockIndexElement) || reserved>1024 ||
           offset<metadata || offset>root || count*30>root-offset ||
           (reserved && (reservedOffset<metadata || reservedOffset>root || reserved*30>root-reservedOffset)))
            throw std::runtime_error("Index plan bounds/count");
        auto b=read(offset,count*30);
        if(md5(b.data(),b.size())!=spec.at("entries_md5")) throw std::runtime_error("Index plan fingerprint");
        p.data_blocks.resize(count); memcpy(p.data_blocks.data(),b.data(),b.size());
        indexRanges.push_back({offset,offset+b.size()});
        if(reserved) {
            auto r=read(reservedOffset,reserved*30);
            if(md5(r.data(),r.size())!=spec.at("reserved_md5")) throw std::runtime_error("Reserved index fingerprint");
            p.reserved_sectors_blocks.resize(reserved); memcpy(p.reserved_sectors_blocks.data(),r.data(),r.size());
            indexRanges.push_back({reservedOffset,reservedOffset+r.size()});
        }
        if(spec.value("container_verified",false)) {
            uint64_t header=spec.at("header_offset");
            auto hb=read(header,32); MetadataBlockHeader mh; memcpy(&mh,hb.data(),32);
            if(memcmp(mh.block_name,"$INDEX  ",8) || mh.flags.compression || mh.flags.encryption ||
               header+32+mh.block_Length!=offset+count*30) throw std::runtime_error("Verified container bounds");
            auto payload=read(header+32,mh.block_Length);
            if(md5(payload.data(),payload.size())!=hex(mh.hash,16)) throw std::runtime_error("Verified container hash");
        }
        event({{"operation","index_loaded"},{"partition",pi},{"source_offset",offset},{"entries",count},
               {"container_verified",spec.value("container_verified",false)}});
    }
    for(size_t a=0;a<indexRanges.size();++a) for(size_t b=a+1;b<indexRanges.size();++b)
        if(indexRanges[a].begin<indexRanges[b].end && indexRanges[b].begin<indexRanges[a].end)
            throw std::runtime_error("Overlapping index ranges");
    event({{"operation","begin"},{"source_size",size},{"imageid",plan["imageid"]},{"dry_run",dryRun},
           {"warning","Unverified index zero entries are unresolved, never asserted to be free space."}});
    VHDXManager manager;
    Handle target;
    OfflineVHDX offline;
    auto targetWrite=[&](uint64_t offset,const unsigned char* p,DWORD n) {
        if(direct) offline.write(offset,p,n); else writeAt(target.h,offset,p,n);
    };
    std::wstring rawPath=output+L".raw";
    if(!dryRun) {
      if(direct) {
        if(!std::filesystem::is_regular_file(qemu)) throw std::runtime_error("qemu-img executable missing");
        if(disk._geometry.bytes_per_sector!=512) throw std::runtime_error("Direct VHDX requires 512-byte logical sectors");
        std::wstring command=L"\""+qemu+L"\" create -f vhdx -o subformat=dynamic,block_size=2097152 \""+output+L"\" "+std::to_wstring(disk._geometry.disk_size);
        STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION process{};
        if(!CreateProcessW(qemu.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&process))
            throw std::runtime_error("Cannot create empty VHDX template");
        CloseHandle(process.hThread); WaitForSingleObject(process.hProcess,INFINITE);
        DWORD code=1; GetExitCodeProcess(process.hProcess,&code); CloseHandle(process.hProcess);
        if(code) throw std::runtime_error("qemu-img create failed");
        target.h=CreateFileW(output.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if(target.h==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open new VHDX");
        DWORD returned=0;
        if(!DeviceIoControl(target.h,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&returned,nullptr)) throw std::runtime_error("Sparse VHDX not supported by destination");
        offline.initialize(target.h,disk._geometry.disk_size);
        event({{"operation","direct_vhdx_initialized"}});
      } else if(!qemu.empty()) {
        if(!std::filesystem::is_regular_file(qemu)) throw std::runtime_error("qemu-img executable missing");
        target.h=CreateFileW(rawPath.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,0,nullptr);
        if(target.h==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot exclusively create sparse output: "+std::to_string(GetLastError()));
        DWORD returned=0;
        if(!DeviceIoControl(target.h,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&returned,nullptr))
            throw std::runtime_error("Destination does not support sparse files");
        LARGE_INTEGER end; end.QuadPart=disk._geometry.disk_size;
        if(!SetFilePointerEx(target.h,end,nullptr,FILE_BEGIN) || !SetEndOfFile(target.h))
            throw std::runtime_error("Cannot size sparse output");
      } else {
        manager.CreateVHDX(output,disk._geometry.disk_size,disk._geometry.bytes_per_sector);
        manager.MountVHDX(output);
        target.h=CreateFileW(manager.GetDiskPath().c_str(),GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        if(target.h==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open created virtual disk: "+std::to_string(GetLastError()));
        // Keep the destination offline so Windows cannot replay NTFS logs during recovery.
        SET_DISK_ATTRIBUTES attr{}; attr.Version=sizeof(attr); attr.Attributes=DISK_ATTRIBUTE_OFFLINE;
        attr.AttributesMask=DISK_ATTRIBUTE_OFFLINE; DWORD returned=0;
        if(!DeviceIoControl(target.h,IOCTL_DISK_SET_DISK_ATTRIBUTES,&attr,sizeof(attr),nullptr,0,&returned,nullptr))
            throw std::runtime_error("Cannot keep destination offline: "+std::to_string(GetLastError()));
      }
        targetWrite(0,disk.track0.data(),(DWORD)disk.track0.size());
    }
    uint64_t verified=0, failed=0, absent=0, written=0, overrides=0;
    auto heartbeat=std::chrono::steady_clock::now();
    for(size_t pi=0;pi<disk.partitions.size();++pi) {
        auto& p=disk.partitions[pi];
        auto spec=plan["partitions"][pi];
        uint64_t lcn0=p._geometry.start+(p._file_system.lcn0_offset-p._file_system.start);
        // Each phase is contiguous logically; coalesce zero-index ranges in manifest.
        for(int phase=0;phase<2;++phase) {
            auto& entries=phase ? p.data_blocks:p.reserved_sectors_blocks;
            uint64_t stride=phase?p._header.block_size:4ull*1024*1024;
            uint64_t origin=phase?lcn0:p._geometry.start+p._geometry.boot_sector_offset;
            uint64_t limit=phase?p._geometry.start+p._geometry.length:origin+p._file_system.reserved_sectors_byte_length;
            if(!stride || stride>64*1024*1024 || limit>disk._geometry.disk_size) throw std::runtime_error("Partition geometry bounds");
            uint64_t gapStart=0,gapLength=0;
            auto flushGap=[&](){
                if(gapLength) event({{"operation","range"},{"partition",pi},{"disk_offset",gapStart},{"length",gapLength},
                    {"status",spec.value("container_verified",false)?"not-stored":"unknown-zero-index"},{"substitution","unallocated VHDX range reads as zero"}});
                gapLength=0;
            };
            for(size_t bi=0;bi<entries.size();++bi) {
                uint64_t dest=origin+bi*stride;
                if(dest>=limit) { if(entries[bi].block_length) throw std::runtime_error("Data beyond partition"); else continue; }
                uint64_t expected=(std::min)(stride,limit-dest);
                auto e=entries[bi];
                bool overrideEntry=false;
                if(phase && spec.contains("overrides") && spec["overrides"].contains(std::to_string(bi))) {
                    auto o=spec["overrides"][std::to_string(bi)];
                    e.file_position=o.at("source_offset"); e.block_length=o.at("stored_length"); e.file_number=0;
                    auto digest=o.at("decoded_md5").get<std::string>();
                    if(digest.size()!=32) throw std::runtime_error("Override digest");
                    for(int k=0;k<16;++k) e.md5_hash[k]=(unsigned char)std::stoul(digest.substr(k*2,2),nullptr,16);
                    overrideEntry=true;
                }
                if(!e.block_length) {
                    if(!gapLength) gapStart=dest;
                    gapLength+=expected;
                    if(!spec.value("container_verified",false)) ++absent;
                    continue;
                }
                flushGap();
                std::vector<unsigned char> data;
                std::string problem;
                try {
                    if(e.file_number || e.file_position<0 || uint64_t(e.file_position)>=metadata ||
                       e.block_length>metadata-uint64_t(e.file_position) || e.block_length>stride+1024*1024)
                        throw std::runtime_error("Index entry bounds/reference invalid");
                    auto raw=read(e.file_position,e.block_length);
                    if(j["_compression"]["compression_level"]!="none") {
                        auto frame=ZSTD_findFrameCompressedSize(raw.data(),raw.size());
                        auto decoded=ZSTD_getFrameContentSize(raw.data(),raw.size());
                        if(ZSTD_isError(frame) || frame!=raw.size() || decoded==ZSTD_CONTENTSIZE_UNKNOWN ||
                           decoded==ZSTD_CONTENTSIZE_ERROR || !decoded || decoded>stride)
                            throw std::runtime_error("Invalid Zstandard frame/declared size");
                        data.resize((size_t)decoded);
                        auto result=ZSTD_decompress(data.data(),data.size(),raw.data(),raw.size());
                        if(ZSTD_isError(result) || result!=decoded) throw std::runtime_error(std::string("Zstandard: ")+ZSTD_getErrorName(result));
                    } else data=std::move(raw);
                    if(data.size()<expected) throw std::runtime_error("Decoded block shorter than target range");
                    auto computed=md5(data.data(),data.size());
                    if(computed!=hex(e.md5_hash,16)) throw std::runtime_error("Decoded MD5 mismatch expected="+hex(e.md5_hash,16)+" computed="+computed);
                } catch(const std::exception& ex) { problem=ex.what(); }
                if(!problem.empty()) {
                    ++failed;
                    event({{"operation","range"},{"partition",pi},{"block",bi},{"reserved",!phase},
                           {"disk_offset",dest},{"length",expected},{"source_offset",e.file_position},
                           {"stored_length",e.block_length},{"status","unrecoverable"},{"reason",problem},
                           {"substitution","unallocated VHDX range reads as zero"}});
                } else {
                    if(!dryRun) targetWrite(dest,data.data(),(DWORD)expected);
                    written+=expected;
                    if(overrideEntry) {
                        ++overrides;
                        event({{"operation","range"},{"partition",pi},{"block",bi},{"disk_offset",dest},{"length",expected},
                               {"source_offset",e.file_position},{"status","reconstructed-unverified"},
                               {"reason",spec["overrides"][std::to_string(bi)]["reason"]}});
                    } else ++verified;
                }
                if(std::chrono::steady_clock::now()-heartbeat>std::chrono::seconds(5)) {
                    std::cout<<"partition="<<pi<<" block="<<bi<<"/"<<entries.size()<<" verified="<<verified
                             <<" failed="<<failed<<" unknown_zero="<<absent<<" bytes="<<written<<std::endl;
                    event({{"operation","progress"},{"partition",pi},{"block",bi},{"verified_blocks",verified},
                           {"failed_blocks",failed},{"unknown_zero_blocks",absent},{"written_bytes",written}});
                    heartbeat=std::chrono::steady_clock::now();
                }
            }
            flushGap();
        }
    }
    if(!dryRun && !FlushFileBuffers(target.h)) throw std::runtime_error("Flush target failed");
    hashUntil(size);
    unsigned char sourceHash[SHA256_DIGEST_LENGTH]; SHA256_Final(sourceHash,&sourceDigest);
    if(size!=std::filesystem::file_size(source)||sourceWriteTime!=std::filesystem::last_write_time(source))
        throw std::runtime_error("Source size/timestamp changed during recovery");
    event({{"operation","source_fingerprint"},{"sha256",hex(sourceHash,sizeof(sourceHash))},{"source_size",size},{"size_and_write_time_unchanged",true}});
    if(!dryRun && !qemu.empty() && !direct) {
        CloseHandle(target.h); target.h=INVALID_HANDLE_VALUE;
        event({{"operation","vhdx_conversion_begin"}});
        std::wstring command=L"\""+qemu+L"\" convert -p -f raw -O vhdx -o subformat=dynamic,block_size=2097152 \""+rawPath+L"\" \""+output+L"\"";
        STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION process{};
        if(!CreateProcessW(qemu.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&process))
            throw std::runtime_error("Cannot launch qemu-img: "+std::to_string(GetLastError()));
        CloseHandle(process.hThread);
        while(WaitForSingleObject(process.hProcess,5000)==WAIT_TIMEOUT) {
            std::cout<<"Converting recovered sparse disk to VHDX..."<<std::endl;
        }
        DWORD code=1; GetExitCodeProcess(process.hProcess,&code); CloseHandle(process.hProcess);
        if(code!=0) throw std::runtime_error("qemu-img conversion failed: "+std::to_string(code)+"; sparse recovery retained");
        event({{"operation","vhdx_conversion_complete"},{"intermediate_retained",true}});
    }
    event({{"operation","complete"},{"verified_blocks",verified},{"failed_blocks",failed},
           {"unknown_zero_blocks",absent},{"reconstructed_blocks",overrides},{"written_bytes",written},
           {"status",(failed||absent||overrides)?"partial":"verified"}});
    std::cout<<"Recovery finished: verified="<<verified<<" failed="<<failed<<" unknown_zero="<<absent
             <<" reconstructed="<<overrides<<". "<<((failed||absent||overrides)?"Partial recovery; see manifest.":"All stored blocks verified.")<<std::endl;
    return (failed||absent||overrides)?2:0;
}
}
