// Exhaustive single-bit repair of a bounded Zstd frame, accepted ONLY against
// its original decoded MD5. Input is immutable; output is exclusively created.
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd/zstd.h"
#include "openssl/md5.h"

int wmain(int argc,wchar_t** argv) {
  try {
    if(argc!=5) throw std::runtime_error("Usage: repair_frame_bits encoded.bin repaired.bin original_decoded_md5|@digest_list.txt decoded_length");
    std::filesystem::path input(argv[1]),output(argv[2]);
    if(std::filesystem::exists(output))throw std::runtime_error("Output exists");
    auto size=std::filesystem::file_size(input);
    auto decodedSize=std::stoull(argv[4]);
    if(!size||size>5*1024*1024||!decodedSize||decodedSize>4*1024*1024)throw std::runtime_error("Frame bounds");
    std::wstring expectedText(argv[3]);std::string expectedAscii;std::array<unsigned char,16> expected{},digest{};
    auto parse=[](const std::wstring& text){std::array<unsigned char,16> value{};if(text.size()!=32)throw std::runtime_error("Expected MD5 length");for(size_t i=0;i<16;++i){size_t end=0;auto n=std::stoul(text.substr(i*2,2),&end,16);if(end!=2||n>255)throw std::runtime_error("Expected MD5 syntax");value[i]=(unsigned char)n;}return value;};
    bool batch=!expectedText.empty()&&expectedText[0]==L'@';std::vector<std::array<unsigned char,16>> targets;
    if(batch){std::filesystem::path listPath(expectedText.substr(1));if(std::filesystem::file_size(listPath)>16*1024*1024)throw std::runtime_error("Digest list bounds");std::ifstream list{listPath};std::string line;while(std::getline(list,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();targets.push_back(parse(std::wstring(line.begin(),line.end())));}if(targets.empty())throw std::runtime_error("Empty digest list");std::sort(targets.begin(),targets.end());targets.erase(std::unique(targets.begin(),targets.end()),targets.end());expectedText=std::wstring(32,L'0');}
    else targets.push_back(parse(expectedText));
    expected=targets.front();auto matchesDigest=[&](const std::array<unsigned char,16>& value){return std::binary_search(targets.begin(),targets.end(),value);};
    for(wchar_t c:expectedText)expectedAscii.push_back(static_cast<char>(c));
    std::ifstream stream(input,std::ios::binary);std::vector<unsigned char> encoded((size_t)size),decoded((size_t)decodedSize);
    if(!stream.read(reinterpret_cast<char*>(encoded.data()),encoded.size()))throw std::runtime_error("Input read");
    auto context=ZSTD_createDCtx();if(!context)throw std::runtime_error("Zstd allocation");
    auto valid=[&]() {
      auto n=ZSTD_decompressDCtx(context,decoded.data(),decoded.size(),encoded.data(),encoded.size());
      if(ZSTD_isError(n)||n!=decoded.size())return false;
      MD5(decoded.data(),decoded.size(),digest.data());return matchesDigest(digest);
    };
    if(valid()) {ZSTD_freeDCtx(context);std::cout<<"{\"status\":\"input-already-matches\"}\n";return 0;}
    // Uncompressed Zstd blocks map encoded payload bits directly to decoded
    // bits. Cache MD5 prefix states instead of rehashing each unchanged prefix.
    // Header/checksum bits and compressed frames retain full decoder testing.
    const size_t absent=~size_t(0);std::vector<size_t> rawMap(encoded.size(),absent);bool raw=false;
    auto n=ZSTD_decompressDCtx(context,decoded.data(),decoded.size(),encoded.data(),encoded.size());
    ZSTD_frameHeader fh{};
    if(!ZSTD_isError(n)&&n==decoded.size()&&ZSTD_getFrameHeader(&fh,encoded.data(),encoded.size())==0) {
      size_t pos=fh.headerSize,logical=0;bool last=false;raw=true;
      while(!last) {
        if(pos+3>encoded.size()){raw=false;break;}
        unsigned header=encoded[pos]|unsigned(encoded[pos+1])<<8|unsigned(encoded[pos+2])<<16;pos+=3;last=header&1;
        size_t bytes=header>>3;
        if(((header>>1)&3)!=0||pos+bytes>encoded.size()||logical+bytes>decoded.size()){raw=false;break;}
        for(size_t i=0;i<bytes;++i) {
          if(encoded[pos+i]!=decoded[logical+i]){raw=false;break;}
          rawMap[pos+i]=logical+i;
        }
        if(!raw)break;pos+=bytes;logical+=bytes;
      }
      raw=raw&&logical==decoded.size()&&pos+(fh.checksumFlag?4:0)==encoded.size();
    }
    std::vector<MD5_CTX> prefixes;
    if(raw) {
      prefixes.resize(decoded.size()/64+1);MD5_CTX p;MD5_Init(&p);prefixes[0]=p;
      for(size_t i=1;i<prefixes.size();++i){MD5_Update(&p,decoded.data()+(i-1)*64,64);prefixes[i]=p;}
    }
    ZSTD_freeDCtx(context);
    std::atomic<size_t> matches{0},tested{0};size_t foundOffset=0;unsigned foundBit=0;std::mutex reportMutex;std::atomic<bool> failed{false};
    auto began=std::chrono::steady_clock::now();
    // Each worker owns its encoded buffer and decoder. Every encoded bit is
    // still tested; parallelism never substitutes a sampled search.
    unsigned jobs=std::min(8u,std::max(1u,std::thread::hardware_concurrency()));
    std::vector<std::thread> workers;
    for(unsigned job=0;job<jobs;++job)workers.emplace_back([&,job]() {
      auto local=encoded;std::vector<unsigned char> out((size_t)decodedSize);auto rawData=decoded;std::array<unsigned char,16> hash{};
      auto ctx=ZSTD_createDCtx();if(!ctx){failed=true;return;}
      size_t lo=encoded.size()*job/jobs,hi=encoded.size()*(job+1)/jobs,pending=0;
      for(size_t offset=lo;offset<hi;++offset) {
        for(unsigned bit=0;bit<8;++bit) {
          local[offset]^=1u<<bit;
          bool candidate=false;
          if(raw&&rawMap[offset]!=absent) {
            size_t at=rawMap[offset],start=at/64*64;rawData[at]^=1u<<bit;auto p=prefixes[at/64];
            MD5_Update(&p,rawData.data()+start,rawData.size()-start);MD5_Final(hash.data(),&p);rawData[at]^=1u<<bit;candidate=matchesDigest(hash);
          } else {
            auto n=ZSTD_decompressDCtx(ctx,out.data(),out.size(),local.data(),local.size());
            if(!ZSTD_isError(n)&&n==out.size()){MD5(out.data(),out.size(),hash.data());candidate=matchesDigest(hash);}
          }
          if(candidate) {
            auto n=ZSTD_decompressDCtx(ctx,out.data(),out.size(),local.data(),local.size());
            if(!ZSTD_isError(n)&&n==out.size()){MD5(out.data(),out.size(),hash.data());if(matchesDigest(hash)){std::lock_guard<std::mutex> lock(reportMutex);++matches;foundOffset=offset;foundBit=bit;}}
          }
          local[offset]^=1u<<bit;
        }
        if(++pending==1000){auto done=tested.fetch_add(pending)+pending;pending=0;std::lock_guard<std::mutex> lock(reportMutex);std::cerr<<"tested_bytes="<<done<<" total="<<encoded.size()<<" matches="<<matches.load()<<std::endl;}
      }
      tested+=pending;ZSTD_freeDCtx(ctx);
    });
    for(auto& worker:workers)worker.join();
    if(failed)throw std::runtime_error("Worker Zstd allocation");
    auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-began).count();
    if(matches!=1) {std::cout<<"{\"status\":\"no-unique-single-bit-repair\",\"original_decoded_md5\":\""<<expectedAscii<<"\",\"decoded_bytes\":"<<decodedSize<<",\"matches\":"<<matches.load()<<",\"tested_bytes\":"<<tested.load()<<",\"raw_prefix_optimization\":"<<(raw?"true":"false")<<",\"workers\":"<<jobs<<",\"elapsed_ms\":"<<elapsed<<"}\n";return 2;}
    unsigned before=encoded[foundOffset];encoded[foundOffset]^=1u<<foundBit;
    HANDLE file=CreateFileW(output.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Exclusive output create");
    DWORD actual=0;bool ok=WriteFile(file,encoded.data(),(DWORD)encoded.size(),&actual,nullptr)&&actual==encoded.size();CloseHandle(file);
    if(!ok)throw std::runtime_error("Output write");
    std::cout<<"{\"status\":\"unique-original-md5-repair\",\"byte_offset\":"<<foundOffset<<",\"bit\":"<<foundBit<<",\"original_byte\":"<<before<<",\"repaired_byte\":"<<unsigned(encoded[foundOffset])<<",\"raw_prefix_optimization\":"<<(raw?"true":"false")<<",\"tested_bytes\":"<<tested.load()<<",\"elapsed_ms\":"<<elapsed<<"}\n";
    return 0;
  } catch(const std::exception& e) {std::cerr<<e.what()<<std::endl;return 1;}
}
