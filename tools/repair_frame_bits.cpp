// Exhaustive single-bit repair of a bounded Zstd frame, accepted ONLY against
// its original decoded MD5. Input is immutable; output is exclusively created.
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <chrono>
#include "zstd/zstd.h"
#include "openssl/md5.h"

int wmain(int argc,wchar_t** argv) {
  try {
    if(argc!=5) throw std::runtime_error("Usage: repair_frame_bits encoded.bin repaired.bin original_decoded_md5 decoded_length");
    std::filesystem::path input(argv[1]),output(argv[2]);
    if(std::filesystem::exists(output))throw std::runtime_error("Output exists");
    auto size=std::filesystem::file_size(input);
    auto decodedSize=std::stoull(argv[4]);
    if(!size||size>5*1024*1024||!decodedSize||decodedSize>4*1024*1024)throw std::runtime_error("Frame bounds");
    std::wstring expectedText(argv[3]);std::array<unsigned char,16> expected{},digest{};
    if(expectedText.size()!=32)throw std::runtime_error("Expected MD5 length");
    for(size_t i=0;i<16;++i) {
      auto text=expectedText.substr(i*2,2);size_t end=0;auto value=std::stoul(text,&end,16);
      if(end!=2)throw std::runtime_error("Expected MD5 syntax");expected[i]=(unsigned char)value;
    }
    std::ifstream stream(input,std::ios::binary);std::vector<unsigned char> encoded((size_t)size),decoded((size_t)decodedSize);
    if(!stream.read(reinterpret_cast<char*>(encoded.data()),encoded.size()))throw std::runtime_error("Input read");
    auto context=ZSTD_createDCtx();if(!context)throw std::runtime_error("Zstd allocation");
    auto valid=[&]() {
      auto n=ZSTD_decompressDCtx(context,decoded.data(),decoded.size(),encoded.data(),encoded.size());
      if(ZSTD_isError(n)||n!=decoded.size())return false;
      MD5(decoded.data(),decoded.size(),digest.data());return digest==expected;
    };
    if(valid()) {ZSTD_freeDCtx(context);std::cout<<"{\"status\":\"input-already-matches\"}\n";return 0;}
    size_t matches=0,foundOffset=0;unsigned foundBit=0;auto began=std::chrono::steady_clock::now();
    for(size_t offset=0;offset<encoded.size();++offset) {
      for(unsigned bit=0;bit<8;++bit) {
        encoded[offset]^=1u<<bit;
        if(valid()) {++matches;foundOffset=offset;foundBit=bit;}
        encoded[offset]^=1u<<bit;
      }
      if(offset%10000==0)std::cerr<<"tested_bytes="<<offset<<" total="<<encoded.size()<<" matches="<<matches<<std::endl;
    }
    ZSTD_freeDCtx(context);
    auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-began).count();
    if(matches!=1) {std::cout<<"{\"status\":\"no-unique-single-bit-repair\",\"matches\":"<<matches<<",\"elapsed_ms\":"<<elapsed<<"}\n";return 2;}
    unsigned before=encoded[foundOffset];encoded[foundOffset]^=1u<<foundBit;
    HANDLE file=CreateFileW(output.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Exclusive output create");
    DWORD actual=0;bool ok=WriteFile(file,encoded.data(),(DWORD)encoded.size(),&actual,nullptr)&&actual==encoded.size();CloseHandle(file);
    if(!ok)throw std::runtime_error("Output write");
    std::cout<<"{\"status\":\"unique-original-md5-repair\",\"byte_offset\":"<<foundOffset<<",\"bit\":"<<foundBit<<",\"original_byte\":"<<before<<",\"repaired_byte\":"<<unsigned(encoded[foundOffset])<<",\"elapsed_ms\":"<<elapsed<<"}\n";
    return 0;
  } catch(const std::exception& e) {std::cerr<<e.what()<<std::endl;return 1;}
}
