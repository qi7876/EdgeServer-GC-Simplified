/**
 * @file ecallStorage.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of storage core inside the enclave 
 * @version 0.1
 * @date 2020-12-16
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include "../../include/ecallStorage.h"

/**
 * @brief Construct a new Ecall Storage Core object
 * 
 */
EcallStorageCore::EcallStorageCore() {
    cryptoObj_ = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    //Enclave::Logging(myName_.c_str(), "init the StorageCore.\n");
    
}

 /**
 * @brief Destroy the Ecall Storage Core object
 * 
 */
EcallStorageCore::~EcallStorageCore() {
    delete cryptoObj_;
    // Enclave::Logging(myName_.c_str(), "========StorageCore Info========\n");
    // Enclave::Logging(myName_.c_str(), "write the data size: %lu\n", writtenDataSize_);
    // Enclave::Logging(myName_.c_str(), "write chunk num: %lu\n", writtenChunkNum_);
    // Enclave::Logging(myName_.c_str(), "================================\n");
}

/**
 * @brief save the chunk to the storage serve
 * 
 * @param chunkData the chunk data buffer
 * @param chunkSize the chunk size
 * @param chunkAddr the chunk address (return)
 * @param sgxClient the current client
 * @param upOutSGX the pointer to outside SGX buffer
 */
void EcallStorageCore::SaveChunk(char* chunkData, uint32_t chunkSize,
    uint8_t* containerName, UpOutSGX_t* upOutSGX, uint8_t* chunkHash) {
    // assign a chunk length
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer;
    Container_t* outContainer = upOutSGX->curContainer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    // 如果超过container大小则将container持久化存储
    uint32_t curSize = inContainer->curContentSize + inContainer->curHeaderSize + 4;
    if (curSize + CHUNK_HASH_SIZE + 8 + chunkSize >= MAX_CONTAINER_SIZE) {
        // curNum转换为4*char
        uint8_t curNumChar[4];
        curNumChar[0] = inContainer->curNum >> 24;
        curNumChar[1] = inContainer->curNum >> 16;
        curNumChar[2] = inContainer->curNum >> 8;
        curNumChar[3] = inContainer->curNum;

        // 依次复制curNum, header, content
        memcpy(outContainer->body, curNumChar, 4);

        cryptoObj_->EncryptWithKey(cipherCtx, inContainer->headerBuf,
            inContainer->curHeaderSize, Enclave::indexQueryKey_, outContainer->body + 4);
        
        memcpy(outContainer->body + 4 + inContainer->curHeaderSize, inContainer->contentBuf, inContainer->curContentSize);
        outContainer->currentSize = 4 + inContainer->curHeaderSize + inContainer->curContentSize;
        Ocall_WriteContainer(upOutSGX->outClient);

        // 重置container
        inContainer->curHeaderSize = 0;
        inContainer->curContentSize = 0;
        inContainer->curNum = 0;
    }

    // 把int转换为4*char
    uint8_t offsetChar[4];
    // 写offset
    offsetChar[0] = inContainer->curContentSize >> 24;
    offsetChar[1] = inContainer->curContentSize >> 16;
    offsetChar[2] = inContainer->curContentSize >> 8;
    offsetChar[3] = inContainer->curContentSize;
    uint8_t lengthChar[4];
    lengthChar[0] = chunkSize >> 24;
    lengthChar[1] = chunkSize >> 16;
    lengthChar[2] = chunkSize >> 8;
    lengthChar[3] = chunkSize;

    uint32_t headerWriteOffset = inContainer->curHeaderSize;
    uint32_t contentWriteOffset = inContainer->curContentSize;

    // header包括FP，Offset，Length
    // 写header
    memcpy(inContainer->headerBuf + headerWriteOffset, chunkHash, CHUNK_HASH_SIZE);
    headerWriteOffset += CHUNK_HASH_SIZE;
    memcpy(inContainer->headerBuf + headerWriteOffset, offsetChar, 4);
    headerWriteOffset += 4;
    memcpy(inContainer->headerBuf + headerWriteOffset, lengthChar, 4);
    
    // 修改headerSize
    inContainer->curHeaderSize += CHUNK_HASH_SIZE + 8;
    
    // 写content
    memcpy(inContainer->contentBuf + contentWriteOffset, chunkData, chunkSize);
    
    // 修改contentSize
    inContainer->curContentSize += chunkSize;
    
    // 复制回containerName
    memcpy(containerName, outContainer->containerID, CONTAINER_ID_LENGTH);
    
    // curNum+1
    inContainer->curNum += 1;

    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;

    return;
}

void EcallStorageCore::SaveChunk_RT(char* chunkData, uint32_t chunkSize,
    uint8_t* containerName, RtOutSGX_t* rtOutSGX, uint8_t* chunkHash) {
    // assign a chunk length
    EnclaveClient* sgxClient = (EnclaveClient*)rtOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer_RT;
    Container_t* outContainer = rtOutSGX->curContainer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;

    // 如果超过container大小则将container持久化存储
    uint32_t curSize = inContainer->curContentSize + inContainer->curHeaderSize + 4;
    if (curSize + CHUNK_HASH_SIZE + 8 + chunkSize >= MAX_CONTAINER_SIZE) {
        // curNum转换为4*char
        uint8_t curNumChar[4];
        curNumChar[0] = inContainer->curNum >> 24;
        curNumChar[1] = inContainer->curNum >> 16;
        curNumChar[2] = inContainer->curNum >> 8;
        curNumChar[3] = inContainer->curNum;

        // 依次复制curNum, header, content
        memcpy(outContainer->body, curNumChar, 4);

        cryptoObj_->EncryptWithKey(cipherCtx, inContainer->headerBuf,
            inContainer->curHeaderSize, Enclave::indexQueryKey_, outContainer->body + 4);
        
        memcpy(outContainer->body + 4 + inContainer->curHeaderSize, inContainer->contentBuf, inContainer->curContentSize);
        outContainer->currentSize = 4 + inContainer->curHeaderSize + inContainer->curContentSize;
        Ocall_WriteContainerRT(rtOutSGX->outClient);

        // 重置container
        inContainer->curHeaderSize = 0;
        inContainer->curContentSize = 0;
        inContainer->curNum = 0;
    }

    // 把int转换为4*char
    uint8_t offsetChar[4];
    // 写offset
    offsetChar[0] = inContainer->curContentSize >> 24;
    offsetChar[1] = inContainer->curContentSize >> 16;
    offsetChar[2] = inContainer->curContentSize >> 8;
    offsetChar[3] = inContainer->curContentSize;
    uint8_t lengthChar[4];
    lengthChar[0] = chunkSize >> 24;
    lengthChar[1] = chunkSize >> 16;
    lengthChar[2] = chunkSize >> 8;
    lengthChar[3] = chunkSize;

    uint32_t headerWriteOffset = inContainer->curHeaderSize;
    uint32_t contentWriteOffset = inContainer->curContentSize;

    // header包括FP，Offset，Length
    // 写header
    memcpy(inContainer->headerBuf + headerWriteOffset, chunkHash, CHUNK_HASH_SIZE);
    headerWriteOffset += CHUNK_HASH_SIZE;
    memcpy(inContainer->headerBuf + headerWriteOffset, offsetChar, 4);
    headerWriteOffset += 4;
    memcpy(inContainer->headerBuf + headerWriteOffset, lengthChar, 4);
    
    // 修改headerSize
    inContainer->curHeaderSize += CHUNK_HASH_SIZE + 8;
    
    // 写content
    memcpy(inContainer->contentBuf + contentWriteOffset, chunkData, chunkSize);
    
    // 修改contentSize
    inContainer->curContentSize += chunkSize;
    
    // 复制回containerName
    memcpy(containerName, outContainer->containerID, CONTAINER_ID_LENGTH);
    
    // curNum+1
    inContainer->curNum += 1;

    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;

    return;
}



void EcallStorageCore::SaveChunk_GC(char* chunkData, uint32_t chunkSize,
    uint8_t* containerName, GcOutSGX_t* gcOutSGX, uint8_t* chunkHash) {
    // assign a chunk length
    EnclaveClient* sgxClient = (EnclaveClient*)gcOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer_GC;
    Container_t* outContainer = gcOutSGX->curContainer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;

    // 如果超过container大小则将container持久化存储
    uint32_t curSize = inContainer->curContentSize + inContainer->curHeaderSize + 4;
    if (curSize + CHUNK_HASH_SIZE + 8 + chunkSize >= MAX_CONTAINER_SIZE) {
        // curNum转换为4*char
        uint8_t curNumChar[4];
        curNumChar[0] = inContainer->curNum >> 24;
        curNumChar[1] = inContainer->curNum >> 16;
        curNumChar[2] = inContainer->curNum >> 8;
        curNumChar[3] = inContainer->curNum;

        // 依次复制curNum, header, content
        memcpy(outContainer->body, curNumChar, 4);

        cryptoObj_->EncryptWithKey(cipherCtx, inContainer->headerBuf,
            inContainer->curHeaderSize, Enclave::indexQueryKey_, outContainer->body + 4);
        
        memcpy(outContainer->body + 4 + inContainer->curHeaderSize, inContainer->contentBuf, inContainer->curContentSize);
        outContainer->currentSize = 4 + inContainer->curHeaderSize + inContainer->curContentSize;
        Ocall_WriteContainerGC(gcOutSGX->outClient);

        // 重置container
        inContainer->curHeaderSize = 0;
        inContainer->curContentSize = 0;
        inContainer->curNum = 0;
    }

    // 把int转换为4*char
    uint8_t offsetChar[4];
    // 写offset
    offsetChar[0] = inContainer->curContentSize >> 24;
    offsetChar[1] = inContainer->curContentSize >> 16;
    offsetChar[2] = inContainer->curContentSize >> 8;
    offsetChar[3] = inContainer->curContentSize;
    uint8_t lengthChar[4];
    lengthChar[0] = chunkSize >> 24;
    lengthChar[1] = chunkSize >> 16;
    lengthChar[2] = chunkSize >> 8;
    lengthChar[3] = chunkSize;

    uint32_t headerWriteOffset = inContainer->curHeaderSize;
    uint32_t contentWriteOffset = inContainer->curContentSize;

    // header包括FP，Offset，Length
    // 写header
    memcpy(inContainer->headerBuf + headerWriteOffset, chunkHash, CHUNK_HASH_SIZE);
    headerWriteOffset += CHUNK_HASH_SIZE;
    memcpy(inContainer->headerBuf + headerWriteOffset, offsetChar, 4);
    headerWriteOffset += 4;
    memcpy(inContainer->headerBuf + headerWriteOffset, lengthChar, 4);
    
    // 修改headerSize
    inContainer->curHeaderSize += CHUNK_HASH_SIZE + 8;
    
    // 写content
    memcpy(inContainer->contentBuf + contentWriteOffset, chunkData, chunkSize);
    
    // 修改contentSize
    inContainer->curContentSize += chunkSize;
    
    // 复制回containerName
    memcpy(containerName, outContainer->containerID, CONTAINER_ID_LENGTH);
    
    // curNum+1
    inContainer->curNum += 1;

    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;

    return;
}