/**
 * @file ecallRecvDecoder.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of enclave-based recv decoder
 * @version 0.1
 * @date 2021-03-02
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/ecallRecvDecoder.h"

/**
 * @brief Construct a new EcallRecvDecoder object
 * 
 */
EcallRecvDecoder::EcallRecvDecoder() {
    cryptoObj_ = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    //Enclave::Logging(myName_.c_str(), "init the RecvDecoder.\n");
}

/**
 * @brief Destroy the Ecall Recv Decoder object
 * 
 */
EcallRecvDecoder::~EcallRecvDecoder() {
    delete(cryptoObj_);
}

/**
 * @brief process a batch of recipes and write chunk to the outside buffer
 * 
 * @param recipeBuffer the pointer to the recipe buffer
 * @param recipeNum the input recipe buffer
 * @param resOutSGX the pointer to the out-enclave var
 * 
 * @return size_t the size of the sended buffer
 */
void EcallRecvDecoder::ProcRecipeBatch(uint8_t* recipeBuffer, uint8_t* keyRecipeBuffer, 
    size_t recipeNum, ResOutSGX_t* resOutSGX) {
    // out-enclave info
    ReqContainer_t* reqContainer = (ReqContainer_t*)resOutSGX->reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer;
    uint8_t** containerArray = reqContainer->containerArray;
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* sessionKey = sgxClient->_sessionKey;
    uint8_t* masterKey = sgxClient->_masterKey;

    string tmpContainerNameStr;
    unordered_map<string, uint32_t> tmpContainerMap;
    tmpContainerMap.reserve(CONTAINER_CAPPING_VALUE);

    // EnclaveRecipeEntry_t tmpEnclaveRecipeEntry;

    // decrypt the recipe file
    cryptoObj_->DecryptWithKey(cipherCtx, recipeBuffer, recipeNum * sizeof(RecipeEntry_t),
        Enclave::indexQueryKey_, sgxClient->_plainRecipeBuffer);
    cryptoObj_->DecryptWithKey(cipherCtx, keyRecipeBuffer, recipeNum * sizeof(RecipeEntry_t),
        masterKey, sgxClient->_plainKeyRecipeBuffer);
    RecipeEntry_t* tmpRecipeEntry;
    tmpRecipeEntry = (RecipeEntry_t*)sgxClient->_plainRecipeBuffer;

    InRestoreEntry_t* inRestoreBase = sgxClient->_inRestoreBase;
    InRestoreEntry_t* inResotreEntry = inRestoreBase;
    OutRestore_t* outRestore = resOutSGX->outRestore;
    OutRestoreEntry_t* outRestoreBase = resOutSGX->outRestore->outRestoreBase;
    OutRestoreEntry_t* outRestoreEntry = outRestoreBase;

    unordered_map<string, RestoreIndexEntry_t> restoreIndex;
    
    // Enclave::Logging(myName_.c_str(), "recipe num: %lu.\n", recipeNum);
    outRestore->restoreNum = 0;
    // 根据每一个FP生成对应的inEntry和outEntry
    for (size_t i = 0; i < recipeNum; i++) {
        memcpy(inResotreEntry->chunkHash, sgxClient->_plainRecipeBuffer + i * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
        memcpy(inResotreEntry->mleKey, sgxClient->_plainKeyRecipeBuffer + i * MLE_KEY_SIZE, MLE_KEY_SIZE);

        cryptoObj_->IndexAESCMCEnc(cipherCtx, inResotreEntry->chunkHash, CHUNK_HASH_SIZE,
            Enclave::indexQueryKey_, outRestoreEntry->chunkHash);

        outRestoreEntry++;
        inResotreEntry++;
    }
    outRestore->restoreNum = recipeNum;

    // 查询FP Index
    Ocall_RestoreGetContainerName(resOutSGX->outClient);
    // Enclave::Logging(myName_.c_str(), "ok for get enc container name.\n");

    inResotreEntry = inRestoreBase;
    outRestoreEntry = outRestoreBase;
    for (size_t i = 0; i < recipeNum; i++) {
        cryptoObj_->DecryptWithKey(cipherCtx, outRestoreEntry->containerName, CONTAINER_ID_LENGTH,
            Enclave::indexQueryKey_, inResotreEntry->containerName);
        outRestoreEntry++;
        inResotreEntry++;
    }
    // Enclave::Logging(myName_.c_str(), "ok for dec container name.\n");

    uint32_t processNum = 0;
    InRestoreEntry_t* startEntry = inRestoreBase;
    InRestoreEntry_t* endEntry = inRestoreBase;
    inResotreEntry = inRestoreBase;
    outRestoreEntry = outRestoreBase;
    while (processNum < recipeNum) {
        tmpContainerNameStr.assign((char*)inResotreEntry->containerName, CONTAINER_ID_LENGTH);
        auto findResult = tmpContainerMap.find(tmpContainerNameStr);
        if (findResult == tmpContainerMap.end()) {
            inResotreEntry->containerID = reqContainer->idNum;
            tmpContainerMap[tmpContainerNameStr] = reqContainer->idNum;
            memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH, 
                tmpContainerNameStr.c_str(), CONTAINER_ID_LENGTH);
            reqContainer->idNum++;
        }
        else {
            inResotreEntry->containerID = findResult->second;
        }

        inResotreEntry++;
        processNum ++;

        // 如果container到达上限，开始处理每个chunk
        if (reqContainer->idNum == CONTAINER_CAPPING_VALUE || processNum == recipeNum) {
            endEntry = inResotreEntry;
            Ocall_GetReqContainers(resOutSGX->outClient);
            // Enclave::Logging(myName_.c_str(), "ok for get container.\n");
            
            this->IndexConstruct(resOutSGX, restoreIndex, containerArray, reqContainer->idNum);
            // Enclave::Logging(myName_.c_str(), "ok for construct index.\n");

            while (startEntry != endEntry) {
                string tmpHashStr;
                tmpHashStr.assign((char*)startEntry->chunkHash, CHUNK_HASH_SIZE);
                auto findResult = restoreIndex.find(tmpHashStr);
                startEntry->chunkOffset = findResult->second.offset;
                startEntry->chunkSize = findResult->second.length;
                uint8_t* containerContent = containerArray[startEntry->containerID];

                this->RecoverOneChunk(startEntry, containerContent, restoreChunkBuf, cipherCtx);

                startEntry++;

                // chunk buf已满，准备传送
                if (restoreChunkBuf->header->currentItemNum % 
                        Enclave::sendChunkBatchSize_ == 0 || processNum == recipeNum) {
                    cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
                        restoreChunkBuf->header->dataSize, sessionKey, sendChunkBuf->dataBuffer);
                    
                    // copy the header to the send buffer
                    restoreChunkBuf->header->messageType = SERVER_RESTORE_CHUNK;
                    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
                    Ocall_SendRestoreData(resOutSGX->outClient);

                    restoreChunkBuf->header->dataSize = 0;
                    restoreChunkBuf->header->currentItemNum = 0;
                }
            }

            // 重置
            reqContainer->idNum = 0;
            tmpContainerMap.clear();
            restoreIndex.clear();
        }
    }

    // for (size_t i = 0; i < recipeNum; i++) {
    //     // parse the recipe entry one-by-one
    //     tmpContainerIDStr.assign((char*)tmpRecipeEntry->containerName, CONTAINER_ID_LENGTH);
    //     tmpEnclaveRecipeEntry.offset = tmpRecipeEntry->offset;
    //     tmpEnclaveRecipeEntry.length = tmpRecipeEntry->length;

    //     auto findResult = tmpContainerMap.find(tmpContainerIDStr);
    //     if (findResult == tmpContainerMap.end()) {
    //         // this is a unique container entry, it does not exist in current local index
    //         tmpEnclaveRecipeEntry.containerID = reqContainer->idNum;
    //         tmpContainerMap[tmpContainerIDStr] = reqContainer->idNum;
    //         memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH, 
    //             tmpContainerIDStr.c_str(), CONTAINER_ID_LENGTH);
    //         reqContainer->idNum++;
    //     } else {
    //         // this is a duplicate container entry, using existing result.
    //         tmpEnclaveRecipeEntry.containerID = findResult->second;
    //     }
    //     sgxClient->_enclaveRecipeBuffer.push_back(tmpEnclaveRecipeEntry);

    //     // judge whether reach the capping value 
    //     if (reqContainer->idNum == CONTAINER_CAPPING_VALUE) {
    //         // start to let outside application to fetch the container data
    //         Ocall_GetReqContainers(resOutSGX->outClient);

    //         // read chunk from the encrypted container buffer, 
    //         // write the chunk to the outside buffer
    //         for (size_t idx = 0; idx < sgxClient->_enclaveRecipeBuffer.size(); idx++) {
    //             uint32_t containerID = sgxClient->_enclaveRecipeBuffer[idx].containerID;
    //             uint32_t offset = sgxClient->_enclaveRecipeBuffer[idx].offset;
    //             uint32_t chunkSize = sgxClient->_enclaveRecipeBuffer[idx].length;
    //             uint8_t* chunkBuffer = containerArray[containerID] + offset;
    //             this->RecoverOneChunk(chunkBuffer, chunkSize, restoreChunkBuf, cipherCtx);
                // if (restoreChunkBuf->header->currentItemNum % 
                //     Enclave::sendChunkBatchSize_ == 0) {
                //     cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
                //         restoreChunkBuf->header->dataSize, sessionKey, sendChunkBuf->dataBuffer);
                    
                //     // copy the header to the send buffer
                //     restoreChunkBuf->header->messageType = SERVER_RESTORE_CHUNK;
                //     memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
                //     Ocall_SendRestoreData(resOutSGX->outClient);

                //     restoreChunkBuf->header->dataSize = 0;
                //     restoreChunkBuf->header->currentItemNum = 0;
                // }
    //         }

    //         // reset 
    //         reqContainer->idNum = 0;
    //         tmpContainerMap.clear();
    //         sgxClient->_enclaveRecipeBuffer.clear();
    //     }
    //     tmpRecipeEntry++;
    // }
    return ;
}

/**
 * @brief process the tail batch of recipes
 * 
 * @param resOutSGX the pointer to the out-enclave var
 */
void EcallRecvDecoder::ProcRecipeTailBatch(ResOutSGX_t* resOutSGX) {
    // out-enclave info
    ReqContainer_t* reqContainer = (ReqContainer_t*)resOutSGX->reqContainer;
    uint8_t** containerArray = reqContainer->containerArray;
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* sessionKey = sgxClient->_sessionKey;

    cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
        restoreChunkBuf->header->dataSize, sessionKey,
        sendChunkBuf->dataBuffer);

    // copy the header to the send buffer
    restoreChunkBuf->header->messageType = SERVER_RESTORE_FINAL;
    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
    Ocall_SendRestoreData(resOutSGX->outClient);

    restoreChunkBuf->header->currentItemNum = 0;
    restoreChunkBuf->header->dataSize = 0;

    return ;
}

/**
 * @brief recover a chunk
 * 
 * @param chunkBuffer the chunk buffer
 * @param chunkSize the chunk size
 * @param restoreChunkBuf the restore chunk buffer
 * @param cipherCtx the pointer to the EVP cipher
 * 
 */
void EcallRecvDecoder::RecoverOneChunk(InRestoreEntry_t* entry, uint8_t* chunkBuffer,
    SendMsgBuffer_t* restoreChunkBuf, EVP_CIPHER_CTX* cipherCtx) {
    uint8_t* outputBuffer = restoreChunkBuf->dataBuffer + 
        restoreChunkBuf->header->dataSize;
    uint8_t decompressedChunk[MAX_CHUNK_SIZE];
    
    // 读取容器chunk数量
    cryptoObj_->DecryptWithKey(cipherCtx, chunkBuffer + entry->chunkOffset, 
        entry->chunkSize, entry->mleKey, decompressedChunk);

    // Enclave::Logging(myName_.c_str(), "pla chunk:\n");
    // for (size_t i = 0; i < entry->chunkSize; i++) {
    //     Enclave::Logging(myName_.c_str(), "%d: %d\n", i, (int)decompressedChunk[i]);
    // }

    // Enclave::Logging(myName_.c_str(), "enc chunk:\n");
    // for (size_t i = 0; i < entry->chunkSize; i++) {
    //     Enclave::Logging(myName_.c_str(), "%d: %d\n", i, (int)(chunkBuffer + entry->chunkOffset)[i]);
    // }

    // Enclave::Logging(myName_.c_str(), "mle key:\n");
    // for (size_t i = 0; i < MLE_KEY_SIZE; i++) {
    //     Enclave::Logging(myName_.c_str(), "%d: %d\n", i, (int)entry->mleKey[i]);
    // }

    // try to decompress the chunk
    int decompressedSize = LZ4_decompress_safe((char*)decompressedChunk, 
        (char*)(outputBuffer + sizeof(uint32_t)), entry->chunkSize, MAX_CHUNK_SIZE);
    if (decompressedSize > 0) {
        // it can do the decompression, write back the decompressed chunk size
        memcpy(outputBuffer, &decompressedSize, sizeof(uint32_t));
        restoreChunkBuf->header->dataSize += sizeof(uint32_t) + decompressedSize; 
    } else {
        // it cannot do the decompression
        memcpy(outputBuffer, &entry->chunkSize, sizeof(uint32_t));
        memcpy(outputBuffer + sizeof(uint32_t), decompressedChunk, entry->chunkSize);
        restoreChunkBuf->header->dataSize += sizeof(uint32_t) + entry->chunkSize;
    }

    restoreChunkBuf->header->currentItemNum++;
    return ;
}

void EcallRecvDecoder::IndexConstruct(ResOutSGX_t* resOutSGX, 
    unordered_map<string, RestoreIndexEntry_t>& restoreIndex, uint8_t** containerArray, uint32_t idNum) {
        
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    uint8_t headerBuf[MAX_CONTAINER_SIZE / 20];
    
    // Enclave::Logging(myName_.c_str(), "index construct.....\n");
    for (size_t i = 0; i < idNum; i++) {
        size_t chunkNum = (containerArray[i][3]) + (containerArray[i][2] << 8) + 
            (containerArray[i][1] << 16) + (containerArray[i][0] << 24);
        // Enclave::Logging(myName_.c_str(), "ok for get chunk num: %lu\n", chunkNum);

        cryptoObj_->DecryptWithKey(cipherCtx, containerArray[i]+4, 
            chunkNum * (CHUNK_HASH_SIZE+8), Enclave::indexQueryKey_, headerBuf);
        // Enclave::Logging(myName_.c_str(), "ok for dec header\n");

        for (size_t j = 0; j < chunkNum; j++) {
            string tmpChunkHash;
            // Enclave::Logging(myName_.c_str(), "start get offset and length\n");
            tmpChunkHash.assign((char*)headerBuf + (j * (CHUNK_HASH_SIZE + 8)), CHUNK_HASH_SIZE);
            // Enclave::Logging(myName_.c_str(), "ok for get hash\n");
            RestoreIndexEntry_t tmpRestoreEntry;
            tmpRestoreEntry.offset = 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 3]) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 2] << 8) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 1] << 16) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 0] << 24) +
                chunkNum * (CHUNK_HASH_SIZE + 8) + 4;
            // Enclave::Logging(myName_.c_str(), "ok for get offset\n");
            tmpRestoreEntry.length = 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 7]) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 6] << 8) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 5] << 16) + 
                (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 4] << 24);
            restoreIndex[tmpChunkHash] = tmpRestoreEntry;
            // Enclave::Logging(myName_.c_str(), "ok for get length\n");
        }
    }
    return ;
}