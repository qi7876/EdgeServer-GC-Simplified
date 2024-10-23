/**
 * @file ecallFreqTwoIndex.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of frequency-two index
 * @version 0.1
 * @date 2021-01-15
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/ecallFreqIndex.h"

/**
 * @brief Construct a new Ecall Frequency Index object
 * 
 */
EcallFreqIndex::EcallFreqIndex() {
    topThreshold_ = Enclave::topKParam_;
    insideDedupIndex_ = new EcallEntryHeap();
    insideDedupIndex_->SetHeapSize(topThreshold_);
    cmSketch_ = new EcallCMSketch(sketchWidth_, sketchDepth_);

    if (ENABLE_SEALING) {
        if (!this->LoadDedupIndex()) {
            //Enclave::Logging(myName_.c_str(), "do not need to load the index.\n");
        }
    }
    //Enclave::Logging(myName_.c_str(), "init the EcallFreqIndex.\n");
}

/**
 * @brief Destroy the Ecall Frequency Index object
 * 
 */
EcallFreqIndex::~EcallFreqIndex() {
    // size_t heapSize = insideDedupIndex_->Size();
    // fprintf(stdout, "the number of entry: %lu\n", heapSize);
    // for (size_t i = 0; i < heapSize; i++) {
    //     fprintf(stdout, "%u\n", insideDedupIndex_->TopEntry());
    //     if (insideDedupIndex_->Size() > 1) {
    //         insideDedupIndex_->Pop();
    //     } else {
    //         break;
    //     }
    // }

    if (ENABLE_SEALING) {
        this->PersistDedupIndex();
    }
    delete insideDedupIndex_;
    delete cmSketch_;
    Ocall_Printf("\n\n");
    Enclave::Logging(myName_.c_str(), "========EdgeServer Info========\n");
    //Enclave::Logging(myName_.c_str(), "logical chunk num: %lu\n", _logicalChunkNum);
    Enclave::Logging(myName_.c_str(), "total logical data size: %lu MiB\n", _logicalDataSize / (1024*1024));
    //Enclave::Logging(myName_.c_str(), "unique chunk num: %lu\n", _uniqueChunkNum);
    //Enclave::Logging(myName_.c_str(), "unique data size: %lu\n", _uniqueDataSize);
    Enclave::Logging(myName_.c_str(), "total write data size: %lu MiB\n", _compressedDataSize / (1024*1024)); 
    // Enclave::Logging(myName_.c_str(), "inside dedup chunk num: %lu\n", insideDedupChunkNum_);
    // Enclave::Logging(myName_.c_str(), "inside dedup data size: %lu\n", insideDedupDataSize_);
    Enclave::Logging(myName_.c_str(), "===================================\n");
    Ocall_Printf("\n\n");
}

/**
 * @brief update the inside-enclave with only freq
 * 
 * @param ChunkFp the chunk fp
 * @param currentFreq the current frequency
 */
void EcallFreqIndex::UpdateInsideIndexFreq(const string& chunkFp, uint32_t currentFreq) {
    insideDedupIndex_->Update(chunkFp, currentFreq);
    return ;
}

/**
 * @brief process the tailed batch when received the end of the recipe flag
 * 
 * @param upOutSGX the pointer to enclave-related var
 */
void EcallFreqIndex::ProcessTailBatch(UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;
    Recipe_t* inSecureRecipe = &sgxClient->_inSecureRecipe;
    Recipe_t* inKeyRecipe = &sgxClient->_inKeyRecipe;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    if (inRecipe->recipeNum != 0) {
        // the out-enclave info
        Recipe_t* outRecipe = (Recipe_t*)upOutSGX->outRecipe;
        Recipe_t* outSecureRecipe = (Recipe_t*)upOutSGX->outSecureRecipe;
        Recipe_t* outKeyRecipe = (Recipe_t*)upOutSGX->outKeyRecipe;

        cryptoObj_->EncryptWithKey(cipherCtx, inRecipe->entryList,
            inRecipe->recipeNum * CHUNK_HASH_SIZE, Enclave::indexQueryKey_,
            outRecipe->entryList);
        // cryptoObj_->EncryptWithKey(cipherCtx, inSecureRecipe->entryList,
        //     inRecipe->recipeNum * CHUNK_HASH_SIZE, Enclave::indexQueryKey_,
        //     outSecureRecipe->entryList);
        memcpy(outSecureRecipe->entryList, inSecureRecipe->entryList, inRecipe->recipeNum * CHUNK_HASH_SIZE);
        cryptoObj_->EncryptWithKey(cipherCtx, inKeyRecipe->entryList,
            inRecipe->recipeNum * MLE_KEY_SIZE, masterKey,
            outKeyRecipe->entryList);
        outRecipe->recipeNum = inRecipe->recipeNum;

        Ocall_UpdateFileRecipe(upOutSGX->outClient);
        
        inRecipe->recipeNum = 0;
    }

    // inContainer还有东西，写入out container
    if (sgxClient->_inContainer.curHeaderSize != 0) {
        // curNum转换为4*char
        uint8_t curNumChar[4];
        curNumChar[0] = sgxClient->_inContainer.curNum >> 24;
        curNumChar[1] = sgxClient->_inContainer.curNum >> 16;
        curNumChar[2] = sgxClient->_inContainer.curNum >> 8;
        curNumChar[3] = sgxClient->_inContainer.curNum;

        // 依次复制curNum, header, content
        memcpy(upOutSGX->curContainer->body, curNumChar, 4);
        cryptoObj_->EncryptWithKey(cipherCtx, sgxClient->_inContainer.headerBuf,
            sgxClient->_inContainer.curHeaderSize, Enclave::indexQueryKey_, upOutSGX->curContainer->body + 4);
        memcpy(upOutSGX->curContainer->body + 4 + sgxClient->_inContainer.curHeaderSize, 
            sgxClient->_inContainer.contentBuf, sgxClient->_inContainer.curContentSize);

        upOutSGX->curContainer->currentSize = 4 + sgxClient->_inContainer.curHeaderSize + 
            sgxClient->_inContainer.curContentSize;
    }

    return ;
}

/**
 * @brief persist the deduplication index into the disk
 * 
 * @return true success
 * @return false fail
 */
bool EcallFreqIndex::PersistDedupIndex() {
    size_t itemNum;
    bool persistenceStatus;
    size_t requiredBufferSize = 0;
    size_t offset = 0;
    // a pointer to store tmp buffer
    uint8_t* tmpBuffer = NULL;

    // step-1: persist the sketch state
    uint32_t** counterArrary = cmSketch_->GetCounterArray();
    Ocall_InitWriteSealedFile(&persistenceStatus, SEALED_SKETCH);
    if (persistenceStatus == false) {
        Ocall_SGX_Exit_Error("EcallFreqIndex: cannot init the sketch sealed file.");
    }

    for (size_t i = 0; i < sketchDepth_; i++) {
        Enclave::WriteBufferToFile((uint8_t*)counterArrary[i], sketchWidth_ * sizeof(uint32_t), SEALED_SKETCH);
    }
    Ocall_CloseWriteSealedFile(SEALED_SKETCH);

    // step-2: persist the min-heap 
    offset = 0;
    Ocall_InitWriteSealedFile(&persistenceStatus, SEALED_FREQ_INDEX);
    if (persistenceStatus == false) {
        Ocall_SGX_Exit_Error("EcallFreqIndex: cannot init the heap sealed file.");
    }

    auto heapPtr = &insideDedupIndex_->_heap;
    itemNum = heapPtr->size();
    requiredBufferSize = sizeof(size_t) + itemNum * (CHUNK_HASH_SIZE + sizeof(HeapItem_t));
    tmpBuffer = (uint8_t*) malloc(sizeof(uint8_t) * requiredBufferSize);
    memcpy(tmpBuffer + offset, &itemNum, sizeof(size_t));
    offset += sizeof(size_t);
    for (size_t i = 0; i < itemNum; i++) {
        memcpy(tmpBuffer + offset, &(*heapPtr)[i]->first[0], CHUNK_HASH_SIZE);
        offset += CHUNK_HASH_SIZE;
        memcpy(tmpBuffer + offset, &(*heapPtr)[i]->second, sizeof(HeapItem_t));
        offset += sizeof(HeapItem_t);
    }
    Enclave::WriteBufferToFile(tmpBuffer, requiredBufferSize, SEALED_FREQ_INDEX);
    Ocall_CloseWriteSealedFile(SEALED_FREQ_INDEX);

    free(tmpBuffer);
    return true;
}

/**
 * @brief read the hook index from sealed data
 * 
 * @return true success
 * @return false fail
 */
bool EcallFreqIndex::LoadDedupIndex() {
    size_t itemNum;
    string tmpChunkFp;
    tmpChunkFp.resize(CHUNK_HASH_SIZE, 0);
    size_t sealedDataSize;
    size_t offset = 0;

    // step-1: load the sketch state 
    uint32_t** counterArray = cmSketch_->GetCounterArray();
    Ocall_InitReadSealedFile(&sealedDataSize, SEALED_SKETCH);
    if (sealedDataSize == 0) {
        return false;
    }   

    for (size_t i = 0; i < sketchDepth_; i++) {
        Enclave::ReadFileToBuffer((uint8_t*)counterArray[i], sizeof(uint32_t) * sketchWidth_, SEALED_SKETCH);
    }
    Ocall_CloseReadSealedFile(SEALED_SKETCH);

    // step-2: load the min-heap 
    auto heapPtr = &insideDedupIndex_->_heap;
    auto indexPtr = &insideDedupIndex_->_index;
    Ocall_InitReadSealedFile(&sealedDataSize, SEALED_FREQ_INDEX);
    if (sealedDataSize == 0) {
        return false;
    }

    uint8_t* tmpIndexBuffer = (uint8_t*) malloc(sealedDataSize * sizeof(uint8_t));
    Enclave::ReadFileToBuffer(tmpIndexBuffer, sealedDataSize, SEALED_FREQ_INDEX);
    memcpy(&itemNum, tmpIndexBuffer + offset, sizeof(size_t));
    offset += sizeof(size_t);
    HeapItem_t tmpItem;
    string tmpFp;
    tmpFp.resize(CHUNK_HASH_SIZE, 0);
    for (size_t i = 0; i < itemNum; i++) {
        memcpy(&tmpChunkFp[0], tmpIndexBuffer + offset, CHUNK_HASH_SIZE);
        offset += CHUNK_HASH_SIZE;
        memcpy(&tmpItem, tmpIndexBuffer + offset, sizeof(HeapItem_t));
        offset += sizeof(HeapItem_t);
        auto tmpIt = indexPtr->insert({tmpChunkFp, tmpItem}).first;
        heapPtr->push_back(tmpIt);
    }
    Ocall_CloseReadSealedFile(SEALED_FREQ_INDEX);

    free(tmpIndexBuffer);
    return true; 
}

/**
 * @brief check whether add this chunk to the heap
 * 
 * @param chunkFreq the chunk freq
 */
bool EcallFreqIndex::CheckIfAddToHeap(uint32_t chunkFreq) {
    if (insideDedupIndex_->Size() < topThreshold_) {
        return true;
    }
    // step: get the min-freq of current heap
    uint32_t currentMin = insideDedupIndex_->TopEntry();
    if (chunkFreq >= currentMin) {
        // the input chunk freq is larger than existing one, can add to the heap
        return true;
    }
    // the input chunk freq is lower than existsing one, cannot add to the heap 
    return false;
}

/**
 * @brief Add the information of this chunk to the heap
 * 
 * @param chunkFreq the chunk freq
 * @param chunkAddr the chunk address
 * @param chunkFp the chunk fp
 */
void EcallFreqIndex::AddChunkToHeap(uint8_t* secureChunkHash, uint32_t chunkFreq, const string& chunkFp) {
    HeapItem_t tmpHeapEntry;
    // pop the minimum item
    if (insideDedupIndex_->Size() == topThreshold_) {
        insideDedupIndex_->Pop();
    }
    // insert the new one
    memcpy(tmpHeapEntry.secureChunkHash, secureChunkHash, CHUNK_HASH_SIZE);
    tmpHeapEntry.chunkFreq = chunkFreq;
    insideDedupIndex_->Add(chunkFp, tmpHeapEntry);
    return ;
}

#if (IMPACT_OF_TOP_K == 0)

/**
 * @brief process one batch
 * 
 * @param recvChunkBuf the recv chunk buffer
 * @param upOutSGX the pointer to the enclave-related var 
 */
void EcallFreqIndex::ProcessOneBatch(SendMsgBuffer_t* recvChunkBuf, 
    UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    EVP_MD_CTX* mdCtx = sgxClient->_mdCtx;
    uint8_t* recvBuffer = sgxClient->_recvBuffer;
    uint8_t* sessionKey = sgxClient->_sessionKey;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;
    Recipe_t* inSecureRecipe = &sgxClient->_inSecureRecipe;
    Recipe_t* inKeyRecipe = &sgxClient->_inKeyRecipe;
    InQueryEntry_t* inQueryBase = sgxClient->_inQueryBase;
    OutQueryEntry_t* outQueryBase = upOutSGX->outQuery->outQueryBase;

    // tmp var
    OutQueryEntry_t* outQueryEntry = outQueryBase;
    uint32_t outQueryNum = 0;
    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);

    // decrypt the received data with the session key
    cryptoObj_->SessionKeyDec(cipherCtx, recvChunkBuf->dataBuffer,
        recvChunkBuf->header->dataSize, sessionKey, recvBuffer);
    
    // get the chunk num
    uint32_t chunkNum = recvChunkBuf->header->currentItemNum;

    // -------------------------------
    // 计算FP和MLEKey                 |
    // -------------------------------

    // compute the hash of each chunk
    InQueryEntry_t* inQueryEntry = inQueryBase;
    size_t currentOffset = 0;
    for (size_t i = 0; i < chunkNum; i++) {
        // compute the hash over the plaintext chunk
        memcpy(&inQueryEntry->chunkSize, recvBuffer + currentOffset,
            sizeof(uint32_t));
        currentOffset += sizeof(uint32_t);

        cryptoObj_->GenerateHash(mdCtx, recvBuffer + currentOffset,
            inQueryEntry->chunkSize, inQueryEntry->chunkHash);
        
        // 生成MLEKey
        memcpy(inQueryEntry->mleKey, inQueryEntry->chunkHash, MLE_KEY_SIZE);

        currentOffset += inQueryEntry->chunkSize;
        inQueryEntry++;
    }
    // Enclave::Logging(myName_.c_str(), "ok for hash\n");

{
#if (MULTI_CLIENT == 1)
    Enclave::sketchLck_.lock();
#endif
    // update the sketch and freq
    inQueryEntry = inQueryBase;
    for (size_t i = 0; i < chunkNum; i++) {
        cmSketch_->Update(inQueryEntry->chunkHash, CHUNK_HASH_SIZE, 1);
        inQueryEntry->chunkFreq = cmSketch_->Estimate(inQueryEntry->chunkHash,
            CHUNK_HASH_SIZE);
        inQueryEntry++;
    }
    // Enclave::Logging(myName_.c_str(), "ok for feq\n");
#if (MULTI_CLIENT == 1)
    Enclave::sketchLck_.unlock();
#endif
}

{
#if (MULTI_CLIENT == 1)
    Enclave::topKIndexLck_.lock();
#endif
    // check the top-k index
    uint32_t minFreq;
    if (insideDedupIndex_->Size() == topThreshold_) {
        minFreq = insideDedupIndex_->TopEntry();
    } else {
        minFreq = 0;
    }
    inQueryEntry = inQueryBase;
    
    for (size_t i = 0; i < chunkNum; i++) {
        tmpHashStr.assign((char*)inQueryEntry->chunkHash, CHUNK_HASH_SIZE);
        auto findRes = sgxClient->_localIndex.find(tmpHashStr);
        if(findRes != sgxClient->_localIndex.end()) {
            // it exist in this local batch index
            uint32_t offset = findRes->second;
            InQueryEntry_t* findEntry = inQueryBase + offset; 
            switch (findEntry->dedupFlag) {
                case UNIQUE: {
                    // this chunk is unique for the top-k index, but duplicate for the local index
                    inQueryEntry->dedupFlag = TMP_UNIQUE;
                    inQueryEntry->entryOffset = offset;
                    break;
                }
                case DUPLICATE: {
                    // this chunk is duplicate for the heap and the local index
                    inQueryEntry->dedupFlag = TMP_DUPLICATE;
                    inQueryEntry->entryOffset = offset;
                    break;
                }
                default: {
                    Ocall_SGX_Exit_Error("EcallFreqIndex: wrong in-enclave dedup flag");
                }
            }

            // update the freq
            findEntry->chunkFreq = inQueryEntry->chunkFreq;
        } else {
            // it does not exists in the batch index, compare the freq 
            if (inQueryEntry->chunkFreq < minFreq) {
                // its frequency is smaller than the minimum value in the heap, must not exist in the heap
                // encrypt its fingerprint, write to the outside buffer
                cryptoObj_->IndexAESCMCEnc(cipherCtx, inQueryEntry->chunkHash,
                    CHUNK_HASH_SIZE, Enclave::indexQueryKey_, outQueryEntry->chunkHash);
                
                // update the in-enclave query buffer
                inQueryEntry->dedupFlag = UNIQUE;
                inQueryEntry->entryOffset = outQueryNum;

                // update the out-enclave query buffer
                outQueryEntry++;
                outQueryNum++;
            } else {
                // its frequency is higher than the minimum value in the heap, check the heap
                bool topKRes = insideDedupIndex_->Contains(tmpHashStr);
                if (topKRes) {
                    // it exists in the heap, directly read
                    inQueryEntry->dedupFlag = DUPLICATE;

                    memcpy(inQueryEntry->secureChunkHash, 
                        (HeapItem_t*)insideDedupIndex_->GetPriority(tmpHashStr)->secureChunkHash,
                        CHUNK_HASH_SIZE);
                } else {
                    // it does not exist in the heap
                    cryptoObj_->IndexAESCMCEnc(cipherCtx, inQueryEntry->chunkHash, CHUNK_HASH_SIZE,
                        Enclave::indexQueryKey_, outQueryEntry->chunkHash);
                    
                    // update the dedup list
                    inQueryEntry->dedupFlag = UNIQUE;
                    inQueryEntry->entryOffset = outQueryNum;

                    // update the out-enclave query buffer
                    outQueryEntry++;
                    outQueryNum++;
                }
            }

            sgxClient->_localIndex[tmpHashStr] = i;
        }
        inQueryEntry++;
    }
    // Enclave::Logging(myName_.c_str(), "ok for topk\n");
#if (MULTI_CLIENT == 1)
    Enclave::topKIndexLck_.unlock();
#endif
}
    // check the out-enclave index
    if (outQueryNum != 0) {
        upOutSGX->outQuery->queryNum = outQueryNum;
        Ocall_QueryOutIndex(upOutSGX->outClient);
    }
    // Enclave::Logging(myName_.c_str(), "ok for query full fp index\n");

    // process the unique chunks and update the metadata
    inQueryEntry = inQueryBase;
    outQueryEntry = upOutSGX->outQuery->outQueryBase;
    currentOffset = 0;
    string tmpContainerName;
    tmpContainerName.resize(CONTAINER_ID_LENGTH, 0);
    InQueryEntry_t* tmpQueryEntry;
    uint32_t tmpChunkSize;
    for (size_t i = 0; i < chunkNum; i++) {
        tmpChunkSize = inQueryEntry->chunkSize;
        currentOffset += sizeof(uint32_t);
        switch (inQueryEntry->dedupFlag) {
            case DUPLICATE: {
                // it is duplicate for the min-heap
                // update the statistic
                insideDedupChunkNum_++;
                insideDedupDataSize_ += tmpChunkSize;
                break;    
            }
            case TMP_DUPLICATE: {
                // it is also duplicate, for the local index
                tmpQueryEntry = inQueryBase + inQueryEntry->entryOffset;
                memcpy(inQueryEntry->secureChunkHash, tmpQueryEntry->secureChunkHash, CHUNK_HASH_SIZE);
                
                // update the statistic
                insideDedupChunkNum_++;
                insideDedupDataSize_ += tmpChunkSize;
                break;
            }
            case UNIQUE: {
                // it is unique for the top-k index
                switch (outQueryEntry->dedupFlag) {
                    case DUPLICATE: {
                        // it is duplicate for the out-enclave index
                        // cryptoObj_->DecryptWithKey(cipherCtx, (uint8_t*)&outQueryEntry->secureChunkHash,
                        //     CHUNK_HASH_SIZE, Enclave::indexQueryKey_,
                        //     inQueryEntry->secureChunkHash);
                        memcpy(inQueryEntry->secureChunkHash, outQueryEntry->secureChunkHash, CHUNK_HASH_SIZE);
                        break;
                    }
                    case UNIQUE: {
                        // it also unique for the out-enclave index
                        this->ProcessUniqueChunk(inQueryEntry->containerName,
                            recvBuffer + currentOffset, 
                            tmpChunkSize, 
                            upOutSGX, 
                            inQueryEntry->mleKey, 
                            inQueryEntry->chunkHash, 
                            inQueryEntry->secureChunkHash);
                        
                        cryptoObj_->EncryptWithKey(cipherCtx, (uint8_t*)&inQueryEntry->containerName,
                            CONTAINER_ID_LENGTH, Enclave::indexQueryKey_,
                            outQueryEntry->containerName);

                        // cryptoObj_->EncryptWithKey(cipherCtx, (uint8_t*)&inQueryEntry->secureChunkHash,
                        //     CHUNK_HASH_SIZE, Enclave::indexQueryKey_,
                        //     outQueryEntry->secureChunkHash);
                        memcpy(outQueryEntry->secureChunkHash, inQueryEntry->secureChunkHash, CHUNK_HASH_SIZE);

                        // update the statistic
                        _uniqueChunkNum++;
                        _uniqueDataSize += tmpChunkSize;
                        break;
                    }
                    default: {
                        Ocall_SGX_Exit_Error("EcallFreqIndex: wrong out-enclave dedup flag");
                    }
                }
                outQueryEntry++;
                break;
            }
            case TMP_UNIQUE: {
                // it is unique for the top-k index, but duplicate in local index
                tmpQueryEntry = inQueryBase + inQueryEntry->entryOffset;
                memcpy(inQueryEntry->secureChunkHash, tmpQueryEntry->secureChunkHash, CHUNK_HASH_SIZE);
                
                // update statistic
                insideDedupChunkNum_++;
                insideDedupDataSize_ += tmpChunkSize;
                break;
            }
            default: {
                Ocall_SGX_Exit_Error("EcallFreqIndex: wrong chunk status flag");
            }
        }
        // tmpHashStr.assign((char*)inQueryEntry->chunkHash, CHUNK_HASH_SIZE);
        this->UpdateFileRecipe(inQueryEntry, inRecipe, inSecureRecipe, inKeyRecipe, upOutSGX);
        currentOffset += tmpChunkSize;
        inQueryEntry++;

        // update the statistic
        _logicalDataSize += tmpChunkSize;
        _logicalChunkNum++;
    }

    inQueryEntry = inQueryBase;
    currentOffset = 0;
    tmpChunkSize = 0;
    uint8_t tmpSecureChunkHash[CHUNK_HASH_SIZE];
    string secureChunkHashStr1;
    string secureChunkHashStr2;
    uint8_t tmpLZ4ChunkContent[MAX_CHUNK_SIZE];
    uint8_t tmpEncChunkContent[MAX_CHUNK_SIZE];
    for (size_t i = 0; i < chunkNum; i++) {
        secureChunkHashStr1.resize(CHUNK_HASH_SIZE+1, 0);
        secureChunkHashStr2.resize(CHUNK_HASH_SIZE+1, 0);
        secureChunkHashStr1.assign((char*)inQueryEntry->secureChunkHash, CHUNK_HASH_SIZE);
        tmpChunkSize = inQueryEntry->chunkSize;
        currentOffset += sizeof(uint32_t);
        uint32_t tmpCompressedChunkSize = LZ4_compress_fast((char*)(recvBuffer + currentOffset), (char*)tmpLZ4ChunkContent,
            inQueryEntry->chunkSize, inQueryEntry->chunkSize, 3);
        if (tmpCompressedChunkSize > 0) {
            cryptoObj_->EncryptWithKey(cipherCtx, tmpLZ4ChunkContent, tmpCompressedChunkSize,
                inQueryEntry->mleKey, tmpEncChunkContent);
            cryptoObj_->GenerateHash(mdCtx, tmpEncChunkContent, 
                tmpCompressedChunkSize, tmpSecureChunkHash);
        }
        else {
            cryptoObj_->EncryptWithKey(cipherCtx, recvBuffer + currentOffset, inQueryEntry->chunkSize,
                inQueryEntry->mleKey, tmpEncChunkContent);
            cryptoObj_->GenerateHash(mdCtx, tmpEncChunkContent, 
                inQueryEntry->chunkSize, tmpSecureChunkHash);
        }
        secureChunkHashStr2.assign((char*)tmpSecureChunkHash, CHUNK_HASH_SIZE);

        if (secureChunkHashStr1.compare(secureChunkHashStr2)) {
            Enclave::Logging(myName_.c_str(), "-------------------\n");
            Enclave::Logging(myName_.c_str(), "item: %lu\n", i);
            Enclave::Logging(myName_.c_str(), "Chunk type: %d\n", inQueryEntry->dedupFlag);
            Enclave::Logging(myName_.c_str(), "FP1: %s\n", secureChunkHashStr1.c_str());
            Enclave::Logging(myName_.c_str(), "FP2: %s\n", secureChunkHashStr2.c_str());
            Enclave::Logging(myName_.c_str(), "Wrong Secure FP!\n");
            Enclave::Logging(myName_.c_str(), "-------------------\n");
            Ocall_SGX_Exit_Error("Wrong Secure FP!");
        }
        else {
            // Enclave::Logging(myName_.c_str(), "-------------------\n");
            // Enclave::Logging(myName_.c_str(), "secure FP: \n");
            // for (size_t j = 0; j < CHUNK_HASH_SIZE; j++) {
            //     Enclave::Logging(myName_.c_str(), "%d: %d\n", j, inQueryEntry->secureChunkHash[j]);
            // }
            // Enclave::Logging(myName_.c_str(), "-------------------\n");
        }
        currentOffset += inQueryEntry->chunkSize;
        inQueryEntry++;
    }

{
#if (MULTI_CLIENT == 1)
    Enclave::topKIndexLck_.lock();
#endif
    // update the min-heap
    inQueryEntry = inQueryBase;
    for (size_t i = 0; i < chunkNum; i++) {
        if (inQueryEntry->dedupFlag == UNIQUE || 
            inQueryEntry->dedupFlag == DUPLICATE) {
            uint32_t chunkFreq = inQueryEntry->chunkFreq;
            if (this->CheckIfAddToHeap(chunkFreq)) {
                // add this chunk to the top-k index
                tmpHashStr.assign((char*)inQueryEntry->chunkHash, CHUNK_HASH_SIZE);
                if (insideDedupIndex_->Contains(tmpHashStr)) {
                    // it exists in the min-heap
                    this->UpdateInsideIndexFreq(tmpHashStr, chunkFreq);
                } else {
                    // it does not exist in the min-heap
                    this->AddChunkToHeap(inQueryEntry->secureChunkHash, chunkFreq, tmpHashStr);
                }
            }
        }
        inQueryEntry++;
    }
#if (MULTI_CLIENT == 1)
    Enclave::topKIndexLck_.unlock();
#endif
}
    // update the out-enclave index
    upOutSGX->outQuery->queryNum = outQueryNum;
    sgxClient->_localIndex.clear();

    return ;
}

#else

/**
 * @brief process one batch (breakdown version)
 * 
 * @param recvChunkBuf the recv chunk buffer
 * @param upOutSGX the pointer to the enclave-related var 
 */
void EcallFreqIndex::ProcessOneBatch(SendMsgBuffer_t* recvChunkBuf, 
    UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    EVP_MD_CTX* mdCtx = sgxClient->_mdCtx;
    uint8_t* recvBuffer = sgxClient->_recvBuffer;
    uint8_t* sessionKey = sgxClient->_sessionKey;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;

    string tmpChunkAddrStr;
    tmpChunkAddrStr.resize(sizeof(RecipeEntry_t), 0);
    string tmpCipherAddrStr;
    tmpCipherAddrStr.resize(sizeof(RecipeEntry_t), 0);
    size_t currentOffset = 0;

#if (SGX_BREAKDOWN == 1)
    Ocall_GetCurrentTime(&_startTime);
#endif
    // decrypt the received data with the session key
    cryptoObj_->SessionKeyDec(cipherCtx, recvChunkBuf->dataBuffer,
        recvChunkBuf->header->dataSize, sessionKey, recvBuffer);
#if (SGX_BREAKDOWN == 1)
    Ocall_GetCurrentTime(&_endTime);
    _dataTransTime += (_endTime - _startTime);
    _dataTransCount++;
#endif

    // get the chunk num
    uint32_t chunkNum = recvChunkBuf->header->currentItemNum;

    // start to process each chunk
    uint32_t tmpChunkSize = 0;
    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);
    string tmpCipherHashStr;
    tmpCipherHashStr.resize(CHUNK_HASH_SIZE, 0);
    uint32_t chunkFreq = 0;

    // check current min freq in the heap
    uint32_t currentMinFreq;
    HeapItem_t tmpHeapEntry;
    bool status;

    // path one: check the inside enclave index, and update the CMSketch
    for (size_t i = 0; i < chunkNum; i++) {
        // step: compute the hash over the plaintext chunk
        // read the chunk size
        memcpy(&tmpChunkSize, recvBuffer + currentOffset, sizeof(tmpChunkSize));
        currentOffset += sizeof(tmpChunkSize);

#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_startTime);
#endif
        cryptoObj_->GenerateHash(mdCtx, recvBuffer + currentOffset, tmpChunkSize, 
            (uint8_t*)&tmpHashStr[0]);
#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_endTime);
        _fingerprintTime += (_endTime - _startTime);
        _fingerprintCount++;
#endif
        
#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_startTime);
#endif
        // update the sketch 
        cmSketch_->Update((uint8_t*)&tmpHashStr[0], CHUNK_HASH_SIZE, 1);

        // estimate the current frequency
        chunkFreq = cmSketch_->Estimate((uint8_t*)&tmpHashStr[0], CHUNK_HASH_SIZE);
#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_endTime);
        _freqTime += (_endTime - _startTime);
        _freqCount++;
#endif


#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_startTime);
#endif
        if (insideDedupIndex_->Size() == topThreshold_) {
            currentMinFreq = insideDedupIndex_->TopEntry();
        } else {
            currentMinFreq = 0;
        }
#if (SGX_BREAKDOWN == 1)
        Ocall_GetCurrentTime(&_endTime);
        _firstDedupTime += (_endTime - _startTime);
        _firstDedupCount++; 
#endif

        if (chunkFreq < currentMinFreq) {
#if (SGX_BREAKDOWN == 1)
            Ocall_GetCurrentTime(&_startTime);
#endif
            // its frequency is smaller than the minimum value in the min-heap
            cryptoObj_->IndexAESCMCEnc(cipherCtx, (uint8_t*)&tmpHashStr[0], CHUNK_HASH_SIZE, 
                Enclave::indexQueryKey_, (uint8_t*)&tmpCipherHashStr[0]);
            
            status = this->ReadIndexStore(tmpCipherHashStr, tmpCipherAddrStr, upOutSGX);
#if (SGX_BREAKDOWN == 1)
            Ocall_GetCurrentTime(&_endTime);
            _secondDedupTime += (_endTime - _startTime);
            _secondDedupCount++;
#endif

            if (status == false) {
                 // this is unique chunk
                // this chunk does not exist in the outside index
                _uniqueChunkNum++;
                _uniqueDataSize += tmpChunkSize;

                // process one unique chunk
                this->ProcessUniqueChunk((RecipeEntry_t*)&tmpChunkAddrStr[0], 
                    recvBuffer + currentOffset, tmpChunkSize, upOutSGX);
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_startTime);
#endif
                // encrypt the chunk address
                cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t*)&tmpChunkAddrStr[0], sizeof(RecipeEntry_t), 
                    Enclave::indexQueryKey_, (uint8_t*)&tmpCipherAddrStr[0]);
                // update the outside index
                this->UpdateIndexStore(tmpCipherHashStr, &tmpCipherAddrStr[0], sizeof(RecipeEntry_t));
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_endTime);
                _secondDedupTime += (_endTime - _startTime);
                _secondDedupCount++;
#endif
            } else {
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_startTime);
#endif
                 // this is duplicate chunk, decrypt the value
                cryptoObj_->AESCBCDec(cipherCtx, (uint8_t*)&tmpCipherAddrStr[0], sizeof(RecipeEntry_t),
                    Enclave::indexQueryKey_, (uint8_t*)&tmpChunkAddrStr[0]); 
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_endTime);
                _secondDedupTime += (_endTime - _startTime);
                _secondDedupCount++;
#endif
            }
            this->UpdateFileRecipe(tmpChunkAddrStr, inRecipe, upOutSGX);
        } else {
            // check the min-heap
#if (SGX_BREAKDOWN == 1)
            Ocall_GetCurrentTime(&_startTime);
#endif
            bool heapFindResult = insideDedupIndex_->Contains(tmpHashStr);
#if (SGX_BREAKDOWN == 1)
            Ocall_GetCurrentTime(&_endTime);
            _firstDedupTime += (_endTime - _startTime);
            _firstDedupCount++;
#endif
            if (heapFindResult) {
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_startTime);
#endif
                tmpChunkAddrStr.assign((char*)insideDedupIndex_->GetPriority(tmpHashStr),
                    sizeof(RecipeEntry_t));
                // update the frequency
                this->UpdateInsideIndexFreq(tmpHashStr, chunkFreq);
                insideDedupChunkNum_++;
                insideDedupDataSize_ += tmpChunkSize;
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_endTime);
                _firstDedupTime += (_endTime - _startTime);
                _firstDedupCount++;
#endif
            } else {
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_startTime);
#endif
                // this chunk is non-duplicate in current index
                cryptoObj_->IndexAESCMCEnc(cipherCtx, (uint8_t*)&tmpHashStr[0], CHUNK_HASH_SIZE, 
                Enclave::indexQueryKey_, (uint8_t*)&tmpCipherHashStr[0]);
            
                status = this->ReadIndexStore(tmpCipherHashStr, tmpCipherAddrStr, upOutSGX);
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_endTime);
                _secondDedupTime += (_endTime - _startTime);
                _secondDedupCount++;
#endif
                if (status == false) {
                    // this is unique chunk
                    // this chunk does not exist in the outside index
                    _uniqueChunkNum++;
                    _uniqueDataSize += tmpChunkSize;

                    // process one unique chunk
                    this->ProcessUniqueChunk((RecipeEntry_t*)&tmpChunkAddrStr[0], 
                        recvBuffer + currentOffset, tmpChunkSize, upOutSGX);
                    // encrypt the chunk address
#if (SGX_BREAKDOWN == 1)
                    Ocall_GetCurrentTime(&_startTime);
#endif
                    cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t*)&tmpChunkAddrStr[0], sizeof(RecipeEntry_t), 
                        Enclave::indexQueryKey_, (uint8_t*)&tmpCipherAddrStr[0]);

                    // update the outside index
                    this->UpdateIndexStore(tmpCipherHashStr, &tmpCipherAddrStr[0], sizeof(RecipeEntry_t));
#if (SGX_BREAKDOWN == 1)
                    Ocall_GetCurrentTime(&_endTime);
                    _secondDedupTime += (_endTime - _startTime);
                    _secondDedupCount++;
#endif
                } else {
#if (SGX_BREAKDOWN == 1)
                    Ocall_GetCurrentTime(&_startTime);
#endif
                    // this is duplicate chunk, decrypt the value
                    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t*)&tmpCipherAddrStr[0], sizeof(RecipeEntry_t),
                        Enclave::indexQueryKey_, (uint8_t*)&tmpChunkAddrStr[0]); 
#if (SGX_BREAKDOWN == 1)
                    Ocall_GetCurrentTime(&_endTime);
                    _secondDedupTime += (_endTime - _startTime);
                    _secondDedupCount++;
#endif
                }

#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_startTime);
#endif
                this->AddChunkToHeap(chunkFreq, (RecipeEntry_t*)&tmpChunkAddrStr[0],
                    tmpHashStr);
#if (SGX_BREAKDOWN == 1)
                Ocall_GetCurrentTime(&_endTime);
                _firstDedupTime += (_endTime - _startTime);
                _firstDedupCount++;
#endif
            }
            this->UpdateFileRecipe(tmpChunkAddrStr, inRecipe, upOutSGX);
        }
        _logicalDataSize += tmpChunkSize;
        _logicalChunkNum++;
        currentOffset += tmpChunkSize;
    }

#if (SGX_BREAKDOWN == 1)
    Ocall_GetCurrentTime(&_startTime);
#endif
#if (SGX_BREAKDOWN == 1)
    Ocall_GetCurrentTime(&_endTime);
    _testOCallTime += (_endTime - _startTime);
    _testOCallCount++;
#endif 

    return ;
}

#endif