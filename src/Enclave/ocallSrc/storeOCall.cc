/**
 * @file encOCall.cpp
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the OCALLs of EncOCALL
 * @version 0.1
 * @date 2020-10-02
 *
 * @copyright Copyright (c) 2020
 *
 */

#include "../include/storeOCall.h"

namespace OutEnclave {
// for upload
StorageCore* storageCoreObj_ = NULL;
AbsDatabase* indexStoreObj_ = NULL;
DataWriter* dataWriterObj_ = NULL;
ofstream outSealedFile_;
ifstream inSealedFile_;

// for restore
EnclaveRecvDecoder* enclaveRecvDecoderObj_ = NULL;
string myName_ = "OCall";

// for migration
EnclaveMigrator* enclaveMigratorObj_ = NULL;

// for lock
pthread_rwlock_t outIdxLck_;
};

using namespace OutEnclave;

/**
 * @brief setup the ocall var
 *
 * @param dataWriterObj the pointer to the data writer
 * @param indexStoreObj the pointer to the index
 * @param storageCoreObj the pointer to the storageCoreObj
 * @param enclaveDecoderObj the pointer to the enclave recvDecoder
 */
void OutEnclave::Init(DataWriter* dataWriterObj,
    AbsDatabase* indexStoreObj,
    StorageCore* storageCoreObj,
    EnclaveRecvDecoder* enclaveRecvDecoderObj,
    EnclaveMigrator* enclaveMigratorObj)
{
    dataWriterObj_ = dataWriterObj;
    indexStoreObj_ = indexStoreObj;
    storageCoreObj_ = storageCoreObj;
    enclaveRecvDecoderObj_ = enclaveRecvDecoderObj;
    enclaveMigratorObj_ = enclaveMigratorObj;

    // init the lck
    pthread_rwlock_init(&outIdxLck_, NULL);
    return;
}

/**
 * @brief destroy the ocall var
 *
 */
void OutEnclave::Destroy()
{
    // destroy the lck
    pthread_rwlock_destroy(&outIdxLck_);
    return;
}

/**
 * @brief persist the buffer to file
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_UpdateFileRecipe(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    Recipe_t* outRecipe = &outClientPtr->_outRecipe;
    Recipe_t* outSecureRecipe = &outClientPtr->_outSecureRecipe;
    Recipe_t* outKeyRecipe = &outClientPtr->_outKeyRecipe;

    storageCoreObj_->UpdateRecipeToFile(outRecipe->entryList,
        outRecipe->recipeNum, outClientPtr->_recipeWriteHandler, HASH);
    storageCoreObj_->UpdateRecipeToFile(outSecureRecipe->entryList,
        outRecipe->recipeNum, outClientPtr->_secureRecipeWriteHandler, HASH);
    storageCoreObj_->UpdateRecipeToFile(outKeyRecipe->entryList,
        outRecipe->recipeNum, outClientPtr->_keyRecipeWriteHandler, KEY);
    outRecipe->recipeNum = 0;
    return;
}

/**
 * @brief exit the enclave with error message
 *
 * @param error_msg the error message
 */
void Ocall_SGX_Exit_Error(const char* error_msg)
{
    tool::Logging(myName_.c_str(), "%s\n", error_msg);
    exit(EXIT_FAILURE);
}

/**
 * @brief dump the inside container to the outside buffer
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_WriteContainer(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
#if (MULTI_CLIENT == 1)
    dataWriterObj_->SaveToFile(outClientPtr->_curContainer);
#else
    outClientPtr->_inputMQ->Push(outClientPtr->_curContainer);
#endif
    // reset current container
    tool::CreateUUID(outClientPtr->_curContainer.containerID,
        CONTAINER_ID_LENGTH);
    outClientPtr->_curContainer.currentSize = 0;
    return;
}

/**
 * @brief printf interface for Ocall
 *
 * @param str input string
 */
void Ocall_Printf(const char* str)
{
    // fprintf(stderr, "**Enclave**: %s", str);
    fprintf(stderr, "%s", str);
}

/**
 * @brief update the outside index store
 *
 * @param ret return result
 * @param key pointer to the key
 * @param keySize the key size
 * @param buffer pointer to the buffer
 * @param bufferSize the buffer size
 */
void Ocall_UpdateIndexStoreBuffer(bool* ret, const char* key, size_t keySize,
    const uint8_t* buffer, size_t bufferSize)
{
    *ret = indexStoreObj_->InsertBothBuffer(key, keySize, (char*)buffer, bufferSize);
    return;
}

/**
 * @brief read the outside index store
 *
 * @param ret return result
 * @param key pointer to the key
 * @param keySize the key size
 * @param retVal pointer to the buffer <return>
 * @param expectedRetValSize the expected buffer size <return>
 * @param outClient the out-enclave client ptr
 */
void Ocall_ReadIndexStore(bool* ret, const char* key, size_t keySize,
    uint8_t** retVal, size_t* expectedRetValSize, void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    *ret = indexStoreObj_->QueryBuffer(key, keySize,
        outClientPtr->_tmpQueryBufferStr);
    (*retVal) = (uint8_t*)&outClientPtr->_tmpQueryBufferStr[0];
    (*expectedRetValSize) = outClientPtr->_tmpQueryBufferStr.size();
    return;
}

bool Ocall_ReadIndexStoreBrief(const char* key, size_t keySize, void* outClient)
{
    bool ret = true;
    ClientVar* outClientPtr = (ClientVar*)outClient;

    ret = indexStoreObj_->QueryBuffer(key, keySize, outClientPtr->_tmpQueryBufferStr);
    if (!ret) {
        return false;
    }
    return ret;
}
/**
 * @brief get current time from the outside
 *
 * @return long current time (usec)
 */
void Ocall_GetCurrentTime(uint64_t* retTime)
{
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    *retTime = currentTime.tv_sec * SEC_2_US + currentTime.tv_usec;
    return;
}

/**
 * @brief init the file output stream
 *
 * @param ret the return result
 * @param sealedFileName the sealed file name
 */
void Ocall_InitWriteSealedFile(bool* ret, const char* sealedFileName)
{
    if (outSealedFile_.is_open()) {
        tool::Logging(myName_.c_str(), "sealed file is already opened: %s\n", sealedFileName);
        *ret = false;
        return;
    }

    outSealedFile_.open(sealedFileName, ios_base::trunc | ios_base::binary);
    if (!outSealedFile_.is_open()) {
        tool::Logging(myName_.c_str(), "cannot open the sealed file.\n");
        *ret = false;
        return;
    }
    *ret = true;
    return;
}

/**
 * @brief write the data to the disk file
 *
 * @param sealedFileName the name of the sealed file
 * @param sealedDataBuffer sealed data buffer
 * @param sealedDataSize sealed data size
 * @return true success
 * @return false fail
 */
void Ocall_WriteSealedData(const char* sealedFileName, uint8_t* sealedDataBuffer, size_t sealedDataSize)
{
    outSealedFile_.write((char*)sealedDataBuffer, sealedDataSize);
    return;
}

/**
 * @brief close the file output stream
 *
 * @param sealedFileName the sealed file name
 */
void Ocall_CloseWriteSealedFile(const char* sealedFileName)
{
    if (outSealedFile_.is_open()) {
        outSealedFile_.close();
        outSealedFile_.clear();
    }
    return;
}

/**
 * @brief Init the unseal file stream
 *
 * @param fileSize the file size
 * @param sealedFileName the sealed file name
 * @return uint32_t the file size
 */
void Ocall_InitReadSealedFile(size_t* fileSize, const char* sealedFileName)
{
    // return OutEnclave::ocallHandlerObj_->InitReadSealedFile(sealedFileName);
    string fileName(sealedFileName);
    // tool::Logging(myName_.c_str(), "print the file name: %s\n", fileName.c_str());
    inSealedFile_.open(fileName, ios_base::binary);

    if (!inSealedFile_.is_open()) {
        // tool::Logging(myName_.c_str(), "sealed file does not exist.\n");
        *fileSize = 0;
        return;
    }

    size_t beginSize = inSealedFile_.tellg();
    inSealedFile_.seekg(0, ios_base::end);
    *fileSize = inSealedFile_.tellg();
    *fileSize = *fileSize - beginSize;

    // reset
    inSealedFile_.clear();
    inSealedFile_.seekg(0, ios_base::beg);

    return;
}

/**
 * @brief close the file input stream
 *
 * @param sealedFileName the sealed file name
 */
void Ocall_CloseReadSealedFile(const char* sealedFileName)
{
    if (inSealedFile_.is_open()) {
        inSealedFile_.close();
    }
    return;
}

/**
 * @brief read the sealed data from the file
 *
 * @param sealedFileName the sealed file
 * @param dataBuffer the data buffer
 * @param sealedDataSize the size of sealed data
 */
void Ocall_ReadSealedData(const char* sealedFileName, uint8_t* dataBuffer,
    uint32_t sealedDataSize)
{
    inSealedFile_.read((char*)dataBuffer, sealedDataSize);
    return;
}

/**
 * @brief Print the content of the buffer
 *
 * @param buffer the input buffer
 * @param len the length in byte
 */
void Ocall_PrintfBinary(const uint8_t* buffer, size_t len)
{
    fprintf(stderr, "**Enclave**: ");
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x", buffer[i]);
    }
    fprintf(stderr, "\n");
    return;
}

/**
 * @brief Get the required container from the outside application
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_GetReqContainers(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    enclaveRecvDecoderObj_->GetReqContainers(outClientPtr);
    return;
}
// for migration
void Ocall_GetReqContainers_MR(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    enclaveMigratorObj_->GetReqContainer(outClientPtr);
    return;
}

/**
 * @brief send the restore chunks to the client
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_SendRestoreData(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    enclaveRecvDecoderObj_->SendBatchChunks(
        &outClientPtr->_sendChunkBuf,
        outClientPtr->_clientSSL);
    return;
}

void Ocall_SendMigrationData(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    enclaveMigratorObj_->SendBatchChunks(
        &outClientPtr->_sendChunkBuf_MR,
        outClientPtr->_clientSSL);
    return;
}

/**
 * @brief query the outside deduplication index
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_QueryOutIndex(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutQuery_t* outQuery = &outClientPtr->_outQuery;
    OutQueryEntry_t* entry = outQuery->outQueryBase;

    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);

    bool queryResult;
    for (size_t i = 0; i < outQuery->queryNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)entry->chunkHash,
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (queryResult) {
            // this chunk is duplicate in the outside index
            // store the query result in the buffer
            entry->dedupFlag = DUPLICATE;
            FPIndexEntry_t FPIndexEntry;
            memcpy(&FPIndexEntry, tmpFPIndexEntryStr.c_str(), sizeof(FPIndexEntry_t));

            memcpy(entry->secureChunkHash, FPIndexEntry.secureChunkHash, CHUNK_HASH_SIZE);
            memcpy(entry->containerName, FPIndexEntry.containerName, CONTAINER_ID_LENGTH);
        } else {
            entry->dedupFlag = UNIQUE;
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_RestoreGetContainerName(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutRestore_t* outRestore = &outClientPtr->_outRestore;
    OutRestoreEntry_t* entry = outRestore->outRestoreBase;

    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);

    bool queryResult;
    for (size_t i = 0; i < outRestore->restoreNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)entry->chunkHash,
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (queryResult) {
            // this chunk is duplicate in the outside index
            // store the query result in the buffer
            // printf("resstore ocall find!\n");
            FPIndexEntry_t FPIndexEntry;
            memcpy(&FPIndexEntry, tmpFPIndexEntryStr.c_str(), sizeof(FPIndexEntry_t));

            memcpy(entry->containerName, FPIndexEntry.containerName, CONTAINER_ID_LENGTH);
        } else {
            printf("restore ocall err, no cor FP!!!\n");
            tool::PrintBinaryArray(entry->chunkHash, CHUNK_HASH_SIZE);
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

/**
 * @brief update the outside deduplication index
 *
 * @param outClient the out-enclave client ptr
 */
void Ocall_UpdateOutIndex(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_wrlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutQuery_t* outQuery = &outClientPtr->_outQuery;
    OutQueryEntry_t* entry = outQuery->outQueryBase;
    for (size_t i = 0; i < outQuery->queryNum; i++) {
        // update the outside index
        if (entry->dedupFlag == UNIQUE) {
            // this is unique for the outside index, update the outside index
            FPIndexEntry_t tmpFPIndexEntry;
            memcpy(tmpFPIndexEntry.secureChunkHash, entry->secureChunkHash, CHUNK_HASH_SIZE);
            memcpy(tmpFPIndexEntry.containerName, entry->containerName, CONTAINER_ID_LENGTH);

            indexStoreObj_->InsertBothBuffer((char*)entry->chunkHash, CHUNK_HASH_SIZE,
                (char*)&tmpFPIndexEntry, sizeof(FPIndexEntry_t));
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_UpdateOutIndexRT(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_wrlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutQuery_t* outQuery = &outClientPtr->_outQuery_RT;
    OutQueryEntry_t* entry = outQuery->outQueryBase;
    // tool::Logging(myName_.c_str(),"update fp index and num is %d\n", outQuery->queryNum);
    //  string containerName;
    //  string tmpFPIndexEntryStr;
    //  tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);
    for (size_t i = 0; i < outQuery->queryNum; i++) {
        // update the outside index
        // if (entry->dedupFlag == NONEXIST) {

        FPIndexEntry_t tmpFPIndexEntry;
        memcpy(tmpFPIndexEntry.secureChunkHash, entry->secureChunkHash, CHUNK_HASH_SIZE);
        memcpy(tmpFPIndexEntry.containerName, entry->containerName, CONTAINER_ID_LENGTH);
        // tool::PrintBinaryArray(entry->chunkHash, CHUNK_HASH_SIZE);
        // containerName.assign((char*)entry->containerName, CONTAINER_ID_LENGTH);
        // tool::Logging(myName_.c_str(), "container id is %s\n", containerName.c_str());
        // tool::Logging(myName_.c_str()," update one entry\n");
        indexStoreObj_->InsertBothBuffer((char*)entry->chunkHash, CHUNK_HASH_SIZE,
            (char*)&tmpFPIndexEntry, sizeof(FPIndexEntry_t));

        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

/**
 * @brief generate the UUID
 *
 * @param id the uuid buffer
 * @param len the id len
 */
void Ocall_CreateUUID(uint8_t* id, size_t len)
{
    tool::CreateUUID((char*)id, len);
    return;
}

void Ocall_MigrationGetContainerName(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    outMigration_t* outMigration = &outClientPtr->_outMigration;
    outMigrationEntry_t* outMigrationEntry = outMigration->outMigrationBase;

    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);

    bool result;
    for (size_t i = 0; i < outMigration->queryNum; i++) {
        result = indexStoreObj_->QueryBuffer((char*)outMigrationEntry->chunkHash,
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (result) {
            FPIndexEntry_t fpIndexEntry;
            memcpy(&fpIndexEntry, tmpFPIndexEntryStr.c_str(), sizeof(FPIndexEntry_t));
            memcpy(outMigrationEntry->containerName, fpIndexEntry.containerName, CONTAINER_ID_LENGTH);
        } else {
            tool::Logging(myName_.c_str(), "did not find entry in FP Index\n");
        }
        outMigrationEntry++;
    }
    return;
}

void Ocall_QueryOutIndexRT(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutQuery_t* outQuery = &outClientPtr->_outQuery_RT;
    OutQueryEntry_t* entry = outQuery->outQueryBase;

    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);
    // tool::Logging(myName_.c_str(),"start query and query num is %d\n", outQuery->queryNum);
    // tool::PrintBinaryArray(entry->chunkHash, CHUNK_HASH_SIZE);
    bool queryResult;
    for (size_t i = 0; i < outQuery->queryNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)(entry->chunkHash),
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (queryResult) {
            // this chunk is duplicate in the outside index
            // store the query result in the buffer
            entry->dedupFlag = EXIST;
            FPIndexEntry_t FPIndexEntry;
            memcpy(&FPIndexEntry, tmpFPIndexEntryStr.c_str(), sizeof(FPIndexEntry_t));

            memcpy(entry->secureChunkHash, FPIndexEntry.secureChunkHash, CHUNK_HASH_SIZE);
            memcpy(entry->containerName, FPIndexEntry.containerName, CONTAINER_ID_LENGTH);
        } else {
            // tool::Logging(myName_.c_str(),"nope\n");
            entry->dedupFlag = NONEXIST;
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_SendSecRecipe(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
    SendMsgBuffer_t* sendSecFpBuffer = &outClientPtr->_sendSecFpBuf;
    enclaveMigratorObj_->SendBatchSecFp(sendSecFpBuffer, outClientPtr->_clientSSL);
    return;
}

void Ocall_WriteContainerRT(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
#if (MULTI_CLIENT == 1)
    dataWriterObj_->SaveToFile(outClientPtr->_curContainer);
#else
    outClientPtr->_inputMQ_RT->Push(outClientPtr->_curContainerRT);
#endif
    // tool::Logging(myName_.c_str(), "write a container to MQ\n");
    //  reset current container
    tool::CreateUUID(outClientPtr->_curContainerRT.containerID,
        CONTAINER_ID_LENGTH);
    outClientPtr->_curContainerRT.currentSize = 0;
    return;
}

void Ocall_ClearFpIndex()
{
    indexStoreObj_->MapClear();
    return;
}

void Ocall_SaveFpIndex()
{
    indexStoreObj_->Save();
    return;
}

void Ocall_AddOutIndexGC(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutGC_t* outGC = &outClientPtr->_outGC;
    OutGCEntry_t* entry = outGC->outGCBase;
    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);
    bool queryResult;
    // tool::Logging(myName_.c_str(), "Add gc num:%d\n", outGC->queryNum);
    for (size_t i = 0; i < outGC->queryNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)(entry->chunkHash),
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (queryResult) {
            // tool::Logging(myName_.c_str(), "can find\n");
        } else {
            // add index
            FPIndexEntry_t FPIndexEntry;
            indexStoreObj_->InsertBothBuffer((char*)entry->chunkHash, CHUNK_HASH_SIZE, (char*)&FPIndexEntry, sizeof(FPIndexEntry_t));
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_QueryOutIndexGC(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutGC_t* outGC = &outClientPtr->_outGC;
    OutGCEntry_t* entry = outGC->outGCBase;
    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);
    bool queryResult;
    for (size_t i = 0; i < outGC->queryNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)(entry->chunkHash),
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (queryResult) {
            // tool::Logging(myName_.c_str(), "query gc fp can find\n");
            entry->existFlag = EXIST;
        } else {
            // tool::Logging(myName_.c_str(), "query gc fp can not find\n");
            entry->existFlag = NONEXIST;
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_UpdateOutIndexGC(void* outClient)
{
#if (MULTI_CLIENT == 1)
    pthread_rwlock_rdlock(&outIdxLck_);
#endif
    ClientVar* outClientPtr = (ClientVar*)outClient;
    OutGC_t* outGC = &outClientPtr->_outGC;
    OutGCEntry_t* entry = outGC->outGCBase;
    string tmpFPIndexEntryStr;
    tmpFPIndexEntryStr.resize(sizeof(FPIndexEntry_t), 0);
    bool queryResult;
    for (size_t i = 0; i < outGC->queryNum; i++) {
        // check the outside index
        queryResult = indexStoreObj_->QueryBuffer((char*)(entry->chunkHash),
            CHUNK_HASH_SIZE, tmpFPIndexEntryStr);
        if (entry->existFlag == EXIST) {
            // tool::Logging(myName_.c_str(), "update gc fp can find\n");
            FPIndexEntry_t tmpFPIndexEntry;

            memcpy(tmpFPIndexEntry.secureChunkHash, entry->secureChunkHash, CONTAINER_ID_LENGTH);
            memcpy(tmpFPIndexEntry.containerName, entry->containerName, CONTAINER_ID_LENGTH);
            indexStoreObj_->InsertBothBuffer((char*)entry->chunkHash, CHUNK_HASH_SIZE,
                (char*)&tmpFPIndexEntry, sizeof(FPIndexEntry_t));
        } else {
            // tool::Logging(myName_.c_str(), "update gc fp can not find\n");
        }
        entry++;
    }
#if (MULTI_CLIENT == 1)
    pthread_rwlock_unlock(&outIdxLck_);
#endif
    return;
}

void Ocall_WriteContainerGC(void* outClient)
{
    ClientVar* outClientPtr = (ClientVar*)outClient;
#if (MULTI_CLIENT == 1)
    dataWriterObj_->SaveToFile(outClientPtr->_curContainer);
#else
    outClientPtr->_inputMQ_GC->Push(outClientPtr->_curContainerGC);
#endif
    // reset current container
    // tool::Logging(myName_.c_str(), "write %s\n", outClientPtr->_curContainerGC.containerID);
    tool::CreateUUID(outClientPtr->_curContainerGC.containerID,
        CONTAINER_ID_LENGTH);
    outClientPtr->_curContainerGC.currentSize = 0;
    return;
}
