
#ifndef ECALL_MIGRATOR_H
#define ECALL_MIGRATOR_H

#include "commonEnclave.h"
#include "ecallEnc.h"
#include "ecallLz4.h"
#include "ecallStorage.h"

#include "../../../include/constVar.h"
#include "../../../include/chunkStructure.h"

class EcallMigrator {
private:
    string myName = "EcallMigrator";

    EcallCrypto* cryptoObj_;

    EcallStorageCore* storageObj_;

public:
    EcallMigrator();

    ~EcallMigrator();

    void MigrateOneBatch(uint8_t* recipeBuffer, size_t recipeNum, MrOutSGX_t* mrOutSGX, uint8_t* isInCloud);

    void MigrateTailBatch(MrOutSGX_t* mrOutSGX);

    void GetMigrationContent(MrOutSGX_t* mrOutSGX, uint8_t** containerArray, uint32_t idNum,
        InMigrationEntry_t* startEntry, size_t entryNum, SendMsgBuffer_t* sendChunkBuffer);

    void DownloadOneBatch(uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX);

    void DownloadTailBatch(RtOutSGX_t* rtOutSGX);

    void ProcessOneBatchChunk(uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX);

    void ProcessTailBatchChunk(RtOutSGX_t* rtOutSGX);

    void AddIndexOneBatch(uint8_t* recipeBuffer, size_t recipeNum, GcOutSGX_t* gcOutSGX);

    void UpdateIndexOneBatch(GcOutSGX_t* gcOutSGX);

    void UpdateIndexTailBatch(GcOutSGX_t* gcOutSGX);
};

#endif