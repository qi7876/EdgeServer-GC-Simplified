

#ifndef MIGRATE_ECALL_H
#define MIGRATE_ECALL_H

#include "commonEnclave.h"
#include "ecallEnc.h"
#include "ecallMigrator.h"

class EcallMigrator;

namespace MigrateEnclave {
extern EcallMigrator* ecallMigratorObj_;
}

using namespace MigrateEnclave;

void Ecall_Init_Migrate();

void Ecall_Destory_Migrate();

void Ecall_MigrateOneBatch(uint8_t* recipeBuffer, size_t recipeNum, MrOutSGX_t* mrOutSGX, uint8_t* isInCloud);

void Ecall_MigrateTailBatch(MrOutSGX_t* mrOutSGX);

void Ecall_DownloadOneBatch(uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX);

void Ecall_DownloadTailBatch(RtOutSGX_t* rtOutSGX);

void Ecall_ProcessOneBatchChunk(uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX);

void Ecall_GCOneBatch(uint8_t* recipeBuffer, size_t recipeNum, GcOutSGX_t* gcOutSGX);

void Ecall_UpdataIndexOneBatch(uint8_t* recipeBuffer, size_t recipeNum, GcOutSGX_t* gcOutSGX);

void Ecall_DeleteIndexOneBatch(uint8_t* recipeBuffer, size_t recipeNum, GcOutSGX_t* gcOutSGX);

#endif