#include "../../include/migrateECall.h"

namespace MigrateEnclave {
    EcallMigrator* ecallMigratorObj_ = NULL;
}

using namespace MigrateEnclave;

void Ecall_MigrateOneBatch(uint8_t* recipeBuffer, size_t recipeNum, MrOutSGX_t* mrOutSGX, 
    uint8_t* isInCloud)
{
    //Enclave::Logging("Migrate Ecall", "migrate one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("Migrate Ecall","is null\n");
    ecallMigratorObj_->MigrateOneBatch(recipeBuffer, recipeNum, mrOutSGX, isInCloud);
    //Enclave::Logging("Migrate Ecall", "migrate one batch done \n");
    return ;
}

void Ecall_MigrateTailBatch(MrOutSGX_t* mrOutSGX)
{
    ecallMigratorObj_->MigrateTailBatch(mrOutSGX);
    return ;
}

void Ecall_Init_Migrate()
{
    ecallMigratorObj_ = new EcallMigrator();
    return ;
}

void Ecall_Destory_Migrate()
{
    if(ecallMigratorObj_)
        delete ecallMigratorObj_;
    return ;
}

void Ecall_DownloadOneBatch(uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX)
{
    //Enclave::Logging("Download Ecall", "download one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("Migrate Ecall","is null\n");
    ecallMigratorObj_->DownloadOneBatch(recipeBuffer, secRecipeBuffer, recipeNum, rtOutSGX);
    //Enclave::Logging("Download Ecall", "download one batch done\n");
    return ;
}

void Ecall_DownloadTailBatch(RtOutSGX_t* rtOutSGX)
{
    ecallMigratorObj_->DownloadTailBatch(rtOutSGX);
    return ;
}

void Ecall_ProcessOneBatchChunk(uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX)
{
    ecallMigratorObj_->ProcessOneBatchChunk(chunkContentBuffer, chunkNum, rtOutSGX);
    return ;
}

void Ecall_ProcessTailBatchChunk(RtOutSGX_t* rtOutSGX)
{
    ecallMigratorObj_->ProcessTailBatchChunk(rtOutSGX);
    return ;
}


void Ecall_UpdateIndexOneBatch(GcOutSGX_t* gcOutSGX)
{
    // Enclave::Logging("Migrate Ecall", "migrate one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("gc Ecall","is null\n");
    ecallMigratorObj_->UpdateIndexOneBatch(gcOutSGX);
    // Enclave::Logging("Migrate Ecall", "migrate one batch done \n");
    return ;
}

void Ecall_UpdateIndexTailBatch(GcOutSGX_t* gcOutSGX)
{
    // Enclave::Logging("Migrate Ecall", "migrate one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("gc Ecall","is null\n");
    ecallMigratorObj_->UpdateIndexTailBatch(gcOutSGX);
    // Enclave::Logging("Migrate Ecall", "migrate one batch done \n");
    return ;
}

void Ecall_AddIndexOneBatch(uint8_t* recipeBuffer, size_t recipeNum, GcOutSGX_t* gcOutSGX)
{
    // Enclave::Logging("Migrate Ecall", "update index one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("gc Ecall","is null\n");
    ecallMigratorObj_->AddIndexOneBatch(recipeBuffer, recipeNum, gcOutSGX);
    // Enclave::Logging("Migrate Ecall", "update index batch done \n");
    return ;
}

void Ecall_UpdataIndexTailBatch(GcOutSGX_t* gcOutSGX)
{
    // Enclave::Logging("Migrate Ecall", "migrate one batch\n");
    if(ecallMigratorObj_ == NULL)
        Enclave::Logging("gc Ecall","is null\n");
    ecallMigratorObj_->UpdateIndexTailBatch(gcOutSGX);
    // Enclave::Logging("Migrate Ecall", "migrate one batch done \n");
    return ;
}
