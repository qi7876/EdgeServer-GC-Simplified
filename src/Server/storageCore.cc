/**
 * @file storageCore.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interfaces defined in the storage core.
 * @version 0.1
 * @date 2019-12-27
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#include "../../include/storageCore.h"


extern Configure config;

/**
 * @brief Construct a new Storage Core object
 * 
 */
StorageCore::StorageCore() {
    recipeNamePrefix_ = config.GetRecipeRootPath();
    recipeNameTail_ = config.GetRecipeSuffix();
}

/**
 * @brief Destroy the Storage Core:: Storage Core object
 * 
 */
StorageCore::~StorageCore() {
}

/**
 * @brief finalize the file recipe
 * 
 * @param recipeHead the recipe header
 * @param fileRecipeHandler the recipe file handler
 */
void StorageCore::FinalizeRecipe(FileRecipeHead_t* recipeHead, 
    ofstream& fileRecipeHandler) {
    if (!fileRecipeHandler.is_open()) {
        tool::Logging(myName_.c_str(), "recipe file does not open.\n");
        exit(EXIT_FAILURE);
    }
    fileRecipeHandler.seekp(0, ios_base::beg);
    // tool::Logging(myName_.c_str(), "file size: %lu.\n", recipeHead->fileSize);
    // tool::Logging(myName_.c_str(), "chunk num: %lu.\n", recipeHead->totalChunkNum);
    fileRecipeHandler.write((const char*)recipeHead, sizeof(FileRecipeHead_t));

    fileRecipeHandler.close();    
    return ; 
}

/**
 * @brief update the file recipe to the disk
 * 
 * @param recipeBuffer the pointer to the recipe buffer
 * @param recipeEntryNum the number of recipe entries
 * @param fileRecipeHandler the recipe file handler
 */
void StorageCore::UpdateRecipeToFile(const uint8_t* recipeBuffer, size_t recipeEntryNum, 
    ofstream& fileRecipeHandler, int writeType) {
    if (!fileRecipeHandler.is_open()) {
        tool::Logging(myName_.c_str(), "recipe file does not open.\n");
        exit(EXIT_FAILURE);
    }
    switch (writeType) {
        case HASH: {
            size_t recipeBufferSize = recipeEntryNum * CHUNK_HASH_SIZE;
            fileRecipeHandler.write((char*)recipeBuffer, recipeBufferSize);
            break;
        }
        case KEY: {
            size_t recipeBufferSize = recipeEntryNum * MLE_KEY_SIZE;
            fileRecipeHandler.write((char*)recipeBuffer, recipeBufferSize);
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong recipe write type.\n");
            exit(EXIT_FAILURE);
        }
    }
    return ;
}