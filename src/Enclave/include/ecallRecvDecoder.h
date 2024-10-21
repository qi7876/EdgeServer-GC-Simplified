/**
 * @file ecallRecvDecoder.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interfaces of ecallRecvDecoder
 * @version 0.1
 * @date 2021-03-01
 *
 * @copyright Copyright (c) 2021
 *
 */

#ifndef ECALL_RECV_DECODER_H
#define ECALL_RECV_DECODER_H

#include "commonEnclave.h"
#include "ecallEnc.h"
#include "ecallLz4.h"

#include "../../../include/chunkStructure.h"
#include "../../../include/constVar.h"

// forward declaration
class EcallCrypto;

class EcallRecvDecoder {
private:
    string myName_ = "EcallRecvDecoder";
    EcallCrypto* cryptoObj_;

    /**
     * @brief recover a chunk
     *
     * @param chunkBuffer the chunk buffer
     * @param chunkSize the chunk size
     * @param restoreChunkBuf the restore chunk buffer
     * @param cipherCtx the pointer to the EVP cipher
     *
     */
    void RecoverOneChunk(InRestoreEntry_t* entry, uint8_t* chunkBuffer,
        SendMsgBuffer_t* restoreChunkBuf, EVP_CIPHER_CTX* cipherCtx);

    void IndexConstruct(ResOutSGX_t* resOutSGX, unordered_map<string, RestoreIndexEntry_t>& restoreIndex,
        uint8_t** containerArray, uint32_t idNum);

public:
    /**
     * @brief Construct a new EcallRecvDecoder object
     *
     */
    EcallRecvDecoder();

    /**
     * @brief Destroy the Ecall Recv Decoder object
     *
     */
    ~EcallRecvDecoder();

    /**
     * @brief process a batch of recipes and write chunk to the outside buffer
     *
     * @param recipeBuffer the pointer to the recipe buffer
     * @param recipeNum the input recipe buffer
     * @param resOutSGX the pointer to the out-enclave var
     *
     * @return size_t the size of the sended buffer
     */
    void ProcRecipeBatch(uint8_t* recipeBuffer, uint8_t* keyRecipeBuffer,
        size_t recipeNum, ResOutSGX_t* resOutSGX);

    /**
     * @brief process the tail batch of recipes
     *
     * @param resOutSGX the pointer to the out-enclave var
     */
    void ProcRecipeTailBatch(ResOutSGX_t* resOutSGX);
};

#endif