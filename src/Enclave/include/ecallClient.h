/**
 * @file ecallClient.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the enclave client
 * @version 0.1
 * @date 2021-07-07
 *
 * @copyright Copyright (c) 2021
 *
 */

#ifndef ECALL_CLIENT_H
#define ECALL_CLIENT_H

#include "ecallEnc.h"
#include "commonEnclave.h"

using namespace std;

typedef struct {
    uint8_t* headerBuf;
    uint8_t* contentBuf;
    uint32_t curHeaderSize;
    uint32_t curContentSize;
    uint32_t curNum;
} InContainer;

class EnclaveClient {
private:
    int indexType_ = 0;
    int optType_; // the operation type (upload / download)

    /**
     * @brief init the buffer used in the upload
     *
     */
    void InitUploadBuffer();

    /**
     * @brief destroy the buffer used in the upload
     *
     */
    void DestroyUploadBuffer();

    /**
     * @brief init the buffer used in the restore
     *
     */
    void InitRestoreBuffer();

    /**
     * @brief destroy the buffer used in the restore
     *
     */
    void DestroyRestoreBuffer();

    /**
     * @brief for random iv generation
     *
     * @param x
     * @param k
     * @return uint64_t
     */

    /**
     * @brief init the buffer used in the migration
     *
     */
    void InitMigrationBuffer();

    /**
     * @brief destroy the buffer used in the migration
     *
     */
    void DestroyMigrationBuffer();
    /**
     * @brief init the buffer used in the download from cloud
     *
     */
    void InitDownloadBuffer();

    /**
     * @brief destroy the buffer used in the download from cloud
     *
     */
    void DestroyDownloadBuffer();
    /**
     * @brief init the buffer used in the gc from cloud
     *
     */
    void InitGCBuffer();

    /**
     * @brief destroy the buffer used in the gc from cloud
     *
     */
    void DestroyGCBuffer();

    inline uint64_t Rotl(const uint64_t x, int k)
    {
        return (x << k) | (x >> (64 - k));
    }

    /**
     * @brief generate the next iv
     *
     */
    inline void GenerateNextIV()
    {
        uint64_t* ptr = (uint64_t*)_iv;
        const uint64_t s0 = *ptr;
        uint64_t s1 = *(ptr + 1);
        s1 ^= s0;
        *ptr = Rotl(s0, 24) ^ s1 ^ (s1 << 16); // a, b
        *(ptr + 1) = Rotl(s1, 37); // c
        return;
    }

public:
    uint32_t _clientID;

    // for crypto operations
    EVP_CIPHER_CTX* _cipherCtx;
    EVP_MD_CTX* _mdCtx;
    uint8_t _iv[CRYPTO_BLOCK_SIZE]; // for store the current iv;

    // the client key
    uint8_t _sessionKey[CHUNK_HASH_SIZE];
    uint8_t _masterKey[CHUNK_HASH_SIZE];

    // for restore
    SendMsgBuffer_t _restoreChunkBuffer;
    uint8_t* _plainRecipeBuffer; // store plaintext recipe after decryption
    uint8_t* _plainKeyRecipeBuffer; // store plaintext recipe after decryption
    InRestoreEntry_t* _inRestoreBase;

    // for upload
    InQueryEntry_t* _inQueryBase; // dedup buffer
    Recipe_t _inRecipe; // the in-enclave recipe buffer
    Recipe_t _inSecureRecipe; // the in-enclave recipe buffer
    Recipe_t _inKeyRecipe; // the in-enclave recipe buffer
    uint8_t* _recvBuffer;
    Segment_t _segment;
    unordered_map<string, uint32_t> _localIndex;
    InContainer _inContainer;

    // for migration
    uint8_t* _plainRecipeBuffer_MR;
    SendMsgBuffer_t _migrationChunkBuffer;
    InMigrationEntry_t* _inMigrationBase;
    // for download from cloud
    uint8_t* _plainRecipeBuffer_RT;
    uint8_t* _secureRecipeBuffer_RT;
    InQueryEntry_t* _inQueryBase_RT;
    InContainer _inContainer_RT;

    // for gc
    uint8_t* _plainRecipeBuffer_GC;
    InGCEntry_t* _inGCBase;
    InContainer _inContainer_GC;

    /**
     * @brief Construct a new Enclave Client object
     *
     * @param clientID client ID
     * @param indexType index type
     * @param optType the operation type (upload / download)
     */
    EnclaveClient(uint32_t clientID, int indexType,
        int optType);

    /**
     * @brief Destroy the Enclave Client object
     *
     */
    ~EnclaveClient();

    /**
     * @brief Pick a new IV
     *
     * @return uint8_t*
     */
    inline uint8_t* PickNewIV()
    {
        uint64_t* tmpPtr = (uint64_t*)_iv;
        *tmpPtr += 1;
        return _iv;
    }

    /**
     * @brief Set the Master Key object
     *
     * @param encryptedSecret input encrypted secret
     * @param secretSize the input secret size
     */
    void SetMasterKey(uint8_t* encryptedSecret, size_t secretSize);
};

#endif