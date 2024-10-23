/**
 * @file clientVar.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the class to store the variable related to a client in the outside the enclave
 * @version 0.1
 * @date 2021-04-24
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef CLIENT_VAR_H
#define CLIENT_VAR_H

#include "define.h"
#include "chunkStructure.h"
#include "messageQueue.h"
#include "readCache.h"
#include "sslConnection.h"

using namespace std;

extern Configure config;

class ClientVar {
    private:
        string myName_ = "ClientVar";
        int optType_; // the operation type (upload / download)
        uint64_t sendChunkBatchSize_;
        uint64_t sendRecipeBatchSize_;
        uint64_t outQueryBatchSize_;
        string recipePath_;
        string secureRecipePath_;
        string keyRecipePath_;

        /**
         * @brief init the upload buffer
         * 
         */
        void InitUploadBuffer();

        /**
         * @brief destroy the upload buffer
         * 
         */
        void DestroyUploadBuffer();

        /**
         * @brief init the restore buffer
         * 
         */
        void InitRestoreBuffer();

        /**
         * @brief destroy the restore buffer
         * 
         */
        void DestroyRestoreBuffer();
        /**
         * @brief Init the migrate buffer
         * 
         */
        void InitMigrateBuffer();
        /**
         * @brief destroy the migrate buffer
         * 
         */
        void DestroyMigrateBuffer();
        /**
         * @brief Init the retrieve buffer
         * 
         */
        void InitRetrieveBuffer();
        /**
         * @brief destroy the migrate buffer
         * 
         */
        void DestroyRetrieveBuffer();
        /**
         * @brief Init the gc buffer
         * 
         */
        void InitGCBuffer();
        /**
         * @brief destroy the gc buffer
         * 
         */
        void DestroyGCBuffer();
        
    public:
        uint32_t _clientID;

        // for handling file recipe
        ofstream _recipeWriteHandler;
        ofstream _secureRecipeWriteHandler;
        ofstream _keyRecipeWriteHandler;
        ifstream _recipeReadHandler;
        ifstream _secureRecipeReadHandler;
        ifstream _keyRecipeReadHandler;
        string _tmpQueryBufferStr;

        // for sgx context 
        UpOutSGX_t _upOutSGX; // pass this structure to the enclave for upload
        ResOutSGX_t _resOutSGX; // pass this structure to the enclave for restore

        // upload buffer parameters
        Container_t _curContainer; // current container buffer
        OutQuery_t _outQuery; // the buffer to store the encrypted chunk fp
        MessageQueue<Container_t>* _inputMQ;
        SendMsgBuffer_t _recvChunkBuf;
        Recipe_t _outRecipe; // the buffer to store ciphertext recipe
        Recipe_t _outSecureRecipe;
        Recipe_t _outKeyRecipe;

        // restore buffer parameters
        uint8_t* _readRecipeBuf;
        uint8_t* _readKeyRecipeBuf;
        ReqContainer_t _reqContainer;
        ReadCache* _containerCache;
        SendMsgBuffer_t _sendChunkBuf;
        OutRestore_t _outRestore;
        // migration buffer
        SendMsgBuffer_t _sendSecRecipeBuf;
        SendMsgBuffer_t _sendRecipeBuf;
        SendMsgBuffer_t _sendKeyRecipeBuf;
        SendMsgBuffer_t _sendChunkBuf_MR;
        SendMsgBuffer_t _recvBoolBuf;
        uint8_t* _readRecipeBuf_MR;
        uint8_t* _readKeyRecipeBuf_MR;
        uint8_t* _SecRecipeBuf;
        MrOutSGX_t _mrOutSGX;
        ReqContainer_t _reqContainer_MR;
        outMigration_t _outMigration;
        ReadCache* _containerCache_MR;
        // retrieve buffer
        SendMsgBuffer_t _recvRecipeBuf;
        SendMsgBuffer_t _recvChunkBuf_RT;
        SendMsgBuffer_t _sendSecFpBuf;
        string _queryBufferStr;
        uint8_t* _readRecipeBuf_RT;
        uint8_t* _readSecRecipeBuf_RT;
        RtOutSGX_t _rtOutSGX;
        OutQuery_t _outQuery_RT;
        uint32_t needChunkNum;
        uint32_t processNum;
        uint32_t recvChunkSize;
        Container_t _curContainerRT;
        MessageQueue<Container_t>* _inputMQ_RT;

         // gc buffer
        uint8_t* _readRecipeBuf_GC;
        uint8_t* _readKeyRecipeBuf_GC;
        uint8_t* _readSecRecipeBuf_GC;
        GcOutSGX_t _gcOutSGX;
        OutGC_t _outGC;
        ReqContainer_t _reqContainer_GC;
        Container_t _curContainerGC;
        MessageQueue<Container_t>* _inputMQ_GC;
        
        
        SSL* _clientSSL; // connection

        // upload logical data size
        uint64_t _uploadDataSize = 0;

        /**
         * @brief Construct a new ClientVar object
         * 
         * @param clientID the client ID
         * @param clientSSL the client SSL
         * @param optType the operation type (upload / download)
         * @param recipePath the file recipe path
         */
        ClientVar(uint32_t clientID, SSL* clientSSL, int optType, 
            string& recipePath, string& secureRecipePath, string& keyRecipePath);
        
        // construtor for migration function
        ClientVar(uint32_t clienID, SSL* clientSSL, int optType);
        
        void SetRecipeReadHandler(string recipePath);

        void SetSecRecipeReadHandler(string secRecipePath);

        void SetKeyRecipeReadHandler(string keyRecipePath);

        void SetRecipeWriteHandler(string recipePath);
        
        void SetSecRecipeWriteHandler(string secRecipePath);

        void SetKeyRecipeWriteHandler(string keyRecipePath);
        /**
         * @brief Destroy the Client Var object
         * 
         */
        ~ClientVar();
};

#endif