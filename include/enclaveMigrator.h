#ifndef ENCLAVE_MIGRATOR_DECODER_H
#define ENCLAVE_MIGRATOR_DECODER_H

#include "configure.h"
#include "sslConnection.h"
#include "clientVar.h"
#include "sgx_urts.h"
#include "cryptoPrimitive.h"
#include "sgx_capable.h"
#include "messageQueue.h"
#include "../build/src/Enclave/storeEnclave_u.h"
#include "dataWriter.h"

class EnclaveMigrator {
private:
    string myName_ = "EnclaveMigrator";
    // for ssl
    SSLConnection* dataSecureChannel_;
    pair<int, SSL*> conChannelRecord_;
    SSL* serverConnection;
    // for enclave
    sgx_enclave_id_t eidSGX_;
    ClientVar* outClient_MR;
    ClientVar* outClient_RT;
    ClientVar* outClient_GC;
    // use client id as edge id(fix later)
    int edgeId_;
    // index type
    int indexType_;
    // statics
    uint64_t totalMigrateRecipeNum;
    uint64_t sendSecRecipeBatchSize_;
    uint64_t enterEnclaveBatchSize_;
    // buffer
    uint8_t* ChunkIsInCloud; // edge 2 cloud upload use
    uint8_t* secFpInCloud; // for retrieve chunk
    // cryptobj_
    CryptoPrimitive* cryptoObj_;
    // container name
    string containerNamePrefix_;
    string containerNameTail_;
    // data writer
    DataWriter* dataWriterObj_;

    bool loginDone;

public:
    EnclaveMigrator(sgx_enclave_id_t eidSGX, int indexType);

    ~EnclaveMigrator();

    void BuildConnectionWithCloud();

    void CloseConnectionWithCloud();

    void BuildConnectionWithEdge();

    void uploadSecRecipeToCloud(string filePath);

    void MigrateFileToCloud(vector<string>& uploadFileList);

    void GetReqContainer(ClientVar* outClient);

    void SendBatchChunks(SendMsgBuffer_t* sendChunkBuffer, SSL* clientSSL);

    void DownloadRecipeFromCloud(string fileName);

    void writeSecRecipe(ClientVar* curClient);

    void writeKeyRecipe(ClientVar* curClient);

    void writeRecipe(ClientVar* curClient);

    void DownloadChunkFromCloud(string fileName);

    void RetrieveFileFromCloud(string fileName);

    void ProcessOneBatchChunk(SendMsgBuffer_t* sendChunkBuffer, ClientVar* curClient);

    void SendBatchSecFp(SendMsgBuffer_t* sendSecFpBuffer, SSL* clientSSL);

    void MigrateDeleteChunk();

    void GetReqContainer_GC(ClientVar* outClient);

    void GCAddIndex();

    void MigrateDeleteContainer(ClientVar* outClient);

    int getContainerSize(vector<string>& containerList);
};

#endif