/**
 * @file clientVar.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of client var
 * @version 0.1
 * @date 2021-04-24
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/clientVar.h"

/**
 * @brief Construct a new ClientVar object
 * 
 * @param clientID the client ID
 * @param clientSSL the client SSL
 * @param optType the operation type (upload / download)
 * @param recipePath the file recipe path
 */
ClientVar::ClientVar(uint32_t clientID, SSL* clientSSL, int optType, 
    string& recipePath, string& secureRecipePath, string& keyRecipePath) {
    // basic info
    _clientID = clientID;
    _clientSSL = clientSSL;
    optType_ = optType;
    recipePath_ = recipePath;
    secureRecipePath_ = secureRecipePath;
    keyRecipePath_ = keyRecipePath;
    myName_ = myName_ + "-" + to_string(_clientID);

    // config
    sendChunkBatchSize_ = config.GetSendChunkBatchSize();
    sendRecipeBatchSize_ = config.GetSendRecipeBatchSize();
    recvChunkSize = 256;
    // tmp is 1024
    outQueryBatchSize_ = 1024;

    switch (optType_) {
        case UPLOAD_OPT: {
            this->InitUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->InitRestoreBuffer();
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong client opt type.\n");
            exit(EXIT_FAILURE);
        }
    }
}

ClientVar::ClientVar(uint32_t clienID, SSL* clientSSL, int optType)
{
    // basic info
    _clientID = clienID;
    _clientSSL = clientSSL;
    optType_ = optType;
    myName_ = myName_ + "-" + to_string(_clientID);

    // config
    sendChunkBatchSize_ = config.GetSendChunkBatchSize();
    sendRecipeBatchSize_ = config.GetSendRecipeBatchSize();
    recvChunkSize = 256;
    outQueryBatchSize_ = 1024;
    // MQ 
    

    switch (optType_) {
        case UPLOAD_OPT: {
            this->InitUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->InitRestoreBuffer();
            break;
        }
        case MIGRATE_TO_CLOUD: {
            this->InitMigrateBuffer(); 
            break; 
        }
        case RETRIEVE_FROM_CLOUD: {
            this->InitRetrieveBuffer();
            break;
        }
        case GC_OPT: {
            this->InitGCBuffer();
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong client opt type.\n");
            exit(EXIT_FAILURE);
        }
    } 
}

/**
 * @brief Destroy the Client Var object
 * 
 */
ClientVar::~ClientVar() {
    switch (optType_) {
        case UPLOAD_OPT: {
            this->DestroyUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->DestroyRestoreBuffer();
            break;
        }
        case MIGRATE_TO_CLOUD: {
            this->DestroyMigrateBuffer();
            break;
        }
        case RETRIEVE_FROM_CLOUD: {
            this->DestroyRetrieveBuffer();
            break;
        }
        case GC_OPT: {
            this->DestroyGCBuffer();
            break;
        }
    }
}

/**
 * @brief init the upload buffer
 * 
 */
void ClientVar::InitUploadBuffer() {
    // assign a random id to the container
    tool::CreateUUID(_curContainer.containerID, CONTAINER_ID_LENGTH);
    _curContainer.currentSize = 0;

    // for querying outside index 
    _outQuery.outQueryBase = (OutQueryEntry_t*) malloc(sizeof(OutQueryEntry_t) * 
        sendChunkBatchSize_);
    _outQuery.queryNum = 0;

    // init the recv buffer
    _recvChunkBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendChunkBatchSize_ * sizeof(Chunk_t));
    _recvChunkBuf.header = (NetworkHead_t*) _recvChunkBuf.sendBuffer;
    _recvChunkBuf.header->clientID = _clientID;
    _recvChunkBuf.header->dataSize = 0;
    _recvChunkBuf.dataBuffer = _recvChunkBuf.sendBuffer + sizeof(NetworkHead_t);

    // prepare the input MQ
#if (MULTI_CLIENT == 1)
    _inputMQ = new MessageQueue<Container_t>(1);
#else
    _inputMQ = new MessageQueue<Container_t>(CONTAINER_QUEUE_SIZE);
#endif
    // prepare the ciphertext recipe buffer
    _outRecipe.entryList = (uint8_t*) malloc(sendRecipeBatchSize_ * 
        CHUNK_HASH_SIZE);
    _outRecipe.recipeNum = 0;

    _outSecureRecipe.entryList = (uint8_t*) malloc(sendRecipeBatchSize_ * 
        CHUNK_HASH_SIZE);
    _outSecureRecipe.recipeNum = 0;

    _outKeyRecipe.entryList = (uint8_t*) malloc(sendRecipeBatchSize_ * 
        MLE_KEY_SIZE);
    _outKeyRecipe.recipeNum = 0;

    // build the param passed to the enclave
    _upOutSGX.curContainer = &_curContainer;
    _upOutSGX.outRecipe = &_outRecipe;
    _upOutSGX.outSecureRecipe = &_outSecureRecipe;
    _upOutSGX.outKeyRecipe = &_outKeyRecipe;
    _upOutSGX.outQuery = &_outQuery;
    _upOutSGX.outClient = this;

    // init the file recipe
    // 一共三个recipe
    // plain file recipe
    _recipeWriteHandler.open(recipePath_, ios_base::trunc | ios_base::binary);
    if (!_recipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init plain recipe file: %s\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    FileRecipeHead_t virtualRecipeEnd;
    _recipeWriteHandler.write((char*)&virtualRecipeEnd, sizeof(FileRecipeHead_t));
   // tool::Logging(myName_.c_str(), "virtual num: %lu\n", virtualRecipeEnd.totalChunkNum);
    //tool::Logging(myName_.c_str(), "virtual size: %lu\n", virtualRecipeEnd.fileSize);

    // secure file recipe
    _secureRecipeWriteHandler.open(secureRecipePath_, ios_base::trunc | ios_base::binary);
    if (!_secureRecipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init secure recipe file: %s\n",
            secureRecipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    _secureRecipeWriteHandler.write((char*)&virtualRecipeEnd, sizeof(FileRecipeHead_t));

    // key file recipe
    _keyRecipeWriteHandler.open(keyRecipePath_, ios_base::trunc | ios_base::binary);
    if (!_keyRecipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init key recipe file: %s\n",
            keyRecipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    _keyRecipeWriteHandler.write((char*)&virtualRecipeEnd, sizeof(FileRecipeHead_t));

    return ;
}

void ClientVar::InitMigrateBuffer()
{
    // init Sec Recipe buffer
    _sendSecRecipeBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _sendSecRecipeBuf.header = (NetworkHead_t*) _sendSecRecipeBuf.sendBuffer; 
    _sendSecRecipeBuf.header->dataSize = 0;
    _sendSecRecipeBuf.header->currentItemNum = 0;
    _sendSecRecipeBuf.dataBuffer = _sendSecRecipeBuf.sendBuffer + sizeof(NetworkHead_t);
    // init recipe buffer
    _sendRecipeBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendRecipeBatchSize_ * sizeof(RecipeEntry_t))  ;
    _sendRecipeBuf.header = (NetworkHead_t*) _sendRecipeBuf.sendBuffer;
    _sendRecipeBuf.header->dataSize = 0;
    _sendRecipeBuf.header->currentItemNum = 0;
    _sendRecipeBuf.dataBuffer = _sendRecipeBuf.sendBuffer + sizeof(NetworkHead_t);
    // init key recipe buffer
    _sendKeyRecipeBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendRecipeBatchSize_ * sizeof(keyRecipeEntry_t));
    _sendKeyRecipeBuf.header = (NetworkHead_t*) _sendKeyRecipeBuf.sendBuffer;
    _sendKeyRecipeBuf.header->dataSize =0;
    _sendKeyRecipeBuf.header->currentItemNum = 0;
    _sendKeyRecipeBuf.dataBuffer = _sendKeyRecipeBuf.sendBuffer + sizeof(NetworkHead_t);
    // init chunk buffer
    _sendChunkBuf_MR.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendChunkBatchSize_ * sizeof(Chunk_t));
    _sendChunkBuf_MR.header = (NetworkHead_t*) _sendChunkBuf_MR.sendBuffer;
    _sendChunkBuf_MR.header->dataSize = 0;
    _sendChunkBuf_MR.dataBuffer = _sendChunkBuf_MR.sendBuffer + sizeof(NetworkHead_t);
    // init recv bool buf
    _recvBoolBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + sendRecipeBatchSize_ * sizeof(uint8_t));
    _recvBoolBuf.header = (NetworkHead_t*) _recvBoolBuf.sendBuffer;
    _recvBoolBuf.header->dataSize = 0;
    _recvBoolBuf.header->currentItemNum = 0;
    _recvBoolBuf.dataBuffer = _recvBoolBuf.sendBuffer + sizeof(NetworkHead_t);
    // init read sec recipe buffer
    //_readSecRecipeBuf = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _readRecipeBuf_MR = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _readKeyRecipeBuf_MR = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(keyRecipeEntry_t));
    _SecRecipeBuf = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    // container buffer
    _reqContainer_MR.idBuffer = (uint8_t*) malloc(CONTAINER_CAPPING_VALUE * 
        CONTAINER_ID_LENGTH);
    _reqContainer_MR.containerArray = (uint8_t**) malloc(CONTAINER_CAPPING_VALUE * 
        sizeof(uint8_t*));
    _reqContainer_MR.idNum = 0;
    for(size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++)
    {
        _reqContainer_MR.containerArray[i] = (uint8_t*) malloc(sizeof(uint8_t) *
            MAX_CONTAINER_SIZE);
    }
    
    _containerCache_MR = new ReadCache();

    _outMigration.queryNum = 0;
    _outMigration.outMigrationBase = (outMigrationEntry_t*) malloc(sizeof(outMigrationEntry_t) * sendRecipeBatchSize_);
    
    _mrOutSGX.reqContainer = &_reqContainer_MR;
    _mrOutSGX.outClient = this;
    _mrOutSGX.sendChunkBuf = &_sendChunkBuf_MR;
    _mrOutSGX.outMigration = &_outMigration;
    
    return ;
}

void ClientVar::DestroyMigrateBuffer()
{
    if (_recipeReadHandler.is_open()) {
        _recipeReadHandler.close();
    }
    if (_keyRecipeReadHandler.is_open()) {
        _keyRecipeReadHandler.close();
    }
    if(_secureRecipeReadHandler.is_open()) {
        _secureRecipeReadHandler.close();
    }

    free(_sendSecRecipeBuf.sendBuffer);
    free(_sendRecipeBuf.sendBuffer);
    free(_sendKeyRecipeBuf.sendBuffer);
    free(_recvBoolBuf.sendBuffer);
    free(_readRecipeBuf_MR);
    free(_readKeyRecipeBuf_MR);
    free(_SecRecipeBuf);
    free(_sendChunkBuf_MR.sendBuffer);
    free(_outMigration.outMigrationBase);
    delete _containerCache_MR;
    return ;
}

void ClientVar::InitRetrieveBuffer()
{
    tool::Logging(myName_.c_str(), "init retrieve buffer start\n");
    //init container
    tool::CreateUUID(_curContainerRT.containerID, CONTAINER_ID_LENGTH);
    _curContainerRT.currentSize = 0;
    // init recv recipe buffer
    _recvRecipeBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendRecipeBatchSize_ * sizeof(RecipeEntry_t))  ;
    _recvRecipeBuf.header = (NetworkHead_t*) _recvRecipeBuf.sendBuffer;
    _recvRecipeBuf.header->dataSize = 0;
    _recvRecipeBuf.header->currentItemNum = 0;
    _recvRecipeBuf.dataBuffer = _recvRecipeBuf.sendBuffer + sizeof(NetworkHead_t);
    // init recv chunk buffer 256 default
    tool::Logging(myName_.c_str(), "recv chunk size is %d\n", recvChunkSize);
    _recvChunkBuf_RT.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        recvChunkSize * sizeof(Chunk_t));
    _recvChunkBuf_RT.header = (NetworkHead_t*) _recvChunkBuf_RT.sendBuffer;
    _recvChunkBuf_RT.header->dataSize = 0;
    _recvChunkBuf_RT.header->currentItemNum = 0;
    _recvChunkBuf_RT.dataBuffer = _recvChunkBuf_RT.sendBuffer + sizeof(NetworkHead_t);
    // init read recipe buffer
    _readRecipeBuf_RT = (uint8_t*) malloc(sizeof(RecipeEntry_t) * sendRecipeBatchSize_);
    _readSecRecipeBuf_RT = (uint8_t*) malloc(sizeof(RecipeEntry_t) * sendRecipeBatchSize_);
    // init send sec fp buffer
    tool::Logging(myName_.c_str(), "sendrecipe size is  %d\n", sendRecipeBatchSize_);
    _sendSecFpBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _sendSecFpBuf.header = (NetworkHead_t*) _sendSecFpBuf.sendBuffer;
    _sendSecFpBuf.header->dataSize = 0;
    _sendSecFpBuf.header->currentItemNum = 0;
    _sendSecFpBuf.dataBuffer = _sendSecFpBuf.sendBuffer + sizeof(NetworkHead_t);
    // init outQuery 
    _outQuery_RT.outQueryBase = (OutQueryEntry_t*) malloc(sizeof(OutQueryEntry_t) * outQueryBatchSize_);
    _outQuery_RT.queryNum = 0;
    //tool::Logging(myName_.c_str(), "addr is %x\n", _outQuery_RT.outQueryBase);
    // process num
    _inputMQ_RT = new MessageQueue<Container_t>(CONTAINER_QUEUE_SIZE);
    processNum = 0;


    _rtOutSGX.sendSecFpBuf = &_sendSecFpBuf;
    _rtOutSGX.outQuery = &_outQuery_RT;
    _rtOutSGX.needChunkNum = &needChunkNum;
    _rtOutSGX.processNum = &processNum;
    _rtOutSGX.curContainer = &_curContainerRT;
    _rtOutSGX.outClient = this;
    return ;
}

void ClientVar::DestroyRetrieveBuffer()
{
    free(_recvRecipeBuf.sendBuffer);
    free(_recvChunkBuf_RT.sendBuffer);
    free(_readRecipeBuf_RT);
    free(_readSecRecipeBuf_RT);
    free(_sendSecFpBuf.sendBuffer);
    free(_outQuery_RT.outQueryBase);
    delete _inputMQ_RT;
    return ;
}

/**
 * @brief destroy the upload buffer
 * 
 */
void ClientVar::DestroyUploadBuffer() {
    if (_recipeWriteHandler.is_open()) {
        _recipeWriteHandler.close();
    }
    if (_secureRecipeWriteHandler.is_open()) {
        _secureRecipeWriteHandler.close();
    }
    if (_keyRecipeWriteHandler.is_open()) {
        _keyRecipeWriteHandler.close();
    }
    free(_outRecipe.entryList);
    free(_outSecureRecipe.entryList);
    free(_outKeyRecipe.entryList);
    free(_outQuery.outQueryBase);
    free(_recvChunkBuf.sendBuffer);
    delete _inputMQ;
    return ; 
}

/**
 * @brief init the restore buffer
 * 
 */
void ClientVar::InitRestoreBuffer() {
    // init buffer    
    _readRecipeBuf = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));

    _readKeyRecipeBuf = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(keyRecipeEntry_t));

    _reqContainer.idBuffer = (uint8_t*) malloc(CONTAINER_CAPPING_VALUE * 
        CONTAINER_ID_LENGTH);
    _reqContainer.containerArray = (uint8_t**) malloc(CONTAINER_CAPPING_VALUE * 
        sizeof(uint8_t*));
    _reqContainer.idNum = 0;
    for (size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++) {
        _reqContainer.containerArray[i] = (uint8_t*) malloc(sizeof(uint8_t) * 
            MAX_CONTAINER_SIZE);
    }

    // init the send buffer
    _sendChunkBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendChunkBatchSize_ * sizeof(Chunk_t));
    _sendChunkBuf.header = (NetworkHead_t*) _sendChunkBuf.sendBuffer;
    _sendChunkBuf.header->clientID = _clientID;
    _sendChunkBuf.header->dataSize = 0;
    _sendChunkBuf.dataBuffer = _sendChunkBuf.sendBuffer + sizeof(NetworkHead_t);

    // init the container cache
    _containerCache = new ReadCache();

    // build the param passed to the enclave
    _resOutSGX.reqContainer = &_reqContainer;
    _resOutSGX.sendChunkBuf = &_sendChunkBuf;
    _resOutSGX.outClient = this;

    // init the recipe handler
    _recipeReadHandler.open(recipePath_, ios_base::in | ios_base::binary);
    if (!_recipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the file recipe: %s.\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }

    // init the recipe handler
    _keyRecipeReadHandler.open(keyRecipePath_, ios_base::in | ios_base::binary);
    if (!_keyRecipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the key file recipe: %s.\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }

    _outRestore.restoreNum = 0;
    _outRestore.outRestoreBase = (OutRestoreEntry_t*) malloc(sizeof(OutRestoreEntry_t) * sendRecipeBatchSize_);
    _resOutSGX.outRestore = &_outRestore;

    return ;
}

/**
 * @brief destroy the restore buffer
 * 
 */
void ClientVar::DestroyRestoreBuffer() {
    if (_recipeReadHandler.is_open()) {
        _recipeReadHandler.close();
    }
    if (_keyRecipeReadHandler.is_open()) {
        _keyRecipeReadHandler.close();
    }
    free(_sendChunkBuf.sendBuffer);
    free(_readKeyRecipeBuf);
    free(_readRecipeBuf); 
    free(_reqContainer.idBuffer);
    for (size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++) {
        free(_reqContainer.containerArray[i]);
    }
    free(_reqContainer.containerArray);
    
    free(_outRestore.outRestoreBase);
    delete _containerCache;
    return ;
}

void ClientVar::SetRecipeReadHandler(string recipePath)
{
    // init the recipe read handler
    if(_recipeReadHandler.is_open())
        _recipeReadHandler.close();
    
    _recipeReadHandler.open(recipePath, ios_base::in | ios_base::binary);
    if (!_recipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the file recipe: %s.\n",
            recipePath.c_str());
        exit(EXIT_FAILURE);
    }

    return;
}

void ClientVar::SetSecRecipeReadHandler(string secRecipePath)
{
    // init  secure file recipe read handler
    if(_secureRecipeReadHandler.is_open())
        _secureRecipeReadHandler.close();
    _secureRecipeReadHandler.open(secRecipePath, ios_base::in | ios_base::binary);
    if (!_secureRecipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the secure file recipe: %s.\n",
            secRecipePath.c_str());
        exit(EXIT_FAILURE);
    }

    return;
}

void ClientVar::SetKeyRecipeReadHandler(string keyRecipePath)
{
    // init the key recipe read handler
    if(_keyRecipeReadHandler.is_open())
        _keyRecipeReadHandler.close();
    _keyRecipeReadHandler.open(keyRecipePath, ios_base::in | ios_base::binary);
    if (!_keyRecipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the key file recipe: %s.\n",
            keyRecipePath.c_str());
        exit(EXIT_FAILURE);
    }
}

void ClientVar::SetKeyRecipeWriteHandler(string keyRecipePath)
{
    if(_keyRecipeWriteHandler.is_open())
        _keyRecipeWriteHandler.close();
    _keyRecipeWriteHandler.open(keyRecipePath, ios_base::trunc | ios_base::binary);
    if (!_keyRecipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the key file recipe: %s.\n",
           keyRecipePath.c_str());
        exit(EXIT_FAILURE);
    }
}

void ClientVar::SetRecipeWriteHandler(string recipePath)
{
    if(_recipeWriteHandler.is_open())
        _recipeWriteHandler.close();
    _recipeWriteHandler.open(recipePath, ios_base::trunc | ios_base::binary);
    if (!_recipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init file recipe: %s.\n",
            recipePath.c_str());
        exit(EXIT_FAILURE);
    }     
}

void ClientVar::SetSecRecipeWriteHandler(string secRecipePath)
{
    if(_secureRecipeWriteHandler.is_open())
        _secureRecipeWriteHandler.close();
    _secureRecipeWriteHandler.open(secRecipePath, ios_base::trunc | ios_base::binary);
    if (!_secureRecipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init secure file recipe: %s.\n",
            secRecipePath.c_str());
        exit(EXIT_FAILURE);
    }
}

void ClientVar::InitGCBuffer()
{
    tool::CreateUUID(_curContainerGC.containerID, CONTAINER_ID_LENGTH);
    _curContainerGC.currentSize = 0;
    // recipe buffer
    _readRecipeBuf_GC = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _readKeyRecipeBuf_GC = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(keyRecipeEntry_t));
    _readSecRecipeBuf_GC = (uint8_t*) malloc(sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    // container buffer
    _reqContainer_GC.idBuffer = (uint8_t*) malloc(CONTAINER_CAPPING_VALUE * 
        CONTAINER_ID_LENGTH);
    _reqContainer_GC.containerArray = (uint8_t**) malloc(CONTAINER_CAPPING_VALUE * 
        sizeof(uint8_t*));
    _reqContainer_GC.idNum = 0;
    for(size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++)
    {
        _reqContainer_GC.containerArray[i] = (uint8_t*) malloc(sizeof(uint8_t) *
            MAX_CONTAINER_SIZE);
    }
    
    _outGC.queryNum = 0;
    _outGC.outGCBase = (OutGCEntry_t*) malloc(sizeof(OutGCEntry_t) * outQueryBatchSize_);
    
    _gcOutSGX.curContainer = &_curContainerGC;
    _gcOutSGX.reqContainer = &_reqContainer_GC;
    _gcOutSGX.outClient = this;
    _gcOutSGX.outGC = &_outGC;
    _inputMQ_GC = new MessageQueue<Container_t>(CONTAINER_QUEUE_SIZE);
    return ;
}

void ClientVar::DestroyGCBuffer()
{
    free(_readRecipeBuf_GC);
    free(_readKeyRecipeBuf_GC);
    free(_readSecRecipeBuf_GC);
    free(_reqContainer_GC.idBuffer);
    for (size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++) {
        free(_reqContainer_GC.containerArray[i]);
    }
    free(_reqContainer_GC.containerArray);
    free(_outGC.outGCBase);
    delete _inputMQ_GC;
    return ;
}
