#include "../include/enclaveMigrator.h"
#include "enclaveMigrator.h"

extern Configure config;

EnclaveMigrator::EnclaveMigrator(sgx_enclave_id_t eidSGX, int indexType)
{
    // basic info
    eidSGX_ = eidSGX;
    edgeId_ = config.GetClientID();
    indexType_ = indexType;
    // batch size 
    sendSecRecipeBatchSize_ = 1024;
    enterEnclaveBatchSize_ = 1024;
    ChunkIsInCloud = NULL;
    // container name
    containerNamePrefix_ = config.GetContainerRootPath();
    containerNameTail_ = config.GetContainerSuffix();
    // data writer
    dataWriterObj_ = new DataWriter();
    // init enclaveMigrator
    Ecall_Init_Migrate(eidSGX);
    // login Done 
    loginDone = true;
}

EnclaveMigrator::~EnclaveMigrator()
{
    //free(tmpRecvBuffer);
    Ecall_Destory_Migrate(eidSGX_);
    if(ChunkIsInCloud != NULL){
        free(ChunkIsInCloud);
    }
    //free(sendSecRecipeBuffer.sendBuffer);
    delete dataWriterObj_;
  
}

void EnclaveMigrator::BuildConnectionWithCloud()
{
    // get cloud ip & port
    string cloudIp = config.GetCloudServerIP();
    int cloudPort = config.GetCloudServerPort();
    // build connection
    dataSecureChannel_ = new SSLConnection(cloudIp, cloudPort, IN_CLIENTSIDE); // edge to cloud (clientSide is edge)
    conChannelRecord_ = dataSecureChannel_->ConnectSSL();
    serverConnection = conChannelRecord_.second;
    
    tool::Logging(myName_.c_str(), "Connection with Cloud setup done.\n");
    return ;
}

void EnclaveMigrator::CloseConnectionWithCloud()
{
    //dataSecureChannel_->Finish(conChannelRecord_);
    //tool::Logging(myName_.c_str(), "111\n");
    dataSecureChannel_->Finish(conChannelRecord_);
    delete dataSecureChannel_;
  
    tool::Logging(myName_.c_str(), "Connection with Cloud close.\n");
    return ;
}

void EnclaveMigrator::MigrateFileToCloud(vector<string>& uploadFileList)
{
    // build SSL connection
    BuildConnectionWithCloud();
    // init out client 
    outClient_MR = new ClientVar(edgeId_, serverConnection, MIGRATE_TO_CLOUD);
    tool::Logging(myName_.c_str(), "Start Migration...\n");
    outClient_MR->_clientID = edgeId_;

    SendMsgBuffer_t* sendKeyRecipeBuf = &outClient_MR->_sendKeyRecipeBuf;
    SendMsgBuffer_t* sendRecipeBuf = &outClient_MR->_sendRecipeBuf;
    //init enclave client var
    //index-type is freq by default
    uint8_t* masterkey = nullptr; // migration opt will skip masterkey setup
    MrOutSGX_t* mrOutSGX = &outClient_MR->_mrOutSGX;
    Ecall_Init_Client(eidSGX_, edgeId_, indexType_, MIGRATE_TO_CLOUD, masterkey, &outClient_MR->_mrOutSGX.sgxClient);

    for(int i = 0; i < uploadFileList.size(); i++)
    {
        if(i > 0) loginDone = false;
        string fileName = uploadFileList[i];
        // build connection with cloud(fix later)
      
        // upload sec file recipe 
        uploadSecRecipeToCloud(fileName);
        // read file recipe batch based on bool result
        string recipePath = config.GetRecipeRootPath() + fileName + config.GetRecipeSuffix(); 
        //tool::Logging(myName_.c_str(), "read recipe path: %s\n", recipePath.c_str());
        outClient_MR->SetRecipeReadHandler(recipePath);
        string keyRecipePath = config.GetRecipeRootPath() + fileName + config.GetKeyRecipeSuffix();
        //tool::Logging(myName_.c_str(), "read key recipe path: %s\n", keyRecipePath.c_str());
        outClient_MR->SetKeyRecipeReadHandler(keyRecipePath);
        // read recipe header first 
        char* tmp;
        tmp = (char*) malloc(sizeof(FileRecipeHead_t));
        outClient_MR->_keyRecipeReadHandler.read(tmp, sizeof(FileRecipeHead_t));
        outClient_MR->_recipeReadHandler.read(tmp, sizeof(FileRecipeHead_t));
        // get filesize & total chunk num
        uint32_t recipeNum = ((FileRecipeHead_t*)tmp)->totalChunkNum;
        uint32_t fileSize = ((FileRecipeHead_t*)tmp)->fileSize;
        free(tmp);

        uint8_t* isInCloudPtr = ChunkIsInCloud; 
        uint8_t* secReciptePtr = outClient_MR->_SecRecipeBuf;
        uint8_t* readRecipeBuf = outClient_MR->_readRecipeBuf_MR;
        uint8_t* readKeyRecipeBuf = outClient_MR->_readKeyRecipeBuf_MR;
        bool end = false;
        while(!end)
        {
            outClient_MR->_recipeReadHandler.read((char*)readRecipeBuf,
                enterEnclaveBatchSize_ * sizeof(RecipeEntry_t));
            outClient_MR->_keyRecipeReadHandler.read((char*)readKeyRecipeBuf,
                enterEnclaveBatchSize_ * sizeof(keyRecipeEntry_t));
        
            size_t readCnt = outClient_MR->_recipeReadHandler.gcount();
            end = outClient_MR->_recipeReadHandler.eof();
            if(readCnt == 0)
            {
                break;
            }
            size_t recipeEntryNum = readCnt / sizeof(RecipeEntry_t);
            sendRecipeBuf->header->dataSize = readCnt;
         

            readCnt = outClient_MR->_keyRecipeReadHandler.gcount();
            end = outClient_MR->_keyRecipeReadHandler.eof();
            if(readCnt == 0)
            {
                break;
            }
            recipeEntryNum = readCnt / sizeof(RecipeEntry_t);
            sendKeyRecipeBuf->header->dataSize = readCnt;
           
            // send recipe  EDGE_UPLOAD_RECIPE
            sendRecipeBuf->header->currentItemNum = recipeEntryNum;
            sendRecipeBuf->header->messageType = EDGE_UPLOAD_RECIPE;
            memcpy(sendRecipeBuf->dataBuffer, readRecipeBuf, enterEnclaveBatchSize_ * sizeof(RecipeEntry_t));
            if(!dataSecureChannel_->SendData(conChannelRecord_.second, sendRecipeBuf->sendBuffer,
                sizeof(NetworkHead_t) + sendRecipeBuf->header->dataSize))
            {
                tool::Logging(myName_.c_str(), "send recipe error\n");
                exit(EXIT_FAILURE);
            }
            // send key recipe EDGE_UPLOAD_KEY_RECIPE
            sendKeyRecipeBuf->header->currentItemNum = recipeEntryNum;
            sendKeyRecipeBuf->header->messageType = EDGE_UPLOAD_KEY_RECIPE;
            memcpy(sendKeyRecipeBuf->dataBuffer, readKeyRecipeBuf, enterEnclaveBatchSize_ * sizeof(keyRecipeEntry_t));
            if(!dataSecureChannel_->SendData(conChannelRecord_.second, sendKeyRecipeBuf->sendBuffer,
                sizeof(NetworkHead_t) + sendKeyRecipeBuf->header->dataSize))
            {
                tool::Logging(myName_.c_str(), "send key recipe error\n");
                exit(EXIT_FAILURE);
            }
            //tool::Logging(myName_.c_str(), "enter enclave\n");
            Ecall_MigrateOneBatch(eidSGX_, readRecipeBuf, recipeEntryNum, mrOutSGX, isInCloudPtr);
            isInCloudPtr += recipeEntryNum;
        }
        Ecall_MigrateTailBatch(eidSGX_, mrOutSGX);
    }
    // free(ChunkIsInCloud);
    // close connection
    free(outClient_MR);
    tool::Logging(myName_.c_str(), "Migration Done!\n");
    CloseConnectionWithCloud();
    loginDone = true;
    for(size_t i = 0; i < uploadFileList.size(); i ++ ){
        string fileName = uploadFileList[i];
        string recipePath = config.GetRecipeRootPath() + fileName + config.GetRecipeSuffix();
        string keyrecipePath = config.GetRecipeRootPath() + fileName + config.GetKeyRecipeSuffix();
        string secrecipePath = config.GetRecipeRootPath() + fileName + config.GetSecureRecipeSuffix();
        if (filesystem::remove(recipePath)) {
            //  std::cout << "File successfully deleted\n";
        } else {
            std::cout << "File Failed deleted\n";
        }
        if (filesystem::remove(keyrecipePath)) {
            //  std::cout << "File successfully deleted\n";
        } else {
            std::cout << "File Failed deleted\n";
        }
        if (filesystem::remove(secrecipePath)) {
            //  std::cout << "File successfully deleted\n";
        } else {
            std::cout << "File Failed deleted\n";
        }
    }
    return ;
}

void EnclaveMigrator::uploadSecRecipeToCloud(string fileName)
{
    // set file path
    string secRecipePath = config.GetRecipeRootPath() + fileName + config.GetSecureRecipeSuffix();
    outClient_MR->SetSecRecipeReadHandler(secRecipePath);
    uint8_t* secRecipeBuf = outClient_MR->_SecRecipeBuf;

    // login first 
    SendMsgBuffer_t loginMsgBuf;
    loginMsgBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t)  + CHUNK_HASH_SIZE*2 + sizeof(FileRecipeHead_t));
    loginMsgBuf.header = (NetworkHead_t*) loginMsgBuf.sendBuffer;
    
    if(loginDone)
        loginMsgBuf.header->messageType = EDGE_MIGRATE_LOGIN;
    else
        loginMsgBuf.header->messageType = EDGE_MIGRATION_NEWFILE;
    
    loginMsgBuf.header->clientID = edgeId_;
    loginMsgBuf.header->dataSize = 0;
    loginMsgBuf.dataBuffer = loginMsgBuf.sendBuffer + sizeof(NetworkHead_t);
    memcpy(loginMsgBuf.dataBuffer + loginMsgBuf.header->dataSize, (uint8_t*)fileName.c_str(), CHUNK_HASH_SIZE*2);
    loginMsgBuf.header->dataSize += (CHUNK_HASH_SIZE*2);
    // read recipe header first(no use now, dump directly)
    FileRecipeHead_t* tmpHeader = (FileRecipeHead_t*)malloc(sizeof(FileRecipeHead_t));
    outClient_MR->_secureRecipeReadHandler.read((char*)tmpHeader, sizeof(FileRecipeHead_t)); 
    //tool::Logging(myName_.c_str(), "file size is %d total chunk num is %d\n", tmpHeader->fileSize, tmpHeader->totalChunkNum);
    memcpy(loginMsgBuf.dataBuffer + loginMsgBuf.header->dataSize, tmpHeader, sizeof(FileRecipeHead_t));
    loginMsgBuf.header->dataSize += sizeof(FileRecipeHead_t);
    // send login msg
    if(!dataSecureChannel_->SendData(conChannelRecord_.second, loginMsgBuf.sendBuffer, loginMsgBuf.header->dataSize + sizeof(NetworkHead_t)))
    {
        tool::Logging(myName_.c_str(), "send edge login msg failed\n");
        exit(EXIT_FAILURE);
    }
    // TODO: wait login response on use now
    uint32_t recvSize = 0;
    if(loginDone){
        if(!dataSecureChannel_->ReceiveData(conChannelRecord_.second, loginMsgBuf.sendBuffer, recvSize))
        {
            tool::Logging(myName_.c_str(), "receive edge login msg failed\n");
            exit(EXIT_FAILURE);
        }
    }
    free(loginMsgBuf.sendBuffer);

    secRecipeBuf = (uint8_t*) malloc(tmpHeader->totalChunkNum * sizeof(RecipeEntry_t));
    ChunkIsInCloud = (uint8_t*) malloc(tmpHeader->totalChunkNum);
    uint8_t* isInCloudPtr = ChunkIsInCloud;
    // read
    outClient_MR->_sendSecRecipeBuf.header->messageType = EDGE_UPLOAD_SEC_RECIPE;
    outClient_MR->_sendSecRecipeBuf.header->clientID = edgeId_;

    SendMsgBuffer_t* recvBoolBuf = &outClient_MR->_recvBoolBuf;
    bool end = false;
    //tool::Logging(myName_.c_str(), "send sec recipe start\n");
    while(!end)
    {
        //recv size
        recvSize = 0;
        // read sec recipe
        outClient_MR->_secureRecipeReadHandler.read((char*)(secRecipeBuf), 
            sizeof(RecipeEntry_t) * sendSecRecipeBatchSize_);
        memcpy(outClient_MR->_sendSecRecipeBuf.dataBuffer, secRecipeBuf, sizeof(RecipeEntry_t) * sendSecRecipeBatchSize_);
        
        end = outClient_MR->_secureRecipeReadHandler.eof();

        size_t readCnt = outClient_MR->_secureRecipeReadHandler.gcount();
        if(readCnt == 0)
            break;
        outClient_MR->_sendSecRecipeBuf.header->dataSize = readCnt;

        size_t recipeEntryNum = readCnt / sizeof(RecipeEntry_t);
        outClient_MR->_sendSecRecipeBuf.header->currentItemNum = recipeEntryNum;
 
        // send batch 
        if(!dataSecureChannel_->SendData(conChannelRecord_.second, outClient_MR->_sendSecRecipeBuf.sendBuffer, 
            sizeof(NetworkHead_t) + outClient_MR->_sendSecRecipeBuf.header->dataSize))
        {
            tool::Logging(myName_.c_str(), "send sec recipe error\n");
            exit(EXIT_FAILURE);
        }
        // recv response
        if(!dataSecureChannel_->ReceiveData(conChannelRecord_.second, recvBoolBuf->sendBuffer, recvSize))
        {
            tool::Logging(myName_.c_str(), "recv bool vector error\n");
        }

        memcpy(isInCloudPtr, recvBoolBuf->dataBuffer, recvBoolBuf->header->dataSize);
        isInCloudPtr += recvBoolBuf->header->dataSize;
    }
    free(tmpHeader);
    //tool::Logging(myName_.c_str(), "send sec recipe end\n");
    return ;
}

void EnclaveMigrator::GetReqContainer(ClientVar* outClient)
{
    ReqContainer_t* reqContainer = &outClient->_reqContainer_MR;
    uint8_t* idBuffer = reqContainer->idBuffer; 
    uint8_t** containerArray = reqContainer->containerArray;
    ReadCache* containerCache = outClient->_containerCache_MR;
    uint32_t idNum = reqContainer->idNum; 

    // retrieve each container
    string containerNameStr;
    for (size_t i = 0; i < idNum; i++) {
        containerNameStr.assign((char*) (idBuffer + i * CONTAINER_ID_LENGTH), 
            CONTAINER_ID_LENGTH);
        // step-1: check the container cache
        bool cacheHitStatus = containerCache->ExistsInCache(containerNameStr);
        if (cacheHitStatus) {
            // step-2: exist in the container cache, read from the cache, directly copy the data from the cache
            memcpy(containerArray[i], containerCache->ReadFromCache(containerNameStr), 
                MAX_CONTAINER_SIZE);
            continue ;
        } 

        // step-3: not exist in the contain cache, read from disk
        ifstream containerIn;
        string readFileNameStr = containerNamePrefix_ + containerNameStr + containerNameTail_;
        containerIn.open(readFileNameStr, ifstream::in | ifstream::binary);

        if (!containerIn.is_open()) {
            tool::Logging(myName_.c_str(), "cannot open the container: %s\n", readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        }

        // get the data section size (total chunk size - metadata section)
        containerIn.seekg(0, ios_base::end);
        int readSize = containerIn.tellg();
        containerIn.seekg(0, ios_base::beg);

        // read the metadata section
        int containerSize = 0;
        containerSize = readSize;
        // read compression data
        containerIn.read((char*)containerArray[i], containerSize);

        if (containerIn.gcount() != containerSize) {
            tool::Logging(myName_.c_str(), "read size %lu cannot match expected size: %d for container %s.\n",
                containerIn.gcount(), containerSize, readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        } 

        // close the container file
        containerIn.close();
        //readFromContainerFileNum_++;
        containerCache->InsertToCache(containerNameStr, containerArray[i], containerSize);
    }
    return ;
}

void EnclaveMigrator::SendBatchChunks(SendMsgBuffer_t* sendChunkBuffer, SSL* clientSSL)
{
    if(!dataSecureChannel_->SendData(clientSSL, sendChunkBuffer->sendBuffer,
        sizeof(NetworkHead_t) + sendChunkBuffer->header->dataSize))
        {
            tool::Logging(myName_.c_str(), "send the batch of migration chunks error.\n");
            exit(EXIT_FAILURE);
        }
    return ;
}

void EnclaveMigrator::SendBatchSecFp(SendMsgBuffer_t* sendSecFpBuffer, SSL* clientSSL)
{
    sendSecFpBuffer->header->messageType = EDGE_DOWNLOAD_CHUNK_READY;
    //tool::Logging(myName_.c_str(), "send the batch of sec fp start.\n");
    // tool::Logging(myName_.c_str(), "current num is %d and datasize is %d\n", sendSecFpBuffer->header->currentItemNum, sendSecFpBuffer->header->dataSize);
    // tool::PrintBinaryArray(sendSecFpBuffer->dataBuffer, CHUNK_HASH_SIZE);
    //uint8_t data[CHUNK_HASH_SIZE] = {0}; sendSecFpBuffer->header->dataSize + sizeof(NetworkHead_t)
    if(!dataSecureChannel_->SendData(clientSSL, sendSecFpBuffer->sendBuffer,
        sendSecFpBuffer->header->dataSize + sizeof(NetworkHead_t)))
    {
        tool::Logging(myName_.c_str(), "send the batch of sec fp error.\n");
        //exit(EXIT_FAILURE);
        sleep(10);
    }
    sendSecFpBuffer->header->currentItemNum = 0;
    sendSecFpBuffer->header->dataSize = 0;
    //tool::Logging(myName_.c_str(), "send the batch finished\n");
    return ;
}   

void EnclaveMigrator::DownloadRecipeFromCloud(string fileName)
{
    // Build Connection with Cloud 
    tool::Logging(myName_.c_str(), "Download Recipe Begin...\n");
    BuildConnectionWithCloud();
    // Login first 
    SendMsgBuffer_t loginMsgBuf;
    loginMsgBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t)  + CHUNK_HASH_SIZE * 2);
    loginMsgBuf.header = (NetworkHead_t*) loginMsgBuf.sendBuffer;

    loginMsgBuf.header->messageType = EDGE_DOWNLOAD_RECIPE_LOGIN;
    loginMsgBuf.header->clientID = edgeId_;
    loginMsgBuf.header->dataSize = 0;
    loginMsgBuf.dataBuffer = loginMsgBuf.sendBuffer + sizeof(NetworkHead_t);
    // copy message in buffer
    memcpy(loginMsgBuf.dataBuffer, fileName.c_str(), CHUNK_HASH_SIZE * 2);
    loginMsgBuf.header->dataSize += (CHUNK_HASH_SIZE * 2);
    // send download recipe login message 
    if(!dataSecureChannel_->SendData(serverConnection, loginMsgBuf.sendBuffer, 
        loginMsgBuf.header->dataSize + sizeof(NetworkHead_t)))
    {
        tool::Logging(myName_.c_str(), "send edge download recipe login msg failed\n");
        exit(EXIT_FAILURE);
    }
    // wait download reicpe login response 
    uint32_t recvSize;
    if(!dataSecureChannel_->ReceiveData(serverConnection, loginMsgBuf.sendBuffer, recvSize))
    {
        tool::Logging(myName_.c_str(), "receive edge login msg failed\n");
        exit(EXIT_FAILURE);
    }
    // TODO: judge if cloud has this file
    FileRecipeHead_t* tmpRecipeHead = (FileRecipeHead_t*)(loginMsgBuf.dataBuffer);

    outClient_RT = new ClientVar(edgeId_, serverConnection, RETRIEVE_FROM_CLOUD);
    // set write handler
    string recipePath = config.GetRecipeRootPath() + fileName + config.GetRecipeSuffix();
    string secRecipePath = config.GetRecipeRootPath() + fileName + config.GetSecureRecipeSuffix();
    string keyRecipePath = config.GetRecipeRootPath() + fileName + config.GetKeyRecipeSuffix();
    outClient_RT->SetKeyRecipeWriteHandler(keyRecipePath);
    outClient_RT->SetSecRecipeWriteHandler(secRecipePath);
    outClient_RT->SetRecipeWriteHandler(recipePath);
    //tool::Logging(myName_.c_str(), "recipePath is %s\n", recipePath.c_str());
    // write recipe head
    //tool::Logging(myName_.c_str(), "filesize is %d and chunk num is %d\n", tmpRecipeHead->fileSize, tmpRecipeHead->totalChunkNum);
    outClient_RT->_recipeWriteHandler.write((char*)(loginMsgBuf.dataBuffer), sizeof(FileRecipeHead_t));
    outClient_RT->_secureRecipeWriteHandler.write((char*)(loginMsgBuf.dataBuffer), sizeof(FileRecipeHead_t));
    outClient_RT->_keyRecipeWriteHandler.write((char*)(loginMsgBuf.dataBuffer), sizeof(FileRecipeHead_t));
    // send ready
    loginMsgBuf.header->messageType = EDGE_RECEIVE_READY;
    loginMsgBuf.header->dataSize = 0;
    if(!dataSecureChannel_->SendData(serverConnection, loginMsgBuf.sendBuffer, sizeof(NetworkHead_t) + loginMsgBuf.header->dataSize))
    {
        tool::Logging(myName_.c_str(), "send edge login response failed\n");
        exit(EXIT_FAILURE);
    }
    
    SendMsgBuffer_t* recvRecipeBuf = &outClient_RT->_recvRecipeBuf;
    bool sendRecipeEnd = false; 
    while(!sendRecipeEnd)
    {
        recvSize = 0;
        if(!dataSecureChannel_->ReceiveData(serverConnection, recvRecipeBuf->sendBuffer, recvSize))
        {
            tool::Logging(myName_.c_str(), "recv recipe file error.\n");
            exit(EXIT_FAILURE);
        }

        int msgType = recvRecipeBuf->header->messageType;
        switch (msgType)
        {
            case CLOUD_SEND_RECIPE: {
                this->writeRecipe(outClient_RT);
                if(!dataSecureChannel_->SendData(serverConnection, recvRecipeBuf->sendBuffer, sizeof(NetworkHead_t) + recvRecipeBuf->header->dataSize))
                {
                    tool::Logging(myName_.c_str(), "send recipe file respond error.\n");
                }
                break;
            }
            case CLOUD_SEND_SECURE_RECIPE: {
                this->writeSecRecipe(outClient_RT);
                if(!dataSecureChannel_->SendData(serverConnection, recvRecipeBuf->sendBuffer, sizeof(NetworkHead_t) + recvRecipeBuf->header->dataSize))
                {
                    tool::Logging(myName_.c_str(), "send recipe file respond error.\n");
                }
                break;
            }
            case CLOUD_SEND_KEY_RECIPE: {
                this->writeKeyRecipe(outClient_RT);
                if(!dataSecureChannel_->SendData(serverConnection, recvRecipeBuf->sendBuffer, sizeof(NetworkHead_t) + recvRecipeBuf->header->dataSize))
                {
                    tool::Logging(myName_.c_str(), "send recipe file respond error.\n");
                }
                break;
            }
            case CLOUD_SEND_RECIPE_END: {
                sendRecipeEnd = true;
                break;
            }
            default:
                break;
        }
    }   
    outClient_RT->_recipeWriteHandler.close();
    outClient_RT->_secureRecipeWriteHandler.close();
    outClient_RT->_keyRecipeWriteHandler.close();
    tool::Logging(myName_.c_str(), "Download recipe file done.\n");
    CloseConnectionWithCloud();
    return ;
}

void EnclaveMigrator::writeRecipe(ClientVar* curClient)
{
    //tool::Logging(myName_.c_str(), "write recipe\n");
    SendMsgBuffer_t* recvRecipeBuf = &curClient->_recvRecipeBuf;

    uint32_t chunkNum = recvRecipeBuf->header->currentItemNum;
    uint8_t* dataBuffer = recvRecipeBuf->dataBuffer;
    uint32_t dataSize = recvRecipeBuf->header->dataSize;

    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);
    string tmpContainerNameStr;
    tmpContainerNameStr.resize(CONTAINER_ID_LENGTH, 0);
   // tool::PrintBinaryArray(dataBuffer, 6);

    curClient->_recipeWriteHandler.write((char*)dataBuffer, dataSize);
    
    recvRecipeBuf->header->dataSize = 0;
    recvRecipeBuf->header->messageType = EDGE_RECEIVE_READY;
    return ;
}

void EnclaveMigrator::writeKeyRecipe(ClientVar* curClient)
{
    //tool::Logging(myName_.c_str(), "write key recipe\n");
    SendMsgBuffer_t* recvRecipeBuf = &curClient->_recvRecipeBuf;

    uint8_t* dataBuffer = recvRecipeBuf->dataBuffer;
    uint32_t dataSize = recvRecipeBuf->header->dataSize;
   // tool::PrintBinaryArray(dataBuffer, 6);
    curClient->_keyRecipeWriteHandler.write((char*)dataBuffer, dataSize);

    recvRecipeBuf->header->dataSize = 0;
    recvRecipeBuf->header->messageType = EDGE_RECEIVE_READY;
    return ;
}

void EnclaveMigrator::writeSecRecipe(ClientVar* curClient)
{
    //tool::Logging(myName_.c_str(), "write sec recipe\n");
    SendMsgBuffer_t* recvRecipeBuf = &curClient->_recvRecipeBuf;

    uint32_t chunkNum = recvRecipeBuf->header->currentItemNum;
    uint8_t* dataBuffer = recvRecipeBuf->dataBuffer;
    uint32_t dataSize = recvRecipeBuf->header->dataSize;
   // tool::PrintBinaryArray(dataBuffer, 6);
    curClient->_secureRecipeWriteHandler.write((char*)dataBuffer, dataSize);
    
    recvRecipeBuf->header->dataSize = 0;
    recvRecipeBuf->header->messageType = EDGE_RECEIVE_READY;
    return ;

}

void EnclaveMigrator::DownloadChunkFromCloud(string fileName)
{
    tool::Logging(myName_.c_str(), "Download Chunk Begin...\n");
    // build connection 
    BuildConnectionWithCloud();
    outClient_RT->_clientSSL = serverConnection;
    // build data writer;
    boost::thread* thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    thTmp = new boost::thread(attrs, boost::bind(&DataWriter::Run, dataWriterObj_,
        outClient_RT->_inputMQ_RT));
    // init enclave client 
    uint8_t* masterKey = nullptr;
    RtOutSGX_t* rtOutSGX = &outClient_RT->_rtOutSGX;
    Ecall_Init_Client(eidSGX_, edgeId_, indexType_, DOWNLOAD_FROM_CLOUD, masterKey, &outClient_RT->_rtOutSGX.sgxClient);
    // set recipe path
    string recipePath = config.GetRecipeRootPath() + fileName + config.GetRecipeSuffix();
    string secRecipePath = config.GetRecipeRootPath() + fileName + config.GetSecureRecipeSuffix();
    outClient_RT->SetRecipeReadHandler(recipePath);
    outClient_RT->SetSecRecipeReadHandler(secRecipePath);
    //tool::Logging(myName_.c_str(), "send handler done\n");
    // read recipe 
    bool end = false; 
    uint8_t* readRecipeBuf = outClient_RT->_readRecipeBuf_RT;  
    uint8_t* readSecRecipeBuf = outClient_RT->_readSecRecipeBuf_RT;
    // read header first 
    FileRecipeHead_t tmpHead;
    outClient_RT->_recipeReadHandler.read((char*)&tmpHead, sizeof(FileRecipeHead_t));
    outClient_RT->_secureRecipeReadHandler.read((char*)&tmpHead, sizeof(FileRecipeHead_t));
     // Login first 
    SendMsgBuffer_t loginMsgBuf;
    loginMsgBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t));
    loginMsgBuf.header = (NetworkHead_t*) loginMsgBuf.sendBuffer;

    loginMsgBuf.header->messageType = EDGE_DOWNLOAD_CHUNK_LOGIN;
    loginMsgBuf.header->clientID = edgeId_;
    loginMsgBuf.header->dataSize = 0;
    loginMsgBuf.dataBuffer = loginMsgBuf.sendBuffer + sizeof(NetworkHead_t);
    // send login message
    //tool::Logging(myName_.c_str(), "try login in Cloud\n");
    if(!dataSecureChannel_->SendData(serverConnection, loginMsgBuf.sendBuffer, 
        loginMsgBuf.header->dataSize + sizeof(NetworkHead_t)))
    {
        tool::Logging(myName_.c_str(), "send edge download chunk login msg failed\n");
        exit(EXIT_FAILURE);
    }
    // wait download reicpe login response
    //tool::Logging(myName_.c_str(), "ready to recieve response\n"); 
    uint32_t recvSize =  0;
    if(!dataSecureChannel_->ReceiveData(serverConnection, loginMsgBuf.sendBuffer, recvSize))
    {
        tool::Logging(myName_.c_str(), "receive edge login msg failed\n");
        exit(EXIT_FAILURE);
    }
    //tool::Logging(myName_.c_str(), "1 recv size is %d\n", recvSize);
    // recv ready
    //tool::Logging(myName_.c_str(), "send ready\n"); 
    loginMsgBuf.header->messageType = EDGE_RECEIVE_READY;
    if(!dataSecureChannel_->SendData(serverConnection, loginMsgBuf.sendBuffer, 
        sizeof(NetworkHead_t)))
    {
        tool::Logging(myName_.c_str(), "send edge download chunk login msg failed\n");
        exit(EXIT_FAILURE);
    } 
    // read entry
    recvSize = 0;
    SendMsgBuffer_t* recvChunkBuffer = &outClient_RT->_recvChunkBuf_RT;
    SendMsgBuffer_t* sendSecFpBuffer = &outClient_RT->_sendSecFpBuf;
    //tool::Logging(myName_.c_str(), "add is %x\n", recvChunkBuffer->sendBuffer);
    //tool::Logging(myName_.c_str(), "start read recipe file...\n");
    while(!end)
    {
        outClient_RT->_recipeReadHandler.read((char*)readRecipeBuf, 
            sizeof(RecipeEntry_t) * sendSecRecipeBatchSize_);
        outClient_RT->_secureRecipeReadHandler.read((char*)readSecRecipeBuf,
            sizeof(RecipeEntry_t) * sendSecRecipeBatchSize_);
        
        end = outClient_RT->_recipeReadHandler.eof();
        size_t readCnt = outClient_RT->_recipeReadHandler.gcount();
        size_t entryNum = readCnt / sizeof(RecipeEntry_t);

        Ecall_DownloadOneBatch(eidSGX_, readRecipeBuf, readSecRecipeBuf, entryNum, rtOutSGX);
        //this->SendBatchSecFp(&outClient_RT->_recvChunkBuf_RT, serverConnection);
        //tool::Logging(myName_.c_str(),"process num is %d and needchunknum is %d\n", outClient_RT->processNum, outClient_RT->needChunkNum);
        while((outClient_RT->processNum != outClient_RT->needChunkNum) || recvChunkBuffer->header->messageType != CLOUD_SEND_CHUNK_END)
        {
            if(!dataSecureChannel_->ReceiveData(serverConnection, recvChunkBuffer->sendBuffer, recvSize))
            {        
                tool::Logging(myName_.c_str(),"rece data error\n");
                break;
            }
            if(recvChunkBuffer->header->messageType == CLOUD_SEND_CHUNK)
            {
                size_t chunkNum =  recvChunkBuffer->header->currentItemNum;
                // TODO: Ecall to process each chunk 
                Ecall_ProcessOneBatchChunk(eidSGX_, recvChunkBuffer->dataBuffer, chunkNum, rtOutSGX);
                outClient_RT->processNum += chunkNum;
                Ocall_UpdateOutIndexRT(outClient_RT);
                //tool::Logging(myName_.c_str(), "process done!\n");
            }
            if(recvChunkBuffer->header->messageType == CLOUD_SEND_CHUNK_END)
            {
                //tool::Logging(myName_.c_str(),"last batch\n");
            }
        }
        outClient_RT->processNum = 0;
        outClient_RT->needChunkNum = 0;
    }
    Ecall_DownloadTailBatch(eidSGX_, rtOutSGX);
    Ecall_ProcessTailBatchChunk(eidSGX_, rtOutSGX);
    outClient_RT->_inputMQ_RT->done_ = true;

    thTmp->join();
    delete thTmp;

    CloseConnectionWithCloud();
    tool::Logging(myName_.c_str(), "Download Chunk done!\n");
    return ;
}

void EnclaveMigrator:: MigrateDeleteChunk()
{
    // init out client var
    outClient_GC = new ClientVar(edgeId_, serverConnection, GC_OPT);
    outClient_GC->_clientID = edgeId_;

    // build data writer;
    boost::thread *thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    thTmp = new boost::thread(attrs, boost::bind(&DataWriter::Run, dataWriterObj_,
                                                 outClient_GC->_inputMQ_GC));

    // init enclave client var
    uint8_t *masterkey = nullptr;
    GcOutSGX_t *gcOutSGX = &outClient_GC->_gcOutSGX;
    Ecall_Init_Client(eidSGX_, edgeId_, indexType_, GC_OPT, masterkey, &outClient_GC->_gcOutSGX.sgxClient);
    
    // add index
    GCAddIndex();

    // int reqcontainer
    ReqContainer_t* reqContainer = (ReqContainer_t*)gcOutSGX->reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer;
    reqContainer->idNum = 0;

    // get containers before gc
    filesystem::path root = containerNamePrefix_;
    string extension = containerNameTail_;
    vector<string> containerList;
    for (const auto& entry : filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) {
            string tmpFileName = entry.path().filename();
            string tmptension = tmpFileName.substr(tmpFileName.size() - extension.size(), extension.size());
            if(tmptension == extension)
                containerList.push_back(tmpFileName.substr(0, tmpFileName.size() - extension.size()));
        }   
    }
    uint32_t momerySize = getContainerSize(containerList);
    tool::Logging(myName_.c_str(), "before garbage collection container memroy :%.2lf MB\n", (double)momerySize / (1024 * 1024 * 1.0));
    
    for(size_t i = 0; i < containerList.size(); i ++ ){
        string name = containerList[i];
        memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH,
                name.c_str(), CONTAINER_ID_LENGTH);
        reqContainer->idNum++;
        if(reqContainer->idNum == CONTAINER_CAPPING_VALUE || i == (containerList.size() - 1))
        {
            // get containers content
            GetReqContainer_GC(outClient_GC);
            // handle ont batch
            Ecall_UpdateIndexOneBatch(eidSGX_, gcOutSGX);
            // delete containers
            MigrateDeleteContainer(outClient_GC);

            reqContainer->idNum = 0;
        }    
    }

    // handle tail batch
    Ecall_UpdateIndexTailBatch(eidSGX_, gcOutSGX);
    outClient_GC->_inputMQ_GC->done_ = true;
    thTmp->join();

    delete thTmp;
    delete outClient_GC;
    containerList.clear();
    
    // get containers after gc
    for (const auto& entry : filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) {
            string tmpFileName = entry.path().filename();
            string tmptension = tmpFileName.substr(tmpFileName.size() - extension.size(), extension.size());
            if(tmptension == extension)
                containerList.push_back(tmpFileName.substr(0, tmpFileName.size() - extension.size()));
        }   
    }
    momerySize = getContainerSize(containerList);
    tool::Logging(myName_.c_str(), "after garbage collection container memroy :%.2lf MB\n", (double)momerySize / (1024 * 1024 * 1.0));
    return ;
}

void EnclaveMigrator::GetReqContainer_GC(ClientVar *outClient)
{
    ReqContainer_t *reqContainer = &outClient->_reqContainer_GC;
    uint8_t *idBuffer = reqContainer->idBuffer;
    uint8_t **containerArray = reqContainer->containerArray;
    uint32_t idNum = reqContainer->idNum;

    // retrieve each container
    string containerNameStr;
    for (size_t i = 0; i < idNum; i++)
    {
        containerNameStr.assign((char *)(idBuffer + i * CONTAINER_ID_LENGTH),
                                CONTAINER_ID_LENGTH);
        // tool::Logging(myName_.c_str(), "containerName:%s\n", containerNameStr.c_str());
        ifstream containerIn;
        string readFileNameStr = containerNamePrefix_ + containerNameStr + containerNameTail_;
        containerIn.open(readFileNameStr, ifstream::in | ifstream::binary);

        if (!containerIn.is_open())
        {
            tool::Logging(myName_.c_str(), "cannot open the container: %s\n", readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        }

        // get the data section size (total chunk size - metadata section)
        containerIn.seekg(0, ios_base::end);
        int readSize = containerIn.tellg();
        containerIn.seekg(0, ios_base::beg);

        // read the metadata section
        int containerSize = 0;
        containerSize = readSize;
        // read compression data
        containerIn.read((char *)containerArray[i], containerSize);

        if (containerIn.gcount() != containerSize)
        {
            tool::Logging(myName_.c_str(), "read size %lu cannot match expected size: %d for container %s.\n",
                          containerIn.gcount(), containerSize, readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        }

        // close the container file
        containerIn.close();
    }
    return;
}



void EnclaveMigrator::GCAddIndex()
{
    tool::Logging(myName_.c_str(), "Start AddIndex...\n");
    // get recipelist
    filesystem::path root = config.GetRecipeRootPath();
    string extension = config.GetSecureRecipeSuffix();
    vector<string> allFileList;

    for (const auto& entry : filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) {
            string tmpFileName = entry.path().filename();
            string tmptension = tmpFileName.substr(tmpFileName.size() - extension.size(), extension.size());
            if(tmptension == extension)
                allFileList.push_back(tmpFileName.substr(0, tmpFileName.size() - extension.size()));
        }   
    }

    GcOutSGX_t *gcOutSGX = &outClient_GC->_gcOutSGX;

    for(size_t i = 0; i < allFileList.size(); i ++ ){
        string fileName = allFileList[i];
        string recipePath = config.GetRecipeRootPath() + fileName + config.GetRecipeSuffix();
        // tool::Logging(myName_.c_str(), "read recipe path: %s\n", recipePath.c_str());
        outClient_GC->SetRecipeReadHandler(recipePath);
        // init BUF
        uint8_t *readRecipeBuf = (uint8_t*)malloc(enterEnclaveBatchSize_ * sizeof(RecipeEntry_t));
        char *tmp = (char *)malloc(sizeof(FileRecipeHead_t));
        outClient_GC->_recipeReadHandler.read(tmp, sizeof(FileRecipeHead_t));       
        bool end = false;
        while (!end)
        {
            // read recipebuf
            outClient_GC->_recipeReadHandler.read((char *)readRecipeBuf,
                                                  enterEnclaveBatchSize_ * sizeof(RecipeEntry_t));
            size_t readCnt = outClient_GC->_recipeReadHandler.gcount();
            end = outClient_GC->_recipeReadHandler.eof();
            if (readCnt == 0)
            {
                break;
            }
            size_t recipeEntryNum = readCnt / sizeof(RecipeEntry_t);
            // add index ont batch
            Ecall_AddIndexOneBatch(eidSGX_, readRecipeBuf, recipeEntryNum, gcOutSGX);
        }
    }
    tool::Logging(myName_.c_str(), "end AddIndex...\n");
    return ;
}

void EnclaveMigrator::MigrateDeleteContainer(ClientVar *outClient)
{
    // tool::Logging(myName_.c_str(), "getReqContainer begin\n");
    ReqContainer_t *reqContainer = &outClient->_reqContainer_GC;
    uint8_t *idBuffer = reqContainer->idBuffer;
    uint32_t idNum = reqContainer->idNum;
    string containerNameStr;
    for (size_t i = 0; i < idNum; i++)
    {
        containerNameStr.assign((char *)(idBuffer + i * CONTAINER_ID_LENGTH),
                                CONTAINER_ID_LENGTH);
        // tool::Logging(myName_.c_str(), "containerNameStr: %s\n", containerNameStr.c_str());
        string readFileNameStr = containerNamePrefix_ + containerNameStr + containerNameTail_;    
        if (filesystem::remove(readFileNameStr)) {
            //  std::cout << "File successfully deleted\n";
        } else {
            std::cout << "File Failed deleted\n";
        }
    }
    return;
}


int EnclaveMigrator::getContainerSize(vector<string>& containerList)
{
    uint32_t sum = 0;
    for(size_t i = 0; i < containerList.size(); i ++ ){
        string containerName = containerList[i];
        string containerPath = containerNamePrefix_ + containerName + containerNameTail_;
        std::ifstream file(containerPath, std::ifstream::binary | std::ifstream::ate);
        if (!file.is_open()) {
            std::cerr << "Unable to open file: " << containerName << std::endl;
            continue;
        }
        sum += file.tellg(); 
    }
    return sum;
}

