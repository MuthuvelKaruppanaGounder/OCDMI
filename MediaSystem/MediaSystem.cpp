/*
 * Copyright 2018 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <interfaces/IDRM.h> 
#include "MediaSessionSystem.h"

#include <core/core.h>
#include "../Report.h"

namespace CDMi {

namespace {

    class CCLInitialize {
        CCLInitialize(const CCLInitialize&) = delete;
        CCLInitialize& operator= (const CCLInitialize&) = delete;

    public:
        CCLInitialize() {
           // int rc = nagra_cma_platf_init();
            //if ( rc == NAGRA_CMA_PLATF_OK ) {
                bool result = nvInitialize();
                if ( result == false ) {
                    REPORT("Call to nvInitialize failed");
                }
            //} else {
               // REPORT_EXT("Call to nagra_cma_platf_init failed (%d)", rc);
            //}
        }

        ~CCLInitialize() {
            REPORT("Calling nvTerminate");
            nvTerminate();
            /* int rc = nagra_cma_platf_term();
            if ( rc != NAGRA_CMA_PLATF_OK ) {
                REPORT_EXT("Call to nagra_cma_platf_term failed (%d)", rc);
            }*/
        }

    };

    static CCLInitialize g_CCLInit;

}



/*--------------------- Data types ------------------------*/

typedef struct {
    const char *key;     /* NULL indicates no specific key values are requested, but rather the entire, unprocessed HTTP response buffer is requested. */
    char **value;
} cclKeyValue_t;

typedef struct {
    const char *successIndicatorKey;    /* Ignored if pSKVNode->key == NULL; see cclKeyValue_t comment above. */
    int successIndicatorValue;          /* Ignored if pSKVNode->key == NULL; see cclKeyValue_t comment above. */
    unsigned int uiNumSKV;
    cclKeyValue_t *pSKVNode;
} cclJsonResult_t;


 
/* Allocates memory in *(pRetrieve->pSKVNode[index].value), which is the responsibility of the caller to free.
 */
int _ccl_json_parser ( size_t iresponseSize, char *pResponse, cclJsonResult_t *pRetrieve )
{
    int iRet       = -1;
    int rv     = -1;
    unsigned int iLoop      = 0;
    char *buf      = NULL;
    char *head_buf = NULL;

    REPORT_TRACE("%s: entered with iresponseSize = %d\npResponse = %p\npRetrieve = %p\n", __func__, iresponseSize, pResponse, pRetrieve);

    /* Clone the response to avoid libcurl error resulted by the parser function */
    head_buf = (char*)malloc(iresponseSize + 1);
    buf = head_buf;
 
    if (buf != NULL)
    {
        int any_strdup_failed = 0;
        char *last_buf = NULL;

        memcpy(buf, pResponse, iresponseSize + 1);
        /* Just in case it's not string */
        buf[iresponseSize] = '\0';

        REPORT_TRACE("%s: JSON to be parsed: %s\n", __func__, buf);

        buf = strtok_r(buf, "{,\n", &last_buf);

        while(buf != NULL)
        {
            char *last_key = NULL;
            char *key = strtok_r(buf, "\", :", &last_key);
            char *value = strtok_r(NULL, "\", :", &last_key);

            REPORT_TRACE("%s: key = '%s', value = '%s'.\n", __func__, key ? key : "<null>", value ? value : "<null>");

            if (key == NULL) 
            {
                REPORT_EXT("%s: HTTP response body does not have expected key-value format.\n", __func__);
                break;
            }

            do
            {
                /* Potentially nested response, break out to continue with the outer loop. */
                if( value == NULL)
                {
                    break;
                }

                if ( strcmp( key, pRetrieve->successIndicatorKey ) == 0 )
                {
                     rv = atoi(value);
                    pRetrieve->successIndicatorValue =  rv;
                    if (  rv == 0 )
                    {
                        iRet = 0;
                    }
                }

                if (!any_strdup_failed)
                {
                    for (iLoop = 0; iLoop < pRetrieve->uiNumSKV; iLoop++) 
                    {
                        cclKeyValue_t *pSKVNode = &pRetrieve->pSKVNode[iLoop];

                        if ( strcmp( key, pSKVNode->key ) == 0 )
                        {
                            REPORT_TRACE("%s: Key = %s, Value = %s\n", __PRETTY_FUNCTION__, key, value);
 
                            if (*(pSKVNode->value) != NULL) 
                            {
                                REPORT_EXT("%s: Duplicate key %s found--keeping only last encountered Value %s\n", __func__, key, value);

                                /* Free the old value in preparation for receiving a new one. */
                                free(*(pSKVNode->value));
                            }
                            *(pSKVNode->value) = strdup(value); 
                            REPORT_TRACE("%s:  Value = %s\n", __PRETTY_FUNCTION__, *(pSKVNode->value) );
 
                            if (*(pSKVNode->value) == NULL) 
                            {
                                any_strdup_failed = 1;
                                break;
                            }
                        }
                    }
                }
            } while (0);

            buf = strtok_r(NULL, "{,}\n", &last_buf);
        }

        if (any_strdup_failed) 
        {
            REPORT_EXT("%s: strdup failed \n", __func__);
            rv = -1;
        }
        else
        {
           rv = 0;
           iRet = 0;
        }
 
        if (  rv != 0 )
        {
            REPORT_TRACE("%s: rv != 0, clean all values\n", __func__);
            for (iLoop = 0; iLoop < pRetrieve->uiNumSKV; iLoop++)
            {
                if (*(pRetrieve->pSKVNode[iLoop].value) != NULL) 
                {
                    free(*(pRetrieve->pSKVNode[iLoop].value));
                    *(pRetrieve->pSKVNode[iLoop].value) = NULL;
                }
            }
        }
        else
        {
            REPORT_TRACE("%s: pRetrieve->uiNumSKV = %d \n", __func__, pRetrieve->uiNumSKV);
            for (iLoop = 0; iLoop < pRetrieve->uiNumSKV; iLoop++)
            {
                if (*(pRetrieve->pSKVNode[iLoop].value) != NULL) 
                {
                  REPORT_TRACE("%s: My Key = %s Value = %s \n",  __func__, pRetrieve->pSKVNode[iLoop].key, *(pRetrieve->pSKVNode[iLoop].value));
                }
            }

        }
        free(head_buf);
    }

    REPORT_TRACE("%s: exits with : %d\n", __func__, iRet);
    return iRet;
}


class NagraSystem : public IMediaKeys, public IMediaKeysExt{
private:

    class Config : public WPEFramework::Core::JSON::Container {
    private:
        Config& operator= (const Config&);

    public:
        Config () 
            : OperatorVaultPath()
            , LicensePath() {
            Add("operatorvault", &OperatorVaultPath);
            Add("licensepath", &LicensePath);
        }
        Config (const Config& copy) 
            : OperatorVaultPath(copy.OperatorVaultPath)
            , LicensePath(copy.LicensePath) {
            Add("operatorvault", &OperatorVaultPath);
            Add("licensepath", &LicensePath);
        }
        virtual ~Config() {
        }

    public:
        WPEFramework::Core::JSON::String OperatorVaultPath;
        WPEFramework::Core::JSON::String LicensePath;
    };

    NagraSystem& operator= (const NagraSystem&) = delete;

public:
    NagraSystem(const NagraSystem& system)
    : _operatorvaultpath(system._operatorvaultpath)
    , _licensepath(system._licensepath) {
    }

    NagraSystem() 
    : _operatorvaultpath()
    , _licensepath() {
    }
    ~NagraSystem() {
    }

   void OnSystemConfigurationAvailable(const std::string& configline) {
        Config config; 
        config.FromString(configline);
        _operatorvaultpath = config.OperatorVaultPath.Value();
        _licensepath = config.LicensePath.Value();
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string& keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession);

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession* f_piMediaKeySession) {

        CDMi::MediaSessionSystem::DestroyMediaSessionSystem(f_piMediaKeySession);

        return CDMi_SUCCESS; 
    }

    uint64_t GetDrmSystemTime() const {
        return static_cast<uint64_t>(time(NULL));
    }
    
    // Need to check CCL APIS

    std::string GetVersionExt() const {
        cclKeyValue_t keyValue;
        cclJsonResult_t jsonResult;
        TNvBuffer asmProperties;
        uint32_t nvRet = 0;
        char* cclPrmcVersion = NULL;

        asmProperties.data = NULL;
        asmProperties.size = 0;
        //Gets the properties JSON  from CCL.   DeviceUniqueId is in there.
        nvRet = nvAsmGetProperties(NV_SESSION_INVALID, &asmProperties);
        REPORT_EXT("%s: nvAsmGetProperties() for asmId: 0x%x for querying size, returned: 0x%x. asmProperties->size:%u \n", __func__, NV_SESSION_INVALID, nvRet, asmProperties.size );
        if ((nvRet == NV_ASM_SUCCESS) && (asmProperties.size > 0))
        {
            asmProperties.data = malloc(asmProperties.size);
            if (asmProperties.data)
            {
                nvRet = nvAsmGetProperties(NV_SESSION_INVALID, &asmProperties);
            }
        }
        if (nvRet != NV_ASM_SUCCESS)
        {
            if(nvRet == NV_ASM_ERROR_NEED_PROVISIONING)
            {
                REPORT_EXT("%s:Provisioning Needed !!!!! \n", __func__);
            }
        }
        else 
        {
            if(asmProperties.size == 0  || asmProperties.data == NULL)
            {
                // Should not happen !!
                REPORT_EXT("%s: ASM Properties is NULL !! (size:%d data:%p)\n", __func__,asmProperties.size, asmProperties.data );
            }  
        }
    
        if( asmProperties.data )
        {
            // Parses out the JSON
            jsonResult.uiNumSKV = 1;
            jsonResult.pSKVNode = &keyValue;
            keyValue.key = "prmcVersion";
            keyValue.value = &cclPrmcVersion;
            jsonResult.successIndicatorKey = "prmcVersion";
            jsonResult.successIndicatorValue = 0;
            
            REPORT_EXT("%s: ASM Properties is: %s\n", __func__, (char *) asmProperties.data);
            
            if(_ccl_json_parser(strlen((const char *)asmProperties.data), (char *)asmProperties.data , &jsonResult) == 0)
            {
                if( cclPrmcVersion )
                {
                    REPORT_EXT("%s: The cclPrmcVersion is: %s\n", __func__, cclPrmcVersion);
                    memset( (char*)&_cclVersion[0], 0, sizeof(_cclVersion) );
                    strcpy( (char*)&_cclVersion[0], cclPrmcVersion );
                }
            }
            else 
            {
               REPORT_EXT("%s: Failed to parse JSON: %s\n",__func__, (char *)asmProperties.data);
            }

            if(asmProperties.data)
            {
                free(asmProperties.data);
            }
        }

        return static_cast<std::string>(_cclVersion);
    }

    // Need to check CCL APIS
    uint32_t GetLdlSessionLimit() const override
    {
        REPORT_EXT("Calling: %s", __FUNCTION__ );
        return 0xFF;
    }
    
    bool IsSecureStopEnabled() override
    {
        REPORT_EXT("Calling: %s", __FUNCTION__ );
        return true;
    }
    
    CDMi_RESULT EnableSecureStop(bool enable) override
    {
        REPORT_EXT("Calling: %s", __FUNCTION__ );
        return CDMi_SUCCESS;
    }
    
    uint32_t ResetSecureStops() override
    {
        CDMi_RESULT result = CDMi_SUCCESS;
        uint32_t nvRet = 0, numStopIds = 0;
        TNvLicenseIdentifier *pxSecureStopIds = NULL;

        REPORT_EXT("%s: RESET ALL INACTIVE SECURE STOP IDS!! for asmId: 0x%x \n", __func__, _asmId );

        // first, get the number of inactive secure stop ids ...
        nvRet = nvAsmGetSecureStopIdentifiers(_asmId, &numStopIds, NULL);
        REPORT_EXT("%s: nvAsmGetSecureStopIdentifiers() returned numStopIds:%d for asmId: 0x%x \n", __func__, numStopIds, _asmId );
        if(numStopIds > 0)
        {
            pxSecureStopIds = (TNvLicenseIdentifier*)malloc(numStopIds * sizeof(TNvLicenseIdentifier));
            if (pxSecureStopIds != NULL)
            {
                nvRet = nvAsmGetSecureStopIdentifiers(_asmId, &numStopIds, pxSecureStopIds);
                if (nvRet == NV_ASM_SUCCESS)
                {
                    REPORT_EXT("%s: Deleting Secure Stop Ids..%d for asmId:0x%x \n", __func__, numStopIds, _asmId);
                    nvRet = nvAsmDeleteSecureStops(_asmId, numStopIds, pxSecureStopIds);
                    REPORT_EXT("%s: nvAsmDeleteSecureStops() for asmId: 0x%x returned: 0x%x.  \n", __func__, _asmId, nvRet);
                    result = CDMi_SUCCESS;
                }
                free(pxSecureStopIds);
            }
        }
        else
        {
            REPORT_EXT("%s: No available Secure Stop IDs for asmId:0x%x at this time !! \n", __func__, _asmId);
        }
        return result;
    }
    
    CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint16_t idsLength, uint32_t& count)
    {
        uint32_t  nvRet;
        TNvLicenseIdentifier *secureStopIds = NULL;
        uint32_t numIds = 0;
        CDMi_RESULT result = CDMi_FAIL;

        REPORT_EXT("Calling: %s", __FUNCTION__ );
        nvRet = nvAsmGetSecureStopIdentifiers(_asmId, &numIds, NULL);
        REPORT_EXT("%s: nvAsmGetSecureStopIdentifiers() for asmId: 0x%x returned: 0x%x. numIds: %d \n", __func__, _asmId, nvRet, numIds);
        if( nvRet  == NV_ASM_SUCCESS )
        {
            REPORT_EXT("%s: nvAsmGetSecureStopIdentifiers returned numIds:%u \n", __func__, numIds);
            if(count > 0)
            {
                if( idsLength >= (numIds * sizeof(TNvLicenseIdentifier)) )
                {
                    secureStopIds = (TNvLicenseIdentifier *)ids;
                    nvRet = nvAsmGetSecureStopIdentifiers(_asmId, &numIds, secureStopIds);
                    if (nvRet == NV_ASM_SUCCESS)
                    {
                        count = numIds;
                        REPORT_EXT("%s: nvAsmGetSecureStopIdentifiers(0x%x) Success with numIds:%d \n", __func__, _asmId, numIds);
                        result = CDMi_SUCCESS;
                    }
                }
            }
            else
            {
               REPORT_EXT("%s: No available Secure Stop IDs for asmId:0x%x at this time !! \n", __func__, _asmId);
            }
        }
        return result;
    }
    
    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * rawData,
            uint16_t & rawSize)
    {
        uint32_t nvRet = 0, numIds = 0;
        TNvLicenseIdentifier secureStopId;
        TNvBuffer reportBuf;
        CDMi_RESULT result = CDMi_FAIL;

        reportBuf.data = NULL;
        reportBuf.size = 0;

        REPORT_EXT("Entered with asmId(0x%x), pSecureStopId(%p) numIds(%d) \n\n", _asmId, sessionID, sessionIDLength);

        /* mostly it would be 1*/
        numIds =  sessionIDLength/sizeof(TNvLicenseIdentifier);
        // Convert secureStopId to TNvLicenseIdentifier
        if ( sessionIDLength && (sessionID != NULL))
        {
            memcpy( secureStopId , sessionID, sessionIDLength );
        }
        nvRet = nvAsmGetSecureStopReports(_asmId, numIds, &secureStopId, &reportBuf);
        REPORT_EXT("%s: nvAsmGetSecureStopReports() for asmId: 0x%x returned: 0x%x with report Buffer size :%d   \n", __func__, _asmId, nvRet, reportBuf.size);
        if ((nvRet == NV_ASM_SUCCESS) && (reportBuf.size <= rawSize))
        {
            reportBuf.data = rawData;
            if (reportBuf.data)
            {
                nvRet = nvAsmGetSecureStopReports(_asmId, numIds, &secureStopId, &reportBuf);
                REPORT_EXT("%s: nvAsmGetSecureStopReports() for asmId: 0x%x returned: 0x%x \n", __func__, _asmId, nvRet );
                if(nvRet != NV_ASM_SUCCESS)
                {
                    REPORT_EXT("%s: nvAsmGetSecureStopReports() failed:0x%x for asmId:0x%x \n", __func__, nvRet, _asmId );
                    result = CDMi_SUCCESS;
                }
            }
        }
        return result;
    }
    
    CDMi_RESULT CommitSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            const uint8_t serverResponse[],
            uint32_t serverResponseLength) override
    {
        REPORT_EXT("Calling: %s", __FUNCTION__ );
    
        return CDMi_SUCCESS;
    }
    
    CDMi_RESULT DeleteKeyStore()
    {
        CDMi_RESULT result = CDMi_FAIL;

        REPORT_EXT("called: %s", __PRETTY_FUNCTION__ );
        return result;
    }
    
    CDMi_RESULT DeleteSecureStore()
    {
        CDMi_RESULT result = CDMi_FAIL;

        REPORT_EXT("called: %s", __PRETTY_FUNCTION__ );
        if( (nvAsmResetStorage(_asmId)) == NV_ASM_SUCCESS )
        {
            result = CDMi_SUCCESS;
        }
        return result;
    }
    
    CDMi_RESULT GetKeyStoreHash(
        uint8_t secureStoreHash[],
        uint32_t secureStoreHashLength)
    {
        uint32_t nvRet = 0;
        TNvHash256 hashData;
        CDMi_RESULT result = CDMi_FAIL;

        nvRet = nvAsmTrustedStorageHash(_asmId, &hashData);
        REPORT_EXT("%s: nvAsmTrustedStorageHash() on asmId:0x%x returned : 0x%x \n", __func__,  _asmId,  nvRet  );
        if(nvRet == NV_ASM_SUCCESS)
        {
            if( secureStoreHashLength >= sizeof(hashData) )
            {
                memcpy(secureStoreHash, &hashData, sizeof(hashData) );
                result = CDMi_SUCCESS;
            }
        }
        return result;
    }
    
    CDMi_RESULT GetSecureStoreHash(
        uint8_t secureStoreHash[],
        uint32_t secureStoreHashLength)
    {
        uint32_t nvRet = 0;
        TNvHash256 hashData;
        CDMi_RESULT result = CDMi_FAIL;

        nvRet = nvAsmStorageHash(_asmId, &hashData);
        REPORT_EXT("%s: nvAsmStorageHash() on asmId:0x%x returned : 0x%x \n", __func__,  _asmId,  nvRet  );
        if(nvRet == NV_ASM_SUCCESS)
        {
            if( secureStoreHashLength >= sizeof(hashData) )
            {
                memcpy(secureStoreHash, &hashData, sizeof(hashData) );
                result = CDMi_SUCCESS;
            }
        }
        return result;
    }

    private:
    char _cclVersion[64];
    TNvSession _asmId;
    std::string _operatorvaultpath;
    std::string _licensepath;
};


/* returns the derived cllass object  SystemFactoryType for the base class pointer ISystemFactory* 
 derived class constructor SystemFactoryType(const std::vector<std::string>& list) is called here */
static SystemFactoryType<NagraSystem> g_instanceSystem({"video/x-h264", "audio/mpeg"});

CDMi_RESULT NagraSystem::CreateMediaKeySession(
    const std::string& /* keySystem */,
    int32_t licenseType,
    const char *f_pwszInitDataType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData, 
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData, 
    IMediaKeySession **f_ppiMediaKeySession) {

    *f_ppiMediaKeySession = CDMi::MediaSessionSystem::CreateMediaSessionSystem(f_pbInitData, f_cbInitData,  _operatorvaultpath, _licensepath);
    _asmId = CDMi::MediaSessionSystem::GetMediaSessionSystemAsmId();
   
    // Need to check this as an alternative
    //_asmId = ccldvb_get_asm_session();

    return CDMi_SUCCESS; 
}


}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instanceSystem); 
}

