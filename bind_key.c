#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<tss/platform.h>
#include<tss/tss_defines.h>
#include<tss/tss_typedef.h>
#include<tss/tss_structs.h>
#include<tss/tspi.h>
#include<trousers/trousers.h>
#include<tss/tss_error.h>

#define DEBUG 1
#define DBG(message, tResult) { if(DEBUG)  printf("(Line%d, %s) %s returned 0x%08x. %s.\n",__LINE__ ,__func__ , message, tResult,(char *)Trspi_Error_String(tResult));}

#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}

int main(int argc, char **argv)
{
	
	TSS_HCONTEXT hContext=0;
	TSS_HTPM hTPM = 0;
	TSS_RESULT result;
	TSS_HKEY hSRK = 0;
	TSS_HPOLICY hSRKPolicy=0;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	BYTE wks[20]; 
	memset(wks,0,20);

	TSS_HKEY hESS_Bind_Key;
	TSS_UUID ESS_BIND_UUID=BACKUP_KEY_UUID;
	TSS_HPOLICY hESS_Policy;
	TSS_FLAG initFlags;
	BYTE *pubKey;
	UINT32 pubKeySize;
	FILE *fout;

	result =Tspi_Context_Create(&hContext);
	DBG("Create a context", result);
	result=Tspi_Context_Connect(hContext, NULL);
	DBG("Connect to TPM", result);
	
	
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	DBG("Get TPM handle", result);
	result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	DBG("Get SRK handle", result);
	result=Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	DBG("Get SRK Policy", result);
	result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1, 20, wks);
	DBG("Tspi_Policy_SetSecret", result);
	

	result = Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,
			TSS_POLICY_USAGE, &hESS_Policy);
	DBG("Create a key policy object", result);
	result = Tspi_Policy_SetSecret(hESS_Policy, TSS_SECRET_MODE_SHA1,
			20, wks);
	DBG("Set key policy object secret", result);
	initFlags = TSS_KEY_TYPE_BIND |
		    TSS_KEY_SIZE_2048 |
		    TSS_KEY_AUTHORIZATION |
		    TSS_KEY_NOT_MIGRATABLE;
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
			initFlags, &hESS_Bind_Key);
	DBG("Create the key object", result);
	result = Tspi_SetAttribUint32(hESS_Bind_Key,
		TSS_TSPATTRIB_KEY_INFO,
		TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
		TSS_ES_RSAESPKCSV15);
	DBG("Set the keys's padding type", result);
	result = Tspi_Policy_AssignToObject(hESS_Policy, hESS_Bind_Key);
	DBG("Assign the key's policy to the key", result);
	printf("Creating the key could take a while\n");
	result = Tspi_Key_CreateKey(hESS_Bind_Key,
		hSRK, 0);
	DBG("Asking TPM to create the key", result);
	result = Tspi_Context_RegisterKey(hContext,
					hESS_Bind_Key,
					TSS_PS_TYPE_SYSTEM,
					ESS_BIND_UUID,
					TSS_PS_TYPE_SYSTEM,
					SRK_UUID);
	DBG("Registering the key for later retrieval", result);
	
	printf("Registering the key blob for later retrieval\r\n");

	result = Tspi_Key_LoadKey(hESS_Bind_Key,hSRK);
	DBG("Loading key in TPM", result);
	result = Tspi_Key_GetPubKey(hESS_Bind_Key,
				&pubKeySize, &pubKey);
	DBG("Get Public portion of key", result);
	fout = fopen("BackupESSBindKey.pub", "wb");
	if(fout != NULL) {
		write(fileno(fout), pubKey, pubKeySize);
		printf("Finished writing BackupESSBindKey.pub\n");
		fclose(fout);
	}
	else {
		printf("Error opening XXXXXXXXXXXX \r\n");
	}
	result = Tspi_Policy_FlushSecret(hESS_Policy);
	DBG("Policy flush secret", result);

	result = Tspi_Context_FreeMemory(hContext, NULL);
	DBG("Tspi Context Free Memory", result);
	result = Tspi_Context_Close(hContext);
	DBG("Tspi Context Close", result);
	return 0;
	

}

