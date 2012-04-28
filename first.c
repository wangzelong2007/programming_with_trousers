#include<stdio.h>
#include<string.h>
#include<stdlib.h>
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
	result =Tspi_Context_Create(&hContext);
	DBG("Create a context\n", result);
	result=Tspi_Context_Connect(hContext, NULL);
	DBG("Connect to TPM\n", result);
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	DBG("Get TPM handle\n", result);
	result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	DBG("Get SRK handle\n", result);
	result=Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	DBG("Get SRK Policy\n", result);
	result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20, wks);
	DBG("Tspi_Policy_SetSecret\n", result);
	//result = Tspi_Context_Close (hContext);
	//DBG("Close Tspi Context\n",result);
	result = Tspi_Context_FreeMemory(hContext, NULL);
	DBG("Tspi Context Free Memory\n", result);
	result = Tspi_Context_Close(hContext);
	DBG("Tspi Context Close\n", result);
	return 0;
}

