//This file is a sample to begin programming with TSS
//Supply a basic programming structure

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

//This is a useful macro to program with TSS
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
	
	TSS_HPCRS hPCRs = 0;
	BYTE TypePass[12]="My Password";
	UINT32 ulPcrLen;
	BYTE *rbgPcrValue;
	UINT32 encDataSize;
	BYTE *encData;
	FILE *fout;
	TSS_HENCDATA hEncData = 0;
	//By default SRK is 20bytes 0
	//takeownership -z
	BYTE wks[20]; 
	memset(wks,0,20);
	//At the beginning 
	//Create context and get tpm handle
	result =Tspi_Context_Create(&hContext);
	DBG("Create a context", result);
	result=Tspi_Context_Connect(hContext, NULL);
	DBG("Connect to TPM", result);
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	DBG("Get TPM handle", result);
	//Get SRK handle
	//This operation need SRK secret when you takeownership
	//if takeownership -z the SRK is wks by default
	result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	DBG("Get SRK handle", result);
	result=Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	DBG("Get SRK Policy", result);
	result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20, wks);
	DBG("Tspi_Policy_SetSecret", result);

	//Sealing Data
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_PCRS,
					0,
					&hPCRs);
	DBG("Createing a PCR object", result);
	result = Tspi_TPM_PcrRead(hTPM, 8,
				&ulPcrLen, &rbgPcrValue);
	DBG("Read the current value for PCR 8", result);
	result = Tspi_PcrComposite_SetPcrValue(hPCRs,8,20,rbgPcrValue);
	DBG("Set the value read from PCR8 as sealing value of PCR8", result);	

	result = Tspi_TPM_PcrRead(hTPM, 9,	
				&ulPcrLen, &rbgPcrValue);
	DBG("Read the current value for PCR 9", result);
	result = Tspi_PcrComposite_SetPcrValue(hPCRs,9,20,rbgPcrValue);
	DBG("Set the value read from PCR9 as sealing value of PCR9", result);
	//Create a data object for sealing
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_ENCDATA,
					TSS_ENCDATA_SEAL,
					&hEncData);
	DBG("Create data object for sealing", result);
	result = Tspi_Data_Seal(hEncData, 
				hSRK,
				strlen(TypePass),
				TypePass,hPCRs);
	DBG("Sealed my password, using the SRK key, to PCR 9", result);
	//Get the encrypted data and write it to file
	result = Tspi_GetAttribData(hEncData,
				TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				&encDataSize,
				&encData);
	DBG("Get the encrypted sealed data", result);
	fout = fopen("owner_auth.pass", "wb");
	if(fout != NULL)
	{
		write(fileno(fout), encData, encDataSize);
		fclose(fout);
	}
	else {
		printf("Error opening Owner_Auth.pass!");
	}
	//At the end of program 
	//Cleanup some object 
	result = Tspi_Context_FreeMemory(hContext, NULL);
	DBG("Tspi Context Free Memory", result);
	result = Tspi_Context_Close(hContext);
	DBG("Tspi Context Close", result);
	return 0;
}

