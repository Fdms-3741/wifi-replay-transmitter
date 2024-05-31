#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "change_channel.h"


int ChangeChannel(unsigned newChannelValue, char *interfaceName){

	int
		currentPid, childStatus;
	
	char newChannelStrValue[3];
	char *command[] = {"/sbin/iwconfig",interfaceName,"set","channel",newChannelStrValue};
	
	// Returns if channel value number is invalid
	if (newChannelValue < MIN_CHANNEL_24_FREQ || newChannelValue > MAX_CHANNEL_24_FREQ){
		return INVALID_CHANNEL_NUMBER_ERROR;
	}

	// Converts unsigned to str
	sprintf(newChannelStrValue,"%u",newChannelValue);
	
	currentPid = fork();

	if(currentPid){
		waitpid(currentPid,&childStatus,0); /* Waits for child process to execute */
	}else{
		execv(command[0],command);
	}
	
	if (childStatus) {
		return ERROR_COMMAND;
	}
	return 0;
}

#define ERROR_INVALID_RADIOTAP_VERSION 999
#define ERROR_NO_CHANNEL_FIELD 998
#define ERROR_FREQUENCY_NOT_FOUND 997

/* Radiotap field */
#define RADIOTAP_HEADER_VERSION 0
#define RADIOTAP_FIELD_PRESENT 4

/* Defines the bit position for each field in the bitmap  */
#define RADIOTAP_BIT_TSFT_PRESENT 	(1 << 0)
#define RADIOTAP_BIT_FLAGS_PRESENT 	(1 << 1)
#define RADIOTAP_BIT_RATE_PRESENT 	(1 << 2)
#define RADIOTAP_BIT_CHANNEL_PRESENT 	(1 << 3)

/* Defines size of each field */
#define RADIOTAP_SIZE_TSFT 8
#define RADIOTAP_SIZE_FLAGS 1 
#define RADIOTAP_SIZE_RATE 1
#define RADIOTAP_SIZE_CHANNEL 0

#define FREQUENCIES_24GHZ_AVAILABLE {2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472,2484}
#define MAX_CHANNEL_VALUE 15

unsigned ChannelParser(unsigned char *packet){

	unsigned int
		channelLocation, /* Keeps track of how many fields were parsed */
		currentEvaluedFrequency; /* The header's max length, stops interation if cursor reaches this value */
	
	unsigned char
		frequencies[] = FREQUENCIES_24GHZ_AVAILABLE;

	unsigned char
		presentField;

	/* Verifies existance of the radiotap header */
	if (packet[0]){
		return ERROR_INVALID_RADIOTAP_VERSION;
	}
	
	/* Present */
	presentField = packet[RADIOTAP_FIELD_PRESENT];

	/* If channel not present, fails */
	if(!(presentField & RADIOTAP_BIT_CHANNEL_PRESENT)){
		return ERROR_NO_CHANNEL_FIELD;
	}

	/* Calculates channel position information */
	/* cursorPosition gets the amount of bytes to skip in order to get the first channel*/
	channelLocation = 	(presentField & RADIOTAP_BIT_TSFT_PRESENT) * RADIOTAP_SIZE_TSFT 
				+ ((presentField & RADIOTAP_BIT_FLAGS_PRESENT) >>1 ) * RADIOTAP_SIZE_FLAGS 
				+ ((presentField & RADIOTAP_BIT_RATE_PRESENT)  >>2 ) * RADIOTAP_SIZE_RATE
				+ RADIOTAP_SIZE_CHANNEL; /* How many bytes to skip in order to get the frequency value */
	
	/* Matches frequency value and returns corresponding channel number */
	for (currentEvaluedFrequency = 1; currentEvaluedFrequency < MAX_CHANNEL_VALUE; currentEvaluedFrequency++){
		if(packet[channelLocation] == frequencies[currentEvaluedFrequency])
			return currentEvaluedFrequency;	
	}

	return ERROR_FREQUENCY_NOT_FOUND;
}
	




