/* packet_injector.c
 *
 * Description:
 *		This program reads from a pcap file and injects the packets following the timestamps intervals.
 *
 */

#define _DEFAULT_SOURCE


#include <pcap/pcap.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>


#include <errno.h>
#include <string.h>

#include <pcap.h>
#include <pcap/dlt.h>

#include "change_channel.h"

/* DEBUG macro: Prints to screen the message if macro is set */
#ifdef __DEBUG__
	#define DEBUG(fmt, ...) do {printf("[DEBUG]: %s: %s: %d: "fmt, __FILE__, __FUNCTION__, __LINE__,##__VA_ARGS__);}while(0)
#else
	#define DEBUG(fmt, ... ) {}
#endif


#define DEFAULT_WIRELESS_INTERFACE "wlxec086b1e3d7c" /**< Interface to inject packets */

#define NANOSEC_MAX_VAL 999999999
#define PROCESS_OUTPUT_BUFFER_SIZE 100
#define OPTION_SIZE 30
#define FILENAME_SIZE 100

/**< Structure that encompass all required arguments to the @function InjectPacket function*/
struct ParserParameters {
	/** This value is the difference between current time and the time of capture of the first packet. 
	 * This difference can be added to the packet's timestamp value so it will now contain an absolute value of the time to send
	 * the packet based on the current time. This offers more precision using the clock_nanosleep() function from time.h */
	struct timespec timeAdd;
	struct timespec waitTime;
	pcap_t *injectInterfaceSession; /**< Session handler of the interface to inject packets */
	unsigned long int totalPackets;
	unsigned long long int totalBytes;
	unsigned long int failedAttempts;
	unsigned int currentChannel;

};

#ifndef TIMELESS 
static void DoTime(struct ParserParameters *, const struct pcap_pkthdr *);
static void DoTime(struct ParserParameters *arguments, const struct pcap_pkthdr *header){

	/* Adds the time difference from the file's timestamp and start time for transmission. */
	/* The wait time will be start time from the transmission plus its delay relative to the first packet in the file */
	arguments->waitTime.tv_nsec = header->ts.tv_usec + arguments->timeAdd.tv_nsec;
	if (arguments->waitTime.tv_nsec > NANOSEC_MAX_VAL){
		arguments->waitTime.tv_nsec -= NANOSEC_MAX_VAL - 1;
		arguments->waitTime.tv_sec = header->ts.tv_sec + arguments->timeAdd.tv_sec + 1;
	}else{
		arguments->waitTime.tv_sec = header->ts.tv_sec + arguments->timeAdd.tv_sec;
	}
	
	/* TODO: Read the channel value from a currentChannel variable. Change wireless channel if differs from last packet. */
	/* Can be done as a exec call (easy, probably less eficient) or using nl80211 library (hard, fastest, no documentation to assist) */

	/* Sleeps through the necessary time. Has microssecond precision */
	clock_nanosleep(CLOCK_REALTIME,TIMER_ABSTIME,&(arguments->waitTime),NULL);
}
#endif

/** Called for each packet in the pcap file, injects packet after the amount of time on the timestamp field has passed
 *	
 *	This function reads the timestamp from the pcap file and injects the packet if the amount of time from T0 has passed
 *	Sleeps the required amount of time
 *
 * */

void InjectPacket(u_char*, const struct pcap_pkthdr *, const u_char *);
void InjectPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	struct ParserParameters
		*arguments = (struct ParserParameters *) args;

	int
		error;
	int
		delay;

	
	DEBUG("Start injection\n");
	
	/* Counts total amount of packets */
	arguments->totalPackets++;

#ifndef TIMELESS
	DEBUG("Waiting the respective delay for this packet\n");
	DoTime(arguments,header);
#endif

	DEBUG("packet: %06lu / Failed attemps: %06lu\n",arguments->totalPackets,arguments->failedAttempts);
	
	/* Function to send packet */
#ifndef FASTEST
	do {
	    error = 0;
#endif
	    error = pcap_inject(((struct ParserParameters *)args)->injectInterfaceSession,packet,header->caplen);
	    delay = (int) 1000000.0* ((double)header->caplen) *8.0/(1024.0*1024.0);
	    DEBUG("delay: %i\n",delay);
	    usleep(delay); 
#ifdef FASTEST
	    arguments->totalBytes += error;
#endif

#ifndef FASTEST

	    arguments->totalBytes += error; /* This adds the total byte size that was transmitted by the receiver */
	    DEBUG("Size: %i / Error Code: %i \n",header->caplen,error);
	    if((bpf_u_int32)error != header->caplen){
		    DEBUG("ERROR when attempting to inject ");
		    arguments->failedAttempts++;
		    usleep(10000); /* Basically happens because interface buffer is full, waits for it to clear enough room */
	    }
	}while((bpf_u_int32)error != header->caplen);
#endif
	DEBUG("End injection.\n");
}

int main(int argc, char * argv[]){

	char
		errorBuffer[PCAP_BUF_SIZE], /**< Error buffer for internal pcap error messages */
		selectedInterface[OPTION_SIZE] = DEFAULT_WIRELESS_INTERFACE, /* Hold options set by user */
		option;
	
	const u_char 
		*firstPacket; /**< First packet to read and inject. Used to read timestamp value of pcap file. Injects imediately */

	unsigned int
		errorNumber;

	pcap_t 
		*sessionInterfaceHandler, /**< Session for the wireless interface to inject packets*/
		*sessionFileHandler; /**< Session for pcap file reading */
	
	struct ParserParameters
		parameters; /**< Parameters passed to the InjectPacket handler */
	
	struct pcap_pkthdr
		packetHeader;

	struct timespec
		initialTime;

	char
	    tempLocation[FILENAME_SIZE] = "/dev/shm/.packet_injector_transmit.pcap";

	/* Variables for for forking to count packets */
	int 
	    pipeFd[2] = {-1,-1};
	pid_t
	    pid;
	char 
	    processOutput[PROCESS_OUTPUT_BUFFER_SIZE];
	

	/* Program options */ 

	struct option longopts[] = {
		{"interface",1,NULL,'i'},
		{"channel",1,NULL,'c'}
	};

	/* Process options */
	while ((option = getopt_long(argc, argv, "c:i:", longopts, NULL))){
		if (option == (char) -1)
		    break;

		switch (option){
			case 'i':
				strncpy(selectedInterface,optarg,OPTION_SIZE);
				/* Quick parser to avoid unkown values */
				for (int i = 0; i < OPTION_SIZE; i++){
					if (selectedInterface[i] == ' ' || selectedInterface[i] == ';')
					    selectedInterface[i] = '\0';
				}
				break;
				
			default:
				fprintf(stderr,"Failed due to unkown option.");
				exit(EXIT_FAILURE);	

		}
		
	}

	DEBUG("Started pcap injector.\n");
	DEBUG("Selected interface: '%s'.\n",selectedInterface);

	/* Must receive the pcap file name */
	if (argc - optind != 1){
		fprintf(stderr,"ERROR: Exactly one argument must be passed on command line.\n");
		exit(EXIT_FAILURE);
	}
	
	/* Initializes pcap library */
	if(pcap_init(PCAP_CHAR_ENC_UTF_8,errorBuffer)){
		fprintf(stderr,"ERROR: Failed to initialize pcap library: %s\n",errorBuffer);
		exit(EXIT_FAILURE);
	}


	/* Initializes the interface handler */
	DEBUG("Starting interface handler...\n");	
	sessionInterfaceHandler = pcap_open_live(selectedInterface,BUFSIZ,1,1000,errorBuffer);

	if (!sessionInterfaceHandler){
		fprintf(stderr,"ERROR: couldn't open pcap session on device %s: %s\n",selectedInterface,errorBuffer);
		exit(EXIT_FAILURE);
	}
	
	if(pcap_setnonblock(sessionInterfaceHandler,0,errorBuffer)){
		fprintf(stderr,"ERROR: Failed to (un)set nonblocking mode: %s\n",errorBuffer);
		exit(EXIT_FAILURE);
	}

	/* Skips interface validation if interface is loopback */
	DEBUG("Checking for correct datagram type...\n");
	if (!strcmp(selectedInterface,"lo")){
		
	}	
	/* Stops if interface is not on mointor mode */
	else if (pcap_datalink(sessionInterfaceHandler) != DLT_IEEE802_11_RADIO){
	    	DEBUG("Value for 80211 + Radiotap: %i\n",DLT_IEEE802_11_RADIO);
		DEBUG("Returned value: %i\n",pcap_datalink(sessionInterfaceHandler));
		fprintf(stderr,"ERROR: Device is not properly set. Maybe is not on monitor mode.\n");
		exit(EXIT_FAILURE);
	}
	
	/* -------------------------------------------- */
	/* Copies the file to read to a tmpfs directory */
	/* -------------------------------------------- */
	
	if(pipe(pipeFd) == -1){
		fprintf(stderr,"ERROR: Unable to create pipe.\n");
		exit(EXIT_FAILURE);
	}

	if((pid = fork()) == -1){
		fprintf(stderr,"ERROR: Unable to fork process.\n");
		exit(EXIT_FAILURE);
	}
	
	/* Child */
	if (pid == 0){
	    
		dup2(pipeFd[1],STDERR_FILENO);
		close(pipeFd[0]);
		close(pipeFd[1]);
		execl("/bin/cp","cp",argv[optind],tempLocation,(char *)NULL);
		fprintf(stderr,"Error: Failed to execute copy.\n");
		exit(EXIT_FAILURE);

	}else{
		close(pipeFd[1]);
		/* pid gets to be a holder of the packet status value */
		wait(&pid);
		if(pid){
			read(pipeFd[0],processOutput,100);
			fprintf(stderr,"Error: Failed to copy data to temp dir.\n");
			processOutput[PROCESS_OUTPUT_BUFFER_SIZE - 1] = '\0';	
			fprintf(stderr,"%s\n",processOutput);
			exit(EXIT_FAILURE);
		}
	}
	/* --------------------------------------------- */

	/* Initializes the file reading handler */
	DEBUG("Opening session for pcap file reading...\n");
	if (!(sessionFileHandler = pcap_open_offline_with_tstamp_precision(tempLocation,PCAP_TSTAMP_PRECISION_NANO,errorBuffer))){
		fprintf(stderr,"ERROR: Failed to open pcap file for reading: %s\n",errorBuffer);
		exit(EXIT_FAILURE);
	}
	

	/* Initializes values for parameters and gets current time */
	DEBUG("Setting parameters for injector...\n");
	parameters.injectInterfaceSession = sessionInterfaceHandler;
	parameters.totalPackets = 1;
	parameters.failedAttempts = 0;

	/* Get the first packet to calculate time delays */
	firstPacket = pcap_next(sessionFileHandler,&packetHeader);
	parameters.totalBytes = packetHeader.caplen;
	
	clock_gettime(CLOCK_REALTIME,&initialTime);

	parameters.timeAdd.tv_sec = initialTime.tv_sec -  packetHeader.ts.tv_sec;
	parameters.timeAdd.tv_nsec = initialTime.tv_nsec - packetHeader.ts.tv_usec;
	
	DEBUG("Got first packet's timestamp (%li) difference from now (%li). Time difference is set as %li.%li seconds.\n",packetHeader.ts.tv_sec,initialTime.tv_sec,parameters.timeAdd.tv_sec,parameters.timeAdd.tv_nsec);
	
	DEBUG("Sending first packet.\n");
	errorNumber = pcap_inject(sessionInterfaceHandler,firstPacket,packetHeader.caplen);

	if(errorNumber != packetHeader.caplen){
		fprintf(stderr,"ERROR: Error (%i) when injecting packet in interface: %s\n",errorNumber,pcap_geterr(sessionInterfaceHandler));
		exit(1);
	}
	
	/* Initializes the file reading and packet injection, calls InjectPacket for each packet read */
	DEBUG("Entering loop...\n");
	if ((errorNumber = pcap_loop(sessionFileHandler,-1,&InjectPacket,(u_char *)&parameters)) && (int) errorNumber != PCAP_ERROR_BREAK){
		fprintf(stderr,"ERROR: Unexpected pcap error on loop: %s\n",pcap_geterr(sessionInterfaceHandler));
		exit(1);
	}
	
	
	
	/* ----- PROGRAM FINISH -------*/
	
	/* -------------------------------------------- */
	/* Copies the file to read to a tmpfs directory */
	/* -------------------------------------------- */
	
	if(pipe(pipeFd) == -1){
		fprintf(stderr,"ERROR: Unable to create pipe.\n");
		exit(EXIT_FAILURE);
	}

	if((pid = fork()) == -1){
		fprintf(stderr,"ERROR: Unable to fork process.\n");
		exit(EXIT_FAILURE);
	}
	
	/* Child */
	if (pid == 0){
	    
		dup2(pipeFd[1],STDERR_FILENO);
		close(pipeFd[0]);
		close(pipeFd[1]);
		execl("/bin/rm","rm",tempLocation,(char *)NULL);
		fprintf(stderr,"Error: Failed to remove temp file.\n");
		exit(EXIT_FAILURE);

	}else{
		close(pipeFd[1]);
		/* pid gets to be a holder of the packet status value */
		wait(&pid);
		if(pid){
			read(pipeFd[0],processOutput,100);
			fprintf(stderr,"Error: Failed to copy data to temp dir.\n");
			processOutput[PROCESS_OUTPUT_BUFFER_SIZE - 1] = '\0';	
			fprintf(stderr,"%s\n",processOutput);
			exit(EXIT_FAILURE);
		}
	}
	/* Uses timeAdd variable to store current time so it can display elapsed seconds */
	clock_gettime(CLOCK_REALTIME,&(parameters.timeAdd));
	
	printf("{\"frames\":%lu,\"bytes\":%llu,\"failed_attempts\":%lu,\"total_time\":%li.%09li}\n",parameters.totalPackets,parameters.totalBytes,parameters.failedAttempts,
			((parameters.timeAdd.tv_nsec < initialTime.tv_nsec)?(parameters.timeAdd.tv_sec - initialTime.tv_sec - 1):(parameters.timeAdd.tv_sec - initialTime.tv_sec)),
			((parameters.timeAdd.tv_nsec < initialTime.tv_nsec)?(parameters.timeAdd.tv_nsec + NANOSEC_MAX_VAL - initialTime.tv_nsec):(parameters.timeAdd.tv_nsec - initialTime.tv_nsec)));
	DEBUG("Finished successfully.\n");

}
