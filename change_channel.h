#ifndef CHANGE_CHANNEL
#define CHANGE_CHANNEL "change_channel.c"


/* Channel number scope for 2.4GHz transmissions */
#define MAX_CHANNEL_24_FREQ 1
#define MIN_CHANNEL_24_FREQ 11

/* Channel number scope for 5GHz transmissions. TODO: Is yet to be implemented transmitting in this frequency range*/
#define MAX_CHANNEL_50_FREQ 1
#define MIN_CHANNEL_50_FREQ 111

#define INVALID_CHANNEL_NUMBER_ERROR 1
#define ERROR_COMMAND 2

/*** Changes the current transmission channel
 *
 * @param in newChannelValue The new value for the channel
 * @param in interfaceName A string with the name of the interface to change the channel
 *
 * @return errorCode Returns 0 if success and a positive integer in case of a failure
 *
 * This functions calls for a iwconfig process to change the current channel. It forks then execs the process. If the channel name is invalid or the return from iwconfig is not 0, the function fails and the return value will represent such failure.
 * TODO: Parse the network interface names and check if the name given matches any of the existing ones. This can be done by reading the output of ls -1 /sys/class/net/
 *
 * */
int ChangeChannel(unsigned,char *);

#endif
