#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>

#define LOCAL_STATE_DIR "/usr/local/var/"
#define SOCKET_PATH LOCAL_STATE_DIR "/run/suricata/"
#define SOCKET_FILENAME "suricata-command.socket"
#define SOCKET_TARGET SOCKET_PATH SOCKET_FILENAME

#define VERSION_MSG "{ \"version\": \"0.1\" }"

typedef struct _pcap_file_t {
	char * filename;
	char * dirname;
	struct _pcap_file_t * next;
} pcap_file_t;

pcap_file_t * create_entry(char *filename, char *dirname)
{
	pcap_file_t *entry = NULL;

	printf("Creating %s (%s)\n", filename, dirname);
	if ((filename == NULL) || (dirname == NULL)) {
		printf("Invalid entry\n");
	}

	entry = calloc(1, sizeof(pcap_file_t));
	if (entry == NULL) {
		printf("Can not allocate entry");
		return NULL;
	}

	entry->filename = filename;
	entry->dirname = dirname;
	entry->next = NULL;

	return entry;
}

pcap_file_t * add_entry(pcap_file_t *list, pcap_file_t *entry)
{
	if (list == NULL) {
		entry->next = NULL;
		return entry;
	}

	entry->next = list;
	list = entry;

	return list;
}

/**
 *
 * \retval 1 if ok, 0 if not
 */
int validate_entry(pcap_file_t *entry)
{
	struct stat st;
	int ret = 0;

	ret = access(entry->filename, R_OK);
	if (ret != 0) {
		printf("Unable to access file '%s': %s\n",
				entry->filename,
				strerror(errno));
		return 0;
	}

	if (stat(entry->dirname, &st) != 0) {
		printf("Unable to access dir '%s' stat: %s\n",
				entry->dirname,
				strerror(errno));
		return 0;
	}
	if ((st.st_mode & S_IFMT) != S_IFDIR) {
		printf("File '%s' is not a directory.\n", entry->dirname);
		return 0;
	}

	return 1;
}

pcap_file_t * read_filelist(char * filelist)
{
	pcap_file_t *pcap_list = NULL;
	FILE * fl = NULL;
	int ret = 0;
	size_t n = 200;
	char *lineptr = malloc(n * sizeof(char));;

	if (lineptr == NULL) {
		printf("can not allocate lineptr\n");
		return NULL;
	}

	fl = fopen(filelist, "r");
	if (fl == NULL) {
		printf("Can not open file '%s' for reading: %s",
		       filelist,
		       strerror(errno));
		return NULL;
	}

	do {
		char * dir;
		pcap_file_t *entry;
		ret = getline(&lineptr, &n, fl);
		if (ret == -1) {
			break;
		}
		dir = strchr(lineptr, ';');
		if (dir == NULL) {
			printf("Invalid line: %s", lineptr);
		}
		dir[0] = 0;
		dir[strlen(dir + 1)] = 0;
		entry = create_entry(strdup(lineptr), strdup(dir + 1));
		if (entry == NULL) {
			printf("Can't create entry\n");
			free(lineptr);
			fclose(fl);
			return NULL;
		}
		pcap_list = add_entry(pcap_list, entry);

	} while (1);

	free(lineptr);
	fclose(fl);
	return pcap_list;
}

int process_pcap_file(int sck, pcap_file_t *files)
{
	int ret;
	char buffer[512];
	memset(buffer, 0, sizeof(buffer));

	ret = snprintf(buffer, sizeof(buffer) - 1,
		"{ \"command\": \"pcap-file\", "
		"\"arguments\": { \"filename\": "
		"\"%s\", \"output-dir\": \"%s\" } }",
		files->filename,
		files->dirname);
	if (ret < 0) {
		printf("Can not create message: %s\n", strerror(errno));
		return 0;
	} else if (ret == sizeof(buffer) - 1) {
		printf("Write buffer too small");
		return 0;
	}

	ret = send(sck, buffer, sizeof(buffer), 0);
	if (ret == -1) {
		printf("Can not send info: %s\n", strerror(errno));
		return 0;
	} else if (ret < strlen(VERSION_MSG)) {
		printf("Unable to send all message\n");
		return 0;
	}

	usleep(100 * 1000);
	memset(buffer, 0, sizeof(buffer));
	ret = read(sck, buffer, sizeof(buffer));
	if (ret == -1) {
		printf("Can not read answer: %s\n", strerror(errno));
		return 0;
	}

	printf("Buffer: %s.\n", buffer);

	return 1;
}


int main(int argc, char *argv[])
{
	int opt;
	int sck;
	struct sockaddr_un addr;
	char buffer[512];
	int ret;
	char* filelist = NULL;
	pcap_file_t *pcap_list = NULL;
	pcap_file_t *pp_list = NULL;

	while ((opt = getopt(argc, argv, "hf:")) != -1) {
		switch (opt) {
			case 'h':
				printf("Devine.\n");
				exit(0);
			case 'f':
				filelist = optarg;
				break;
			default:
				printf("Option inconnue.\n");
				exit(-1);
		}
	}

	if (filelist == NULL) {
		char *filename = NULL;
		char * dirname = NULL;

		if (argc - optind != 2) {
			printf("Invalid number of arguments.\n");
			exit(-1);
		}

		filename = argv[optind];
		dirname = argv[optind + 1];

		pcap_list = create_entry(filename, dirname);

	} else {
		if (argc - optind != 0) {
			printf("File and command entry are exclusive\n");
			exit(-1);
		}
		pcap_list = read_filelist(filelist);
	}

	pp_list = pcap_list;
	while (pp_list != NULL) {
		if (validate_entry(pp_list) == 0) {
			exit(-1);
		}
		pp_list = pp_list->next;
	}

	/* create socket */
	sck = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sck == -1) {
		printf("Can not create socket: %s\n", strerror(errno));
		exit(-1);
	}

	/* set address */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_TARGET, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	/* Connect to unix socket */
	ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
	if (ret == -1) {
		printf("Can not connect: %s\n", strerror(errno));
		exit(-1);
	}

	ret = send(sck, VERSION_MSG, strlen(VERSION_MSG), 0);
	if (ret == -1) {
		printf("Can not send info: %s\n", strerror(errno));
		exit(-1);
	} else if (ret < strlen(VERSION_MSG)) {
		printf("Unable to send all message\n");
		exit(-1);
	}

	memset(buffer, 0, sizeof(buffer));
	ret = read(sck, buffer, sizeof(buffer));
	if (ret == -1) {
		printf("Can not read answer: %s\n", strerror(errno));
		exit(-1);
	}

	printf("Buffer: %s.\n", buffer);

	pp_list = pcap_list;
	while (pp_list != NULL) {
		if (process_pcap_file(sck, pp_list) == 0) {
			printf("Unable to process '%s'", pp_list->filename);
		}
		pp_list = pp_list->next;
	}

	return 0;
}
