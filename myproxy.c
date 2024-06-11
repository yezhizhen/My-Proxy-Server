#define _GNU_SOURCE
#include "stack.h"
#include "myproxy.h"
#include <pthread.h>
#include <crypt.h>
#include <netdb.h>
#include <regex.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include "compare_time.h"
#define DIRECTORY "resources/"
Stack stack;
typedef struct thread_args
{
	int accept_fd;	
	pthread_t pt;
	int index;
    int is_modified;
    char* is_modified_field;
    int no_cache_signal;
    char* url;
    char* filetype;
    char ip[18];
    int portnumber;
    int has_local;
    int sd;
    int keep_alive;
}thread_args;

void * handle_a_socket(void *input);
void forward_cache(thread_args* status, char* request, char* filename, int fd);
void forward_no_cache(thread_args* status, char* request);

int main(int argc, char** argv)
{
    init_stack(&stack);	
	thread_args t_args[STACK_MAX];
    int temp;
	if(argc != 2)
	{
		fprintf(stderr, "Usage %s [port]\n", argv[0]);
        exit(1);
    }	
	unsigned short port = atoi(argv[1]);
    int fd;
    struct sockaddr_in addr, tmp_addr;
	unsigned int addrlen = sizeof(struct sockaddr_in);
	fd = socket(AF_INET, SOCK_STREAM, 0);		// Create a TCP Socket for accepting
	//printf("server listening socket is:%d\n",fd);
	if(fd == -1)
	{
		perror("socket()");
		exit(1);
	}
    
    //make port reusable
    long val=1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(long))==-1)
    {
        perror("setsockopt");
        exit(1);
    }
	// 4 lines below: setting up the port for the listening socket

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	// bind to all IPs of the machine
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	// After the setup has been done, invoke bind()

	if(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
	{
		perror("bind()");
		exit(1);
	}
    
    if( listen(fd, STACK_MAX) == -1 )
	{
		perror("listen()");
		exit(1);
	}
    //create resources directory
    struct stat st = {0};

    if (stat("resources", &st) == -1) {
	    if(mkdir("resources", 0700)==-1)
		{
			perror("mkdir");
			exit(-1);
		}
    }

    
    //accepting loop
    while(1) {
		// Accept one client. tmp_addr filled with client information
		if( (t_args[temp = pop(&stack)].accept_fd = accept(fd, (struct sockaddr *) &tmp_addr, &addrlen)) == -1)
		{
			perror("accept()");
			exit(1);
		}

		if(temp<0)	continue;
		t_args[temp].index = temp;
		//create the thread here
		pthread_create(&t_args[temp].pt,NULL,handle_a_socket, &t_args[temp]);
		pthread_detach(t_args[temp].pt);
		
	}
}

//return 1 if modified
int setIp(thread_args* status, char* hostname)
{
    struct hostent *he;
	struct in_addr ** addrList;
	he = gethostbyname(hostname);
	//if null
	if(!he){
		perror("gethostbyname()");
		return -1;
	}
	addrList = (struct in_addr**) he->h_addr_list;
	if( strcmp(inet_ntoa(*addrList[0]),status->ip) == 0)
        return 0;
    else
    {
        strcpy(status->ip,inet_ntoa(*addrList[0]));
        return 1;
    }
}

int parse(char* field,thread_args* status, char* input)
{
    char* start;
    int field_length;
    int header_length;
    int total_length;
    if(strcmp(field,"If-Modified-Since")==0)
    {
        if((start=strstr(input,"If-Modified-Since")) !=NULL)
        {
            header_length = strlen("If-Modified-Since: ");
            status->is_modified = 1;
            field_length = strcspn(start,"\r\n")-header_length;
            status->is_modified_field = malloc(field_length+1);
            status->is_modified_field[field_length] = 0;
            strncpy(status->is_modified_field,&start[header_length],field_length);
            //printf("If-Modified-Since: %s\n",status->is_modified_field);
        }
    }
    else if(strcmp(field,"Cache-Control")==0)
    {
        if((start=strstr(input,"Cache-Control")) !=NULL )
        {
            header_length = strlen("Cache-Control: ");
            total_length = strcspn(start,"\r\n")- header_length;
            char copy[total_length+1];
            copy[total_length] = 0;
            strncpy(copy,&start[header_length],total_length);
            const char* target_signal = "no-cache";
            regex_t regex;
            int result;
            
            regcomp(&regex, target_signal, 0);	
            result = regexec(&regex, copy,0,NULL,0);
            //if matched
            if(result==0)
            {
                status->no_cache_signal = 1;
                printf("[%d]:no-cache required\n",status->index);
            }
            else
                status->no_cache_signal = 0;
            regfree(&regex);
        }
    }
    else if(strcmp(field,"GET")==0)
    {
        if((start=strstr(input,"GET")) !=NULL )
        {
            total_length = strstr(start," HTTP")-start;
            header_length = strlen("GET ");
            field_length = total_length-header_length;
            status->url = malloc(field_length+1);
            status->url[field_length] = 0;
            strncpy(status->url,&start[header_length],field_length);
            //printf("\nParsed GET: %s\n",status->url);
            int last_index;
            for(int i=0;i<total_length;i++)
            {
                if(start[i]=='.')
                    last_index = i;
            }
            status->filetype=malloc(total_length-last_index+1);
            status->filetype[total_length-last_index]=0;
            strncpy(status->filetype,&start[last_index],total_length-last_index);
            //printf("Parsed File type: %s\n\n",status->filetype);
            
        }
        else
        {
            //printf("[%d]: This is not a GET request... I don't cope with this...\n",status->index);
            return -1;
        }
    }
    else if(strcmp(field,"Host")==0)
    {
        
        if((start=strstr(input,"Host")) !=NULL)
        {
            header_length = strlen("Host: ");
            field_length = strcspn(start,"\r\n")-header_length;
            fflush(stdout);
            int i;
            for(i=0;i<field_length;i++)
            {
                if(start[header_length+i]==':')
                    break;
            }
            int newport;
            //if no port set
            if(i==field_length) 
            {
                newport = 80;
            }
            else
            {
                char port_string[field_length-i];
                port_string[field_length-i-1] = 0;
                strncpy(port_string, &start[header_length+i+1], field_length-i-1);
                newport = atoi(port_string);
            }
            int port_modified = 0;
            if(status->portnumber != newport)
                port_modified = 1;
            status->portnumber = newport;
            char hostname[i+1];
            hostname[i] = 0;
            strncpy(hostname, &start[header_length], i);
                
            int ip_modified = setIp(status, hostname);
            if (ip_modified || port_modified)
            {
                printf("[%d]: ip/port has been modified..\n",status->index);
                close(status->sd);
                status->sd = -1;
            }
            //printf("[%d]: hostname: %s    Ip: %s:%d\n",status->index,hostname, status->ip, status->portnumber);
        }
    }
    else if (strcmp(field,"Connection")==0)
    {
        //if contains close
        if((strstr(input,"Connection: close")) !=NULL || (strstr(input,"Proxy-Connection: close")) !=NULL)
            status->keep_alive = 0;
        else
            status->keep_alive = 1;
    }
}

int valid_type(char* filetype)
{
    if(strcmp(filetype, ".html")==0 || 
        strcmp(filetype, ".jpg")==0 || 
        strcmp(filetype, ".gif")==0 || 
        strcmp(filetype, ".txt")==0 ||
        strcmp(filetype, ".pdf")==0) 
    {
        
        printf("Type:%s should be cached.\n",filetype);
        return 1;
    }
    else
    {
        printf("Type:%s should not be cached.\n",filetype);
        return 0;
    }
}


int open_socket(thread_args* status)
{
    int sd = socket(AF_INET,SOCK_STREAM,0);
	if(sd < 0)
	{
		perror("socket()");
		exit(-1);
	}
	//declare the structure for handling internet addresses
	struct sockaddr_in server_addr;
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family=AF_INET;
	server_addr.sin_addr.s_addr=inet_addr(status->ip);
	//set the port
	server_addr.sin_port=htons(status->portnumber);
	if(connect(sd,(struct sockaddr *)&server_addr,sizeof(server_addr))<0){
		printf("connection error: %s (Errno:%d)\n",strerror(errno),errno);
		exit(0);
	}
    return sd;
} 

typedef struct _response_
{
    //0 represents content-length; 1 represents transfer-encoding; 2 represents both not exists;
    int type;
    int content_length;
    char status_code[4];
    int keep_alive;
    //char last_modified[80];
} response_status;

//read either from file or socket
void read_send(int size, thread_args* status, int fd) 
{
    //send file data
    int remain_size = size;
    while(remain_size > 0)
    {
        int sent_size;
        if( remain_size > MAX_CHUNK_SIZE )   sent_size = MAX_CHUNK_SIZE;
        //just send all remain size
        else    sent_size = remain_size;
        char buffer[sent_size];
        read(fd, buffer, sent_size);
        //write to client
        if(write_bytes(status->accept_fd, buffer, sent_size)<0) return;
        remain_size -= sent_size;
    }
    //printf("Successfully Send %d bytes\n\n", size);
}

void read_send_cache(int size, thread_args* status, int sd, int fd)
{
    int remain_size = size;
    while(remain_size > 0)
    {
        
        int sent_size;
        if( remain_size > MAX_CHUNK_SIZE )   sent_size = MAX_CHUNK_SIZE;
        //just send all remain size
        else    sent_size = remain_size;
        char buffer[sent_size];
        if(read_bytes(sd, sent_size, buffer)<0)
            return;
        //write to file
        write(fd,buffer,sent_size);
        if(write_bytes(status->accept_fd, buffer, sent_size)<0) return;
        remain_size -= sent_size;
    }
    //printf("Successfully sending and caching %d bytes\n", size);
}

response_status parse_response(char* response)
{
    response_status res_sta;
    res_sta.status_code[3] = 0;
    //get status code
    strncpy(res_sta.status_code, &response[9],3);
    //printf("Parsed status_code: %s\n", res_sta.status_code);
    //parse connection
   
    //if contains close
    if((strstr(response,"Connection: close")) !=NULL || (strstr(response,"Proxy-Connection: close")) !=NULL)
        res_sta.keep_alive = 0;
    else
        res_sta.keep_alive = 1;
    
    char* start;
    /*if((start=strstr(response,"Last-Modified")) !=NULL)
    {
        int header_length = strlen("Last-Modified: ");
        int field_length = strcspn(start,"\r\n")-header_length;
        
        res_sta.last_modified[field_length] = 0;
        strncpy(res_sta.last_modified,&start[header_length],field_length);
        
        printf("Parsed Last-Modified: %s\n",res_sta.last_modified);
    }
    */
    int field_length;
    int header_length;
    int total_length;
    if((start=strstr(response,"Content-Length")) !=NULL)
    {
        res_sta.type = 0;
        header_length = strlen("Content-Length: ");
        field_length = strcspn(start,"\r\n")-header_length;
        char temp[field_length+1];
        temp[field_length] = 0;
        strncpy(temp,&start[header_length],field_length);
        res_sta.content_length = atoi(temp);
        //printf("Parsed Content-Length: %d\n",res_sta.content_length = atoi(temp));
    }
    else if((start=strstr(response,"Transfer-Encoding: chunked")) !=NULL)    res_sta.type = 1;
    else    res_sta.type = 2;
    return res_sta;
}

void forward_no_cache(thread_args* status, char* request)
{
    //open connection if haven't been opened.
    if(status->sd == -1)
        status->sd = open_socket(status);
    int sd = status->sd;
    //send request
    if(write_bytes(sd, request, strlen(request))<0) goto try_close1;
    //wait for response
    char* response_header = readheader(sd);
    //printf("%s\n", response_header);
    //parse response
    response_status res_sta = parse_response(response_header);
    //send the header
    
    if(write_bytes(status->accept_fd,response_header,strlen(response_header))<0)    goto try_close1;
    //content-length based
    if(res_sta.type == 0)  read_send(res_sta.content_length, status, sd);    
    //chunked transfer
    else if(res_sta.type == 1)
    {
        while(1)
        {
            //reserve 8 bytes. 16 hex symbol. 
            char buf[17];
            memset(buf,0,17);
            int counter = 0;
            //parse the size
            while(counter<3 || strcmp(&buf[counter-2],"\r\n") !=0)
            {
                if(read_bytes(sd, 1, &buf[counter])<0)
                    goto try_close1;
                counter++;
            }
            //write to network
            if(write_bytes(status->accept_fd, buf, counter)<0)  goto try_close1;
            //convert buf
            //printf("\nbuf: %s\n",buf);
            int chunk_length = strtol(buf,NULL,16);
            //printf("Parsed chunk size: %d\n",chunk_length);
            //read and send
            //last two /r/n
            read_send(chunk_length+2, status, sd);
            if(chunk_length == 0)   break;
        }
    }
    
    try_close1:;
    //close
    if(!res_sta.keep_alive)
    {
        close(sd);
        status->sd = -1;
    }
    free(response_header);
}

void forward_cache(thread_args* status, char* request, char* filename, int fd)
{
    //open connection
    if(status->sd == -1)
        status->sd = open_socket(status);
    int sd = status->sd;
    //send request
    if(write_bytes(sd, request, strlen(request))<0) return;
    //wait for response
    char* response_header = readheader(sd);
    //printf("%s\n", response_header);
    
    //parse response
    response_status res_sta = parse_response(response_header);
    
    
    //send the data
    if(strcmp(res_sta.status_code,"200")==0)
    {
        //send the header
        if(write_bytes(status->accept_fd,response_header,strlen(response_header))<0)    goto tryclose2;
        //content-length based
        if(res_sta.type == 0)  
        {
            read_send_cache(res_sta.content_length, status, sd, fd);
        }//chunked transfer
        else if(res_sta.type == 1)
        {
            while(1)
            {
                //reserve 8 bytes. 16 hex symbol. 
                char buf[17];
                memset(buf,0,17);
                int counter = 0;
                //parse the size
                while(counter<3 || strcmp(&buf[counter-2],"\r\n") !=0)
                {
                    if(read_bytes(sd, 1, &buf[counter])<0)
                        goto tryclose2;
                    counter++;
                }
                //write to network
                if(write_bytes(status->accept_fd, buf, counter)<0)
                    break;
                //convert buf
                int chunk_length = strtol(buf,NULL,16);
                //printf("\nParsed chunk size: %d\n",chunk_length);
                //read and send and cache file data
                read_send_cache(chunk_length, status, sd, fd);
                //filter out two \r\n
                read_send(2, status, sd);
                if(chunk_length == 0)   break;
            }
            //struct tm* mytm= gmtime(&st.st_mtime);
            //struct tm requesttm;
            //strptime(status->is_modified_field,"%a, %d %b %Y %OH:%M:%S GMT",&requesttm);
        }
    }
    //client has cached. No data received.
    else if(strcmp(res_sta.status_code,"304")==0)
    {
        //no local file
        if(!status->has_local)
        {
            //send the header
            if(write_bytes(status->accept_fd,response_header,strlen(response_header))<0)    goto tryclose2;
            //remove the file
            char path[strlen(DIRECTORY)+24];
            strcpy(path,DIRECTORY);
            strcpy(&path[strlen(DIRECTORY)],filename);
            remove(path);
        }
        //has local file
        else
        {
            //case 3. return the cache.
            if(status->no_cache_signal && !status->is_modified)
            {
                int size;
                struct stat st;
                //check if file exists
                if(fstat(fd, &st)==0)   size = st.st_size;
                else
                {
                    perror("fstat()");
                    exit(-5);
                }
                //send header    
                char *head = "HTTP/1.1 200 OK\r\nContent-Length: ";
                if(write_bytes(status->accept_fd, head, strlen(head))<0)    goto tryclose2;
                char hex_size[17];
                sprintf(hex_size, "%d", size);
                if(write_bytes(status->accept_fd, hex_size, strlen(hex_size))<0)    goto tryclose2;
                if(write_bytes(status->accept_fd, "\r\n\r\n", 4)<0) goto tryclose2;
                //send file data
                read_send(size, status, fd);
            }
            //case 4
            else if(status->no_cache_signal && status->is_modified)
            {
                //if-modified-since field comes from client
                //return 304 message
                //send the header    
                if(strstr(request,status->is_modified_field)!=NULL)
                {
                    if(write_bytes(status->accept_fd,response_header,strlen(response_header))<0)    goto tryclose2;
                }
                //from cached object
                else
                {
                    //return the local cache
                    int size;
                    struct stat st;
                    //check if file exists
                    if(fstat(fd, &st)==0)   size = st.st_size;
                    else
                    {
                        perror("fstat()");
                        exit(-5);
                    }
                    char *head = "HTTP/1.1 200 OK\r\nContent-Length: ";
                    if(write_bytes(status->accept_fd, head, strlen(head))<0)    goto tryclose2;
                    char hex_size[17];
                    sprintf(hex_size, "%d", size);
                    if(write_bytes(status->accept_fd, hex_size, strlen(hex_size))<0)    goto tryclose2;
                    if(write_bytes(status->accept_fd, "\r\n\r\n", 4)<0) goto tryclose2;
                    //send file data
                    read_send(size, status, fd);
                }
           }
        }
    }
    tryclose2:;
    //close
    if(!res_sta.keep_alive)
    {
      close(sd);
      status->sd = -1;
    }
    free(response_header);
}

void resolve_response(thread_args* status, int valid_type, char* filename, char* request, int fd)
{
    //don't cache this type
    if(valid_type == 0)
    {
        forward_no_cache(status, request);
    }
    //this type should be cached
    else
    {
        //local file not exists... Download and write to disk...
        if(!status->has_local)
        {
            forward_cache(status, request, filename, fd);
        }
        //local file exists... Case analysis.
        else
        {
            //construct response 200 and includes web object
            if(!status->is_modified && !status->no_cache_signal)
            {
                //printf("[%d]: 1\n",status->index);
                int size;
                struct stat st;
                //check if file exists
                if(fstat(fd, &st)==0)   size = st.st_size;
                else
                {
                    perror("fstat()");
                    exit(-3);
                }
                char *head = "HTTP/1.1 200 OK\r\nContent-Length: ";
                if(write_bytes(status->accept_fd, head, strlen(head))<0)    return;
                char hex_size[17];
                sprintf(hex_size, "%d", size);
                if(write_bytes(status->accept_fd, hex_size, strlen(hex_size))<0)    return;
                /*if(strcmp(status->filetype,".html")==0)
                {
                    char* ct = "\r\nContent-Type: text/html";
                    if(write_bytes(status->accept_fd,ct, strlen(ct))<0)    return;
                }*/
                if(write_bytes(status->accept_fd, "\r\n\r\n", 4)<0) return;
                //send file data
                read_send(size, status, fd);
            }
            //With If-Modified-Since and without Cache-Control
            else if(status->is_modified && !status->no_cache_signal)
            {
                int size;
                struct stat st;
                //printf("[%d]: 2\n",status->index);
                //check if file exists
                if(fstat(fd, &st)==0)   size = st.st_size;
                else
                {
                    perror("fstat()");
                    exit(-3);
                }
                struct tm* mytm= gmtime(&st.st_mtime);
                struct tm requesttm;
                strptime(status->is_modified_field,"%a, %d %b %Y %OH:%M:%S GMT",&requesttm);
                int compare_result = compare_time(mytm, &requesttm);   
                //request time is later
                //send 304 header
                if(compare_result < 0)
                {
                    char* const head = "HTTP/1.1 304 Not Modified\r\n\r\n";
                    write_bytes(status->accept_fd, head, strlen(head));
                    return;
                }
                else
                {
                    printf("[%d]: cached is later\n",status->index);
                    char* const head = "HTTP/1.1 200 OK\r\nContent-Length: ";
                    if(write_bytes(status->accept_fd, head, strlen(head))<0)    return;
                    char hex_size[17];
                    sprintf(hex_size, "%d", size);
                    if(write_bytes(status->accept_fd, hex_size, strlen(hex_size))<0)    return;
                    if(write_bytes(status->accept_fd, "\r\n\r\n", 4)<0) return;
                    read_send(size, status, fd);
                }
            }
            //without if_m_s and with no_cache
            else if(!status->is_modified && status->no_cache_signal)
            {
                //printf("[%d]: 3\n",status->index);
                //insert IF-MO-Sin into into request
                int size;
                struct stat st;
                char* myhead = "If-Modified-Since: ";
                memcpy(&request[strlen(request)-2], myhead, strlen(myhead));
                if(fstat(fd, &st)==0)   size = st.st_size;
                else
                {
                    perror("fstat()");
                    exit(-3);
                }
                struct tm* mytm= gmtime(&st.st_mtime);
                char if_m_s[65];
                //Tue, 16 Feb 2016 23:55:38 GMT
                strftime(if_m_s, 65, "%a, %d %b %G %H:%M:%S GMT", mytm);
                //concatenate to request
                strcat(request, if_m_s);
                strcat(request, "\r\n\r\n");
                printf("[%d]: After concatenation:\n%s\n", status->index,request);
                forward_cache(status, request, filename, fd);

            }
            //with if_m_s and with no_cache
            else if(status->is_modified && status->no_cache_signal)
            {
                //printf("[%d]: 4\n",status->index);
                //insert IF-MO-Sin into into request
                int size;
                struct stat st;
                //check if file exists
                if(fstat(fd, &st)==0)   size = st.st_size;
                else
                {
                    perror("fstat()");
                    exit(-3);
                }
                struct tm* mytm= gmtime(&st.st_mtime);
                struct tm requesttm;
                strptime(status->is_modified_field,"%a, %d %b %Y %OH:%M:%S GMT",&requesttm);
                int compare_result = compare_time(mytm, &requesttm);
                //cached is later. Modify if modified since
                if(compare_result==1)
                {
                    char *temporary = "If-Modified-Since: ";
                    char *start;
                    char if_m_s[65];
                    //Tue, 16 Feb 2016 23:55:38 GMT
                    strftime(if_m_s, 65, "%a, %d %b %G %H:%M:%S GMT", mytm);
                    if((start=strstr(request,temporary)) !=NULL)
                    {
                        memcpy(&start[strlen(temporary)], if_m_s, strlen(if_m_s));
                    }
                    printf("[%d]: Change if_m_s..\n",status->index);
                    printf("[%d]: \n%s\n", status->index,request);
                    
                }
                forward_cache(status, request, filename, fd);
            }
            
            
        }
    }
}


void resolve_request(thread_args* status, char* request)
{
    //This type should be cached
    printf("[%d]: ",status->index);
    if(valid_type(status->filetype))
    {
        //check if has been cached
        struct crypt_data data;
        data.initialized = 0;
        //the encrypted filename
        char filename[24];
        filename[23] = 0;
        strncpy(filename, crypt_r(status->url,"$1$00$",&data)+6, 23);
        for(int i=0;i<22;i++)
        {
            if(filename[i] == '/')
                filename[i] = '_';
        }
        char path[strlen(DIRECTORY)+24];
        strcpy(path,DIRECTORY);
        strcpy(&path[strlen(DIRECTORY)],filename);
        int fd;
        //check if file exists
        //not exists
        if(access(path,F_OK) == -1)
        {
            printf("[%d]: %s does not exist...\n", status->index,filename);
            /**/
            status->has_local = 0;
            fd = open(path,O_CREAT|O_WRONLY,S_IRWXU);
            if(fd==-1)
            {
                perror("open()");
                exit(-1);
            }
            //only one file can edit
            flock(fd,LOCK_EX);
            //for synchronization, check again
            //has been created
            struct stat st;
            //check if file exists
            if(fstat(fd, &st)==0)
            {
                int size = st.st_size;
                if(size > 0)
                {
                    printf("[%d]: File exists... Go to another control\n",status->index);
                    flock(fd,LOCK_UN);
                    close(fd);
                    goto EXISTS;
                }
            }
            else
            {
                perror("stat()");
                exit(-2);
            }
            //request server
            resolve_response(status,1, filename,request,fd);
            flock(fd,LOCK_UN);
        }
        //cached file exists. Look at other requirement.
        else
        {
            //lock file
        EXISTS:;
            printf("[%d]: File was cached.\n",status->index);
            status->has_local = 1;
            fd = open(path,O_RDWR,S_IRWXU);
            if(fd==-1)
            {
                perror("open()");
                exit(-1);
            }
            flock(fd,LOCK_EX);
            //no-cache, no modified since. forward command.
            resolve_response(status, 1, filename, request, fd);
            
            
            flock(fd,LOCK_UN);
        }
        close(fd);
    }
    //Don't cache this type. Just send request to server
    else
    {
        resolve_response(status, 0, NULL,request, -1);
    }
    
}

void * handle_a_socket(void *input)
{
	thread_args ta = *((thread_args*)(input));
	int accept_fd = ta.accept_fd;
	int index = ta.index;
    printf("New client with index %d\n",index);
    char mybuffer[MAX_HEADER];
    ta.portnumber = -1;
    memset(ta.ip, 0, 18);
    //client may reuse the socket.
    struct timeval tv;
    ta.sd = -1;
    tv.tv_sec = 25;  /* 25 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
     
    setsockopt(accept_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
     
    while(1)
    {
        //reset
        ta.is_modified = 0;
        ta.no_cache_signal =0;
        memset(mybuffer, 0, MAX_HEADER);
        //printf("[%d]: Before read header..\n",ta.index);
        //receive the message
        //set the timeout here
        
        int counter = 0;
        while(counter<5 || strcmp(&mybuffer[counter-4],"\r\n\r\n") !=0)
        {
            if(read_bytes(accept_fd, 1, &mybuffer[counter])<0)
            {   
                close(ta.sd);
                printf("[%d]: Client has no more messages to send.\n",ta.index);
                close(accept_fd);
                push(&stack,index);
                pthread_exit(NULL);
            }
            counter++;
        }
        //printf("[%d]: After read header\n",ta.index);
        
        //printf("[%d]: %s",ta.index,mybuffer);
        //parse the message
        if(parse("GET",&ta,mybuffer)==-1)
        {
            close(accept_fd);
            push(&stack,index);
            pthread_exit(NULL);
        }
        parse("If-Modified-Since",&ta,mybuffer);
        parse("Cache-Control",&ta,mybuffer);
        
        parse("Host",&ta,mybuffer);
        parse("Connection",&ta,mybuffer);
        //do certain operations
        resolve_request(&ta, mybuffer);
        printf("[%d]: Finished resolving request..\n",ta.index);
        //flush the buffer
        //int flag = 1; 
        //setsockopt(accept_fd, SOL_SOCKET, TCP_NODELAY,  &flag, sizeof(int));
        //now, get back to normal
        //flag = 0; 
        //setsockopt(accept_fd, SOL_SOCKET, TCP_NODELAY,  &flag, sizeof(int));
        
        if(ta.is_modified) 
            free(ta.is_modified_field);
        free(ta.filetype);
        free(ta.url);
        //if contain close
        if(!ta.keep_alive)
        {
            printf("[%d]: Close the connection as client want.\n",ta.index);
            break;
        }
    }
    
    //quit
    close(ta.sd);
    close(accept_fd);
    push(&stack,index);
	pthread_exit(NULL);
    
}