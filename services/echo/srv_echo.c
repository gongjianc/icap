/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include "common.h"
#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"

#define MAX_URL_SIZE  8192
#define MAX_METHOD_SIZE  16
#define SMALL_BUFF 1024

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL_SIZE];
};

int echo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf);
int echo_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t *);
int echo_end_of_data_handler(ci_request_t * req);
void *echo_init_request_data(ci_request_t * req);
void echo_close_service();
void echo_release_request_data(void *data);
int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,ci_request_t * req);
//void generate_redirect_page(char * redirect, ci_request_t * req, struct echo_req_data * data);
int extract_http_info(ci_request_t *, ci_headers_list_t *, struct http_info *);
char *http_content_type(ci_request_t *);



CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "echo",                         /* mod_name, The module name */
     "Echo demo service",            /* mod_short_descr,  Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,     /* mod_type, The service type is responce or request modification */
     echo_init_service,              /* mod_init_service. Service initialization */
     NULL,                           /* post_init_service. Service initialization after c-icap 
					configured. Not used here */
     echo_close_service,           /* mod_close_service. Called when service shutdowns. */
     echo_init_request_data,         /* mod_init_request_data */
     echo_release_request_data,      /* mod_release_request_data */
     echo_check_preview_handler,     /* mod_check_preview_handler */
     echo_end_of_data_handler,       /* mod_end_of_data_handler */
     echo_io,                        /* mod_service_io */
     NULL,
     NULL
};

/*
  The echo_req_data structure will store the data required to serve an ICAP request.
*/
struct echo_req_data {
    /*the body data*/
    //ci_ring_buf_t *body;
    /*flag for marking the eof*/
    int eof;
    ci_membuf_t *error_page;
    ci_simple_file_t *body;
    ci_request_t *req;
    int blocked;
};


/* This function will be called when the service loaded  */
int echo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf)
{
     ci_debug_printf(5, "Initialization of echo module......\n");
     
     /*Tell to the icap clients that we can support up to 1024 size of preview data*/
     ci_service_set_preview(srv_xdata, 1024);

     /*Tell to the icap clients that we support 204 responses*/
     ci_service_enable_204(srv_xdata);

     /*Tell to the icap clients to send preview data for all files*/
     ci_service_set_transfer_preview(srv_xdata, "*");

     /*Tell to the icap clients that we want the X-Authenticated-User and X-Authenticated-Groups headers
       which contains the username and the groups in which belongs.  */
     ci_service_set_xopts(srv_xdata,  CI_XAUTHENTICATEDUSER|CI_XAUTHENTICATEDGROUPS);
     
     return CI_OK;
}

/* This function will be called when the service shutdown */
void echo_close_service() 
{
    ci_debug_printf(5,"Service shutdown!\n");
    /*Nothing to do*/
}

/*This function will be executed when a new request for echo service arrives. This function will
  initialize the required structures and data to serve the request.
 */
void *echo_init_request_data(ci_request_t * req)
{

    struct echo_req_data *echo_data;

    /*Allocate memory fot the echo_data*/
    echo_data = malloc(sizeof(struct echo_req_data));
    if (!echo_data) {
        ci_debug_printf(1, "Memory allocation failed inside echo_init_request_data!\n");
        return NULL;
    }

    /*If the ICAP request encuspulates a HTTP objects which contains body data 
      and not only headers allocate a ci_cached_file_t object to store the body data.
     */
     //if (ci_req_hasbody(req))
     //     echo_data->body = ci_ring_buf_new(4096);
     //else
	 echo_data->body = NULL;
     echo_data->error_page = NULL;
     echo_data->req = req;
     echo_data->blocked = 0;
     return echo_data;
}

/*This function will be executed after the request served to release allocated data*/
void echo_release_request_data(void *data)
{
	 ci_debug_printf(10, "@@@@@4_______________echo_release_request_data START... \r\n");
    /*The data points to the echo_req_data struct we allocated in function echo_init_service */
    struct echo_req_data *echo_data = (struct echo_req_data *)data;
    
    /*if we had body data, release the related allocated data*/
    //if(echo_data->body)
	//ci_ring_buf_destroy(echo_data->body);

    if (echo_data->body) {
        ci_simple_file_destroy(echo_data->body);
    }
    if (echo_data->error_page){
        ci_membuf_free(echo_data->error_page);
    }
    free(echo_data);
}

int ishttpsource(char *url)
{
	char *p = url;
	int i=0;
	int length = strlen(url);
	while(i < MAX_URL_SIZE){
		if(i>=length)
		{
			return 1;
		}
		if(strncasecmp(p,".gif",4)==0 || strncasecmp(p,".gif?",5)==0 || strncasecmp(p,".css",4)==0 || strncasecmp(p,".css?",5)==0 || strncasecmp(p,".js?",4)==0 || strncasecmp(p,".js",3)==0 || strncasecmp(p,".jpg",4)==0 || strncasecmp(p,".jpg?",5)==0 || strncasecmp(p,".bmp",4)==0 || strncasecmp(p,".bmp?",5)==0 || strncasecmp(p,".png",4)==0 || strncasecmp(p,".png?",5)==0 || strncasecmp(p,".swf",4)==0 || strncasecmp(p,".swf?",5)==0 || strncasecmp(p,".cab",4)==0 || strncasecmp(p,".cab?",5)==0)
		{
			return 0;
		}
		i++;
		p++;
	}
	return i;
}

static int whattodo = 0;
int echo_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t * req)
{
	 ci_debug_printf(10, "@@@@@1_______________echo_check_preview_handler START... \r\n");
     //ci_off_t content_len;
     ci_headers_list_t *req_header;
     char *clientip;
     struct http_info httpinf;
     /*Get the echo_req_data we allocated using the  echo_init_service  function*/
     struct echo_req_data *echo_data = ci_service_data(req);

     /* Extract the HTTP header from the request */
	 if ((req_header = ci_http_request_headers(req)) == NULL) {
		ci_debug_printf(0, "ERROR echo_check_preview_handler: bad http header, aborting.\n");
		return CI_ERROR;
	 }

	 if ((clientip = ci_headers_value(req->request_header, "X-Client-IP")) != NULL) {
	 	ci_debug_printf(2, "DEBUG echo_check_preview_handler: X-Client-IP: %s\n", clientip);
	 }

	 if (!extract_http_info(req, req_header, &httpinf)) {
		/* Something wrong in the header or unknow method */
		ci_debug_printf(1, "DEBUG echo_check_preview_handler: bad http header, aborting.\n");
		return CI_MOD_ALLOW204;
	}
	 ci_debug_printf(2, "DEBUG echo_check_preview_handler: httpinf.url: %s\n", httpinf.url);

	 //if (strncasecmp(httpinf.method,"GET",3) == 0  && ishttpsource(httpinf.url)!=0){

	 if (strncasecmp(httpinf.method,"GET",3) == 0  && strncasecmp(httpinf.url,"http://www.baidu.com",20) == 0 ){
		 if(whattodo == 1){
			 return CI_MOD_ALLOW204;
		 }
		 ci_debug_printf(2,"_____________www.baidu.com________________________\r\n");
		 whattodo = 1;
		 echo_data->blocked = 1;
		 //generate_redirect_page("http://www.g.cn", req, echo_data);
		 generate_redirect_page("http://www.g.cn", req, echo_data);

		 echo_data->body = ci_simple_file_new(0);
		 ci_req_unlock_data(req);
		 ci_simple_file_lock_all(echo_data->body);

		 ci_debug_printf(2,"_____________preview_data_len=%d__________\r\n",preview_data_len);
		 if (!echo_data->body){
			 ci_debug_printf(2, "________cho_data->body is null");
		 	 return CI_ERROR;
		 }

		 if (preview_data_len) {
			 ci_debug_printf(2,"_____________________________________");
			int i=0;
			/*
			for(i=0; i<preview_data_len;i++){
				if((preview_data[i] >= 0x30 && preview_data[i] < 0x40)
				   ){
					ci_debug_printf(2,"%c",preview_data[i]);
				}
				}

			}
			*/
		 	if (ci_simple_file_write(echo_data->body, preview_data, preview_data_len, ci_req_hasalldata(req)) == CI_ERROR){
		 		ci_debug_printf(2, "________ci_simple_file_write CI_ERROR");
		 		return CI_ERROR;
		 	}
		 }
		 ci_debug_printf(2,"_______CI_MOD_CONTINUE________________");
		 return CI_MOD_CONTINUE;
	 }

	 return CI_MOD_ALLOW204;

}

/* This function will called if we returned CI_MOD_CONTINUE in  echo_check_preview_handler
 function, after we read all the data from the ICAP client*/
int echo_end_of_data_handler(ci_request_t * req)
{
	ci_debug_printf(10, "@@@@@3_______________echo_end_of_data_handler START... \r\n");
    struct echo_req_data *echo_data = ci_service_data(req);
    /*mark the eof*/
    echo_data->eof = 1;
    /*and return CI_MOD_DONE */
    //if (!ci_req_sent_data(req)) {
    	//return CI_MOD_ALLOW204;
    //}
    //if (echo_data->blocked == 1){
    	return CI_MOD_DONE;
    //}
/*
    char *temp = NULL;
	 temp = (char *)malloc(*rlen);
	 memcpy(temp,rbuf,*rlen);
	 FILE *fp;
	 if ((fp=fopen("/test.txt","a"))==NULL) //打开只写的文本文件
	 {
		 printf("cannot open file!");
		 exit(0);
	 }
	 //int i=0;
	 //for(i=0;i<*rlen; i++){
		// fputc(*(rbuf+i),fp); //写入串
	 //}
	 fputs(temp,fp); //写入串
	 fclose(fp); //关文件
	 free(temp);
*/
    //return CI_MOD_ALLOW204;

}

int echo_read_from_net(char *buf, int len, int iseof, ci_request_t * req)
{
	struct echo_req_data *data = ci_service_data(req);
    //int allow_transfer;

     if (!data){
          return CI_ERROR;
     }

     if (!data->body){
    	 return len;
     }

    //if (data->no_more_scan == 1) {
    	//return ci_simple_file_write(data->body, buf, len, iseof);
    //}
/*
    if ((maxsize > 0) && (data->body->bytes_in >= maxsize)) {
	data->no_more_scan = 1;
	ci_req_unlock_data(req);
	ci_simple_file_unlock_all(data->body);
	ci_debug_printf(1, "DEBUG squidclamav_read_from_net: No more antivir check, downloaded stream is upper than maxsize (%d>%d)\n", (int)data->body->bytes_in, (int)maxsize);
    } else if (SEND_PERCENT_BYTES && (START_SEND_AFTER < data->body->bytes_in)) {
	ci_req_unlock_data(req);
	allow_transfer = (SEND_PERCENT_BYTES * (data->body->endpos + len)) / 100;
	ci_simple_file_unlock(data->body, allow_transfer);
    }
*/
     ci_req_unlock_data(req);
     ci_simple_file_lock_all(data->body);
     return ci_simple_file_write(data->body, buf, len, iseof);
}

int echo_write_to_net(char *buf, int len, ci_request_t * req)
{
     int bytes;
     struct echo_req_data *data = ci_service_data(req);

     if (!data)
          return CI_ERROR;

     /* if a virus was found or the page has been blocked, a warning page
	has already been generated */
     if (data->error_page && data->eof == 1){

        return ci_membuf_read(data->error_page, buf, len);
     }

     if (data->body){
    	 bytes = ci_simple_file_read(data->body, buf, len);
     }
     else{
    	 bytes =0;
     }

     return bytes;
}

/* This function will called if we returned CI_MOD_CONTINUE in  echo_check_preview_handler
   function, when new data arrived from the ICAP client and when the ICAP client is 
   ready to get data.
*/
int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req)
{
	 ci_debug_printf(10, "@@@@@2_______________echo_io START... \r\n");
	 ci_debug_printf(10, ">>>>>>>>>>>>>>>>>>>>>.. \r\n");
	 if(rlen){
		 ci_debug_printf(10, "1>>>>>>>>>>>>>>>>>>>>> rlen =%d .. \r\n",*rlen);
	 }else{
		 ci_debug_printf(10, "1>>>>>>>>>>>>>>>>>>>>> rlen is null .. \r\n");
	 }

	  int ret = CI_OK;
	  if (rbuf && rlen) {
			*rlen = echo_read_from_net(rbuf, *rlen, iseof, req);
			ci_debug_printf(10, "2>>>>>>>>>>>>>>>>>>>>> rlen =%d .. \r\n",*rlen);
			if (*rlen == CI_ERROR)
			   return CI_ERROR;
			else if (*rlen < 0)
			   ret = CI_OK;
	  } else if (iseof) {
		  ci_debug_printf(10, "3>>>>>>>>>>>>>>>>>>>>> iseof =%d .. \r\n",iseof);
	   if (echo_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
		  return CI_ERROR;
	  }
	  ci_debug_printf(10, "4>>>>>>>>>>>>>>>>>>>>> wlen =%d .. \r\n",*wlen);
	  if (wbuf && wlen) {
		   *wlen = echo_write_to_net(wbuf, *wlen, req);
		   ci_debug_printf(10, "5>>>>>>>>>>>>>>>>>>>>> wlen =%d .. \r\n",*wlen);
	  }
	  return CI_OK;
}

static const char *blocked_header_message =
     "<html>\n"
     "<body>\n"
     "<p>\n"
     "You will be redirected in few seconds, if not use this <a href=\"";

static const char *blocked_footer_message =
     "\">direct link</a>.\n"
     "</p>\n"
     "</body>\n"
     "</html>\n";

void generate_redirect_page(char * redirect, ci_request_t * req, struct echo_req_data * data)
{
     int new_size = 0;
     char buf[MAX_URL_SIZE];
     ci_membuf_t *error_page;

     new_size = strlen(blocked_header_message) + strlen(redirect) + strlen(blocked_footer_message) + 10;

     if ( ci_http_response_headers(req)){
    	  printf("======ci_http_response_headers(req) != NULL =========\n");
          ci_http_response_reset_headers(req);
     }
     else{
    	 printf("======ci_http_response_headers(req) == NULL =========\n");
         ci_http_response_create(req, 1, 1);
     }

     ci_debug_printf(2, "DEBUG generate_redirect_page: creating redirection page\n");

     snprintf(buf, MAX_URL_SIZE, "Location: %s", redirect);
     /*strcat(buf, ";");*/

     ci_debug_printf(3, "DEBUG generate_redirect_page: %s\n", buf);

     ci_http_response_add_header(req, "HTTP/1.0 301 Moved Permanently");
     ci_http_response_add_header(req, buf);
     ci_http_response_add_header(req, "Server: C-ICAP");
     ci_http_response_add_header(req, "Connection: close");
     /*ci_http_response_add_header(req, "Content-Type: text/html;");*/
     ci_http_response_add_header(req, "Content-Type: text/html");
     ci_http_response_add_header(req, "Content-Language: en");
     //ci_http_response_add_header(req, "Host: www.g.cn");


     if (data->blocked == 1) {
		error_page = ci_membuf_new_sized(new_size);
		((struct echo_req_data *) data)->error_page = error_page;
		ci_membuf_write(error_page, (char *) blocked_header_message, strlen(blocked_header_message), 0);
		ci_membuf_write(error_page, (char *) redirect, strlen(redirect), 0);
		ci_membuf_write(error_page, (char *) blocked_footer_message, strlen(blocked_footer_message), 1);
     }

     ci_debug_printf(3, "DEBUG generate_redirect_page: done\n");

}



int extract_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                  struct http_info *httpinf)
{
     char *str;
     int i = 0;

/* Format of the HTTP header we want to parse:
	 GET http://www.squid-cache.org/Doc/config/icap_service HTTP/1.1
*/
     httpinf->url[0]='\0';
     httpinf->method[0] = '\0';

     str = req_header->headers[0];

     /* if we can't find a space character, there's somethings wrong */
     if (strchr(str, ' ') == NULL) {
          return 0;
     }

     /* extract the HTTP method */
     while (*str != ' ' && i < MAX_METHOD_SIZE) {
	httpinf->method[i] = *str;
        str++;
	i++;
     }
     httpinf->method[i] = '\0';
     ci_debug_printf(3, "DEBUG extract_http_info: method %s\n", httpinf->method);

     /* Extract the URL part of the header */
     while (*str == ' ') str++;
     i = 0;
     while (*str != ' ' && i < MAX_URL_SIZE) {
	httpinf->url[i] = *str;
	i++;
	str++;
     }
     httpinf->url[i] = '\0';
     ci_debug_printf(3, "DEBUG extract_http_info: url %s\n", httpinf->url);
     if (*str != ' ') {
          return 0;
     }
     /* we must find the HTTP version after all */
     while (*str == ' ')
          str++;
     if (*str != 'H' || *(str + 4) != '/') {
          return 0;
     }

     return 1;
}

char *http_content_type(ci_request_t * req)
{
     ci_headers_list_t *heads;
     char *val;
     if (!(heads =  ci_http_response_headers(req))) {
          /* Then maybe is a reqmod request, try to get request headers */
          if (!(heads = ci_http_request_headers(req)))
               return NULL;
     }
     if (!(val = ci_headers_value(heads, "Content-Type")))
          return NULL;

     return val;
}
