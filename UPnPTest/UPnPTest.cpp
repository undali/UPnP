// UPnPTest.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <stdlib.h>
#include <vector>

using namespace std;
 
#if defined(WIN32)
#define WIN32_LEAN_AND_MEAN
typedef int socklen_t;
#include "stdafx.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include<sys/stat.h>

#pragma comment (lib, "Ws2_32.lib")
#else
#define Sleep sleep
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#endif

int sock;
bool server = false;
int Port = 9320;

int GetLastNetworkError()
{
#if defined(WIN32)
	return WSAGetLastError();
#else
	return errno;
#endif
}

void closeSocket(int sck)
{
#ifdef WIN32
	closesocket(sck);
#else
	close(sck);
#endif
}

void closeSocket()
{
#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}

static const char * const deviceList[] = {
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
	"upnp:rootdevice",
	0
};


#define HTTPMU_HOST_ADDRESS "239.255.255.250"
#define HTTPMU_HOST_PORT 1900
//#define HTTPMU_HOST_ADDRESS "192.168.0.1"
//#define HTTPMU_HOST_PORT 15005


#define SEARCH_REQUEST_STRING "M-SEARCH * HTTP/1.1\r\n"            \
"ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"             \
"MX: 3\r\n"                          \
"Man:\"ssdp:discover\"\r\n"          \
"HOST: 239.255.255.250:1900\r\n"     \
"\r\n"
#define HTTP_OK "200 OK"
//#define DEFAULT_HTTP_PORT 80



#define MAX_BUFF_SIZE 102400



#define DEVICE_TYPE_1	"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
#define DEVICE_TYPE_2	"urn:schemas-upnp-org:device:WANDevice:1"
#define DEVICE_TYPE_3	"urn:schemas-upnp-org:device:WANConnectionDevice:1"

#define SERVICE_WANIP	"urn:schemas-upnp-org:service:WANIPConnection:1"
#define SERVICE_WANPPP	"urn:schemas-upnp-org:service:WANPPPConnection:1"



#define HTTP_HEADER_ACTION "POST %s HTTP/1.1\r\n"                         \
"HOST: %s:%u\r\n"                                  \
"SOAPACTION:\"%s#%s\"\r\n"                           \
"CONTENT-TYPE: text/xml ; charset=\"utf-8\"\r\n"\
"Content-Length: %d \r\n\r\n"

#define SOAP_ACTION  "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"     \
"<s:Envelope xmlns:s="                               \
"\"http://schemas.xmlsoap.org/soap/envelope/\" "     \
"s:encodingStyle="                                   \
"\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" \
"<s:Body>\r\n"                                       \
"<u:%s xmlns:u=\"%s\">\r\n%s"         \
"</u:%s>\r\n"                                        \
"</s:Body>\r\n"                                      \
"</s:Envelope>\r\n"

#define PORT_MAPPING_LEASE_TIME "63072000"                                //two year

#define ADD_PORT_MAPPING_PARAMS "<NewRemoteHost></NewRemoteHost>\r\n"      \
"<NewExternalPort>%u</NewExternalPort>\r\n"\
"<NewProtocol>%s</NewProtocol>\r\n"        \
"<NewInternalPort>%u</NewInternalPort>\r\n"\
"<NewInternalClient>%s</NewInternalClient>\r\n"  \
"<NewEnabled>1</NewEnabled>\r\n"           \
"<NewPortMappingDescription>%s</NewPortMappingDescription>\r\n"  \
"<NewLeaseDuration>"                       \
PORT_MAPPING_LEASE_TIME                    \
"</NewLeaseDuration>\r\n"

#define GET_PORT_MAPPING_PARAMS "<NewRemoteHost></NewRemoteHost>\r\n"      \
"<NewExternalPort>%u</NewExternalPort>\r\n"\
"<NewProtocol>%s</NewProtocol>\r\n"

#define GET_MAPPING_GENERIC     "<NewPortMappingIndex>%d</NewPortMappingIndex>\r\n"

#define ACTION_ADD	 "AddPortMapping"
#define ACTION_GET_EXTERNAL_ADDRESS "GetExternalIPAddress"


#define ACTION_GET_PORT_MAPPING "GetSpecificPortMappingEntry"

#define ACTION_GET_MAPPING_GENERIC "GetGenericPortMappingEntry"



#define CONTROLNODE "controlURL"

#define SERVICELISTNODE "serviceList"



string mSearchReply, serviceDescription, controlURL, serviceType, baseURL;

string last_error;

int udp_socket_fd;
int tcp_socket_fd;


bool parseUrl(const char* url, std::string& host, unsigned short* port, std::string& path)
{
	std::string str_url = url;

	std::string::size_type pos1, pos2, pos3;
	pos1 = str_url.find("://");
	if (pos1 == std::string::npos)
	{
		return false;
	}
	pos1 = pos1 + 3;

	pos2 = str_url.find(":", pos1);
	if (pos2 == std::string::npos)
	{
		*port = 80;
		pos3 = str_url.find("/", pos1);
		if (pos3 == std::string::npos)
		{
			return false;
		}

		host = str_url.substr(pos1, pos3 - pos1);
	}
	else
	{
		host = str_url.substr(pos1, pos2 - pos1);
		pos3 = str_url.find("/", pos1);
		if (pos3 == std::string::npos)
		{
			return false;
		}

		std::string str_port = str_url.substr(pos2 + 1, pos3 - pos2 - 1);
		*port = (unsigned short)atoi(str_port.c_str());
	}

	if (pos3 + 1 >= str_url.size())
	{
		path = "/";
	}
	else
	{
		path = str_url.substr(pos3, str_url.size());
	}

	return true;
}

bool TCPConnect(const char * _host, unsigned short int _port)
{
	int ret, i;
	tcp_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in r_address;

	r_address.sin_family = AF_INET;
	r_address.sin_port = htons(_port);
	r_address.sin_addr.s_addr = inet_addr(_host);

	for (i = 1; i <= 3; i++)
	{
		if (i > 1)
			Sleep(1000);

		ret = connect(tcp_socket_fd, (const struct sockaddr *)&r_address, sizeof(struct sockaddr_in));
		if (ret == 0)
		{
			return true;
		}
	}

	char temp[100];
	sprintf(temp, "Fail to connect to %s:%i (using TCP)\n", _host, _port);
	last_error = temp;
	return false;
}

string GetExternalAddress()
{
	int ret;
	std::string exAddr = "";
	std::string host, path;
	unsigned short int port;
	ret = parseUrl(controlURL.c_str(), host, &port, path);
	if (!ret)
	{
		last_error = "Fail to parseURl: " + controlURL + "\n";
		return exAddr;
	}

	//connect
	ret = TCPConnect(host.c_str(), port);
	if (!ret)
	{
		closeSocket(tcp_socket_fd);
		return exAddr;
	}

	
	char buff[MAX_BUFF_SIZE + 1];
	//sprintf(buff, ADD_PORT_MAPPING_PARAMS, _port_ex, _protocal, _port_in, _destination_ip, _description);
	std::string action_params = "";

	sprintf(buff, SOAP_ACTION, ACTION_GET_EXTERNAL_ADDRESS, serviceType.c_str(), action_params.c_str(), ACTION_GET_EXTERNAL_ADDRESS);
	std::string soap_message = buff;

	sprintf(buff, HTTP_HEADER_ACTION, path.c_str(), host.c_str(), port, serviceType.c_str(), ACTION_GET_EXTERNAL_ADDRESS, soap_message.size());
	std::string action_message = buff;

	std::string http_request = action_message + soap_message;

	//send request
	ret = send(tcp_socket_fd, http_request.c_str(), http_request.size(), 0);

	//wait for response
	std::string response;
	memset(buff, 0, sizeof(buff));
	while (ret = recv(tcp_socket_fd, buff, MAX_BUFF_SIZE, 0) > 0)
	{
		response += buff;
		memset(buff, 0, sizeof(buff));
	}

	if (response.find(HTTP_OK) == std::string::npos)
	{
		char temp[100];
		sprintf(temp, "Fail to get external address.\n");
		last_error = temp;

		return exAddr;
	}

	std::string::size_type index1 = response.find("<NewExternalIPAddress>");

	if (index1 == std::string::npos){
		printf("Failed to parse External IP Address \n%s\n", response.c_str());
		return exAddr;
	}
	index1 += 22;

	if (index1 >= response.length()) return exAddr;

	std::string::size_type index2 = response.find("</NewExternalIPAddress>", index1);
	if (index2 == std::string::npos) return exAddr;

	exAddr = response.substr(index1, index2 - index1);

	cout << ">>>> ";
	printf("%s\n", exAddr.c_str());
	closeSocket(tcp_socket_fd);
	return exAddr;
}

bool AddPortMapping(char * _description, char * _destination_ip, unsigned short int _port_ex, unsigned short int _port_in, char * _protocal)
{
	int ret;

	std::string host, path;
	unsigned short int port;
	ret = parseUrl(controlURL.c_str(), host, &port, path);
	if (!ret)
	{
		last_error = "Fail to parseURl: " + controlURL + "\n";
		return false;
	}

	//connect
	ret = TCPConnect(host.c_str(), port);
	if (!ret)
	{
		closeSocket(tcp_socket_fd);
		return false;
	}

	char buff[MAX_BUFF_SIZE + 1];
	sprintf(buff, ADD_PORT_MAPPING_PARAMS, _port_ex, _protocal, _port_in, _destination_ip, _description);
	std::string action_params = buff;

	sprintf(buff, SOAP_ACTION, ACTION_ADD, serviceType.c_str(), action_params.c_str(), ACTION_ADD);
	std::string soap_message = buff;

	sprintf(buff, HTTP_HEADER_ACTION, path.c_str(), host.c_str(), port, serviceType.c_str(), ACTION_ADD, soap_message.size());
	std::string action_message = buff;

	std::string http_request = action_message + soap_message;

	//send request
	ret = send(tcp_socket_fd, http_request.c_str(), http_request.size(), 0);

	//wait for response
	std::string response;
	memset(buff, 0, sizeof(buff));
	while (ret = recv(tcp_socket_fd, buff, MAX_BUFF_SIZE, 0) > 0)
	{
		response += buff;
		memset(buff, 0, sizeof(buff));
	}

	if (response.find(HTTP_OK) == std::string::npos)
	{
		char temp[100];
		sprintf(temp, "Fail to add port mapping (%s/%s)\n", _description, _protocal);
		last_error = temp;

		return false;
	}

	closeSocket(tcp_socket_fd);
	return true;
}

bool ParseDescription()
{
	size_t begin = serviceDescription.find(SERVICE_WANIP);
	if (begin == string::npos) return false;

	//TODO: set base URL
	if (false)
	{

	}
	else
	{
		std::string::size_type index = mSearchReply.find("/", 7);
		if (index == std::string::npos)
		{
			last_error = "Fail to get base_URL from XMLNode \"URLBase\" or describe_url.\n";
			return false;
		}
		baseURL = baseURL.assign(mSearchReply, 0, index);
	}

	if (baseURL.size() < 2) return false;

	int serviceTypeStart, serviceTypeSize = 0;

	for (size_t i = begin; i != 0; i--)
	{
		if (serviceDescription.at(i) == '>')
		{
			serviceTypeStart = i + 1;
			break;
		}
	}

	for (size_t i = serviceTypeStart; i < serviceDescription.size(); i++)
	{
		if (serviceDescription.at(i) != '<') serviceTypeSize++;
		else break;
	}

	if (serviceTypeSize == 0) return false;

	serviceType = serviceDescription.substr(serviceTypeStart, serviceTypeSize);



	size_t controlStart = serviceDescription.find(CONTROLNODE, begin);
	if (controlStart == string::npos) return false;

	controlStart += 11;

	int controlURLSize = 0;
	for (size_t i = controlStart; i < serviceDescription.size(); i++)
	{
		if (serviceDescription.at(i) != '<') controlURLSize++;
		else break;
	}

	if (controlURLSize == 0) return false;

	controlURL = serviceDescription.substr(controlStart, controlURLSize);

	controlURL = baseURL + controlURL;

	return true;
}

bool GetDescription()
{
	std::string host, path;
	unsigned short int port;
	int ret = parseUrl(mSearchReply.c_str(), host, &port, path);
	if (!ret)
	{
		last_error = "Failed to parseURl: " + mSearchReply + "\n";
		return false;
	}

	ret = TCPConnect(host.c_str(), port);
	if (!ret)
		return false;

	char request[200];
	sprintf(request, "GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path.c_str(), host.c_str(), port);
	std::string http_request = request;

	//send request
	ret = send(tcp_socket_fd, http_request.c_str(), http_request.size(), 0);
	//get description xml file
	char buff[MAX_BUFF_SIZE + 1];
	memset(buff, 0, sizeof(buff));
	std::string response;
	while (ret = recv(tcp_socket_fd, buff, MAX_BUFF_SIZE, 0) > 0)
	{
		response += buff;
		memset(buff, 0, sizeof(buff));
	}

	serviceDescription = response;

	return true;
}

bool DiscoverUPNP()
{
	udp_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	cout << "Socet returns " << udp_socket_fd << endl;
	int i , ret;
	std::string send_buff = SEARCH_REQUEST_STRING;
	std::string recv_buff;
	char buff[MAX_BUFF_SIZE + 1]; //buff should be enough big

	struct sockaddr_in r_address, my_address;
	r_address.sin_family = AF_INET;
	r_address.sin_port = htons(HTTPMU_HOST_PORT);
	r_address.sin_addr.s_addr = inet_addr(HTTPMU_HOST_ADDRESS);

	struct sockaddr_in addr, foo;
	int len = sizeof(struct sockaddr);
/*
	my_address.sin_family = AF_INET;
	my_address.sin_port = htons(8075);
	my_address.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(udp_socket_fd, (struct sockaddr*)&my_address, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		cout << "Bind returns " << ret;
		cout << "Error Code " << GetLastNetworkError() << endl;
	}*/

	bool bOptVal = true;
	int bOptLen = sizeof(bool);
	int iOptLen = sizeof(int);


	ret = setsockopt(udp_socket_fd, SOL_SOCKET, SO_BROADCAST, (char*)&bOptVal, bOptLen);
	printf("Setting Socket option broadcast returns %d\n", ret);
/*

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 10000;
	if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0) {
		perror("Error");
	}*/

#ifndef _WIN32

	int flags = fcntl(udp_socket_fd, F_GETFL, 0);
	fcntl(udp_socket_fd, F_SETFL, flags | O_NONBLOCK);
#endif

	u_long val = 1;

#ifdef _WIN32
	ioctlsocket(udp_socket_fd, FIONBIO, &val);//none block
#endif

	for (i = 1; i <= 3; i++)
	{
		Sleep(30);
		ret = ::sendto(udp_socket_fd, send_buff.c_str(), send_buff.size(), 0, (struct sockaddr*)&r_address, sizeof(struct sockaddr_in));
		cout << "Send to returns " << ret << endl;

		getsockname(udp_socket_fd, (struct sockaddr *) &foo, &len);
		fprintf(stderr, "listening on %s:%d\n", inet_ntoa(foo.sin_addr),
			ntohs(foo.sin_port));

		memset(buff, 0, sizeof(buff));
		Sleep(30);
		ret = recvfrom(udp_socket_fd, buff, MAX_BUFF_SIZE, 0, NULL, NULL);
		if (ret == SOCKET_ERROR){
			printf("continuing.. Last network error %d\n", GetLastNetworkError());
			Sleep(1);
			continue;
		}
		else if (ret < 1){
			printf("NOTHING RECEIVED!@ @ ! @# # # #$&$*$ $ $($ $ ($ #)#)# \n");
			Sleep(30);
			continue;
		}

		printf("something received..\n");

		recv_buff = buff;
		ret = recv_buff.find(HTTP_OK);
		if (ret == std::string::npos)
			continue;                       //invalid response

		std::string::size_type begin = recv_buff.find("http://");
		if (begin == std::string::npos)
			continue;                       //invalid response
		std::string::size_type end = recv_buff.find("\r", begin);
		if (end == std::string::npos)
			continue;    //invalid response

		mSearchReply = mSearchReply.assign(recv_buff, begin, end - begin);

		if (mSearchReply.length() < 1){
			Sleep(30);
			continue;
		}

		printf("Ha Ha UPnP success %s\n", mSearchReply.c_str());

		if (!GetDescription()){
			Sleep(30);
			continue;
		}

		if (!ParseDescription()){
			Sleep(30);
			continue;
		}

/*
		getsockname(udp_socket_fd, (struct sockaddr *) &foo, &len);
		fprintf(stderr, "listening on %s:%d\n", inet_ntoa(foo.sin_addr),
			ntohs(foo.sin_port));*/

		closeSocket(udp_socket_fd);



		return true;
	}

/*
	getsockname(udp_socket_fd, (struct sockaddr *) &foo, &len);
	fprintf(stderr, "listening on %s:%d\n", inet_ntoa(foo.sin_addr),
		ntohs(foo.sin_port));*/

	closeSocket(udp_socket_fd);
	return false;
}

void SetDummy1()
{
mSearchReply = "http://192.168.0.1:1900/igd.xml";

serviceDescription = "HTTP/1.1 200 OK                                                                                       \
CONTENT-LENGTH: 4567                                                                                                        \
CONTENT-TYPE: text/xml                                                                                                      \
DATE: Tue, 15 Dec 2015 13:57:36 GMT                                                                                         \
LAST-MODIFIED: Tue, 28 Oct 2003 08:46:08 GMT                                                                                \
SERVER: ipos/7.0 UPnP/1.0 TL-MR3420/2.0                                                                                     \
CONNECTION: close                                                                                                           \
                                                                                                                            \
<?xml version=\"1.0\"?>                                                                                                       \
<root xmlns=\"urn:schemas-upnp-org:device-1-0\">                                                                              \
	<specVersion>                                                                                                           \
		<major>1</major>                                                                                                    \
		<minor>0</minor>                                                                                                    \
	</specVersion>                                                                                                          \
	<device>                                                                                                                \
		<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>                                        \
		<presentationURL>http://192.168.0.1:80/      </presentationURL>                                                     \
		<friendlyName>Wireless N 3G/4G Router MR3420</friendlyName>                                                         \
  		<manufacturer>TP-LINK</manufacturer>                                                                                \
                         		<manufacturerURL>http://www.tp-link.com</manufacturerURL>                                   \
          		<modelDescription>Wireless N 3G/4G Router MR3420</modelDescription>                                         \
  		<modelName>TL-MR3420</modelName>                                                                                    \
                       		<modelNumber>2.0</modelNumber>                                                                  \
                             		<modelURL>http://192.168.0.1:80</modelURL>                                              \
        	<serialNumber>none</serialNumber>                                                                               \
		<UDN>uuid:060b7353-fca6-4070-85f4-1fbfb9add62c</UDN>                                                                \
		<UPC>00000-00001</UPC>                                                                                              \
		<serviceList>                                                                                                       \
			<service>                                                                                                       \
				<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>                                  \
				<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>                                                 \
				<controlURL>/l3f</controlURL>                                                                               \
				<eventSubURL>/l3f</eventSubURL>                                                                             \
				<SCPDURL>/l3f.xml</SCPDURL>                                                                                 \
			</service>                                                                                                      \
		</serviceList>                                                                                                      \
		<deviceList>                                                                                                        \
		<device>                                                                                                            \
			<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>                                                \
			<friendlyName>Wireless N 3G/4G Router MR3420</friendlyName>                                                     \
  			<manufacturer>TP-LINK</manufacturer>                                                                            \
                         			<manufacturerURL>http://www.tp-link.com</manufacturerURL>                               \
          			<modelDescription>Wireless N 3G/4G Router MR3420</modelDescription>                                     \
  			<modelName>TL-MR3420</modelName>                                                                                \
                       			<modelNumber>2.0</modelNumber>                                                              \
                             			<modelURL>http://192.168.0.1:80</modelURL>                                          \
        		<serialNumber>none</serialNumber>                                                                           \
			<UDN>uuid:254e9977-8964-49f3-b8d5-51acb7bd40fc</UDN>                                                            \
			<UPC>00000-00001</UPC>                                                                                          \
			<serviceList>                                                                                                   \
				<service>                                                                                                   \
					<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>                      \
					<serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>                                             \
					<controlURL>/ifc</controlURL>                                                                           \
					<eventSubURL>/ifc</eventSubURL>                                                                         \
					<SCPDURL>/ifc.xml</SCPDURL>                                                                             \
				</service>                                                                                                  \
			</serviceList>                                                                                                  \
			<deviceList>                                                                                                    \
				<device>                                                                                                    \
					<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>                              \
					<friendlyName>Wireless N 3G/4G Router MR3420</friendlyName>                                             \
  					<manufacturer>TP-LINK</manufacturer>                                                                    \
                         					<manufacturerURL>http://www.tp-link.com</manufacturerURL>                       \
          					<modelDescription>Wireless N 3G/4G Router MR3420</modelDescription>                             \
  					<modelName>TL-MR3420</modelName>                                                                        \
                       					<modelNumber>2.0</modelNumber>                                                      \
                             					<modelURL>http://192.168.0.1:80</modelURL>                                  \
        				<serialNumber>none</serialNumber>                                                                   \
					<UDN>uuid:9f0865b3-f5da-4ad5-85b7-7404637fdf37</UDN>                                                    \
					<UPC>00000-00001</UPC>                                                                                  \
					<serviceList>                                                                                           \
						<service>                                                                                           \
						<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>                           \
						<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>                                            \
						<controlURL>/ipc</controlURL>                                                                       \
						<eventSubURL>/ipc</eventSubURL>                                                                     \
						<SCPDURL>/ipc.xml</SCPDURL>                                                                         \
						</service>                                                                                          \
					</serviceList>                                                                                          \
				</device>                                                                                                   \
			</deviceList>                                                                                                   \
		</device>                                                                                                           \
<!-- WFAWC goes here                                                                                                        \
		<device>                                                                                                            \
			<deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>                                        \
			<presentationURL>http://255.255.255.255:65535</presentationURL>                                                 \
			<friendlyName>Wireless N 3G/4G Router MR3420</friendlyName>                                                     \
  			<manufacturer>TP-LINK</manufacturer>                                                                            \
                         			<manufacturerURL>http://www.tp-link.com</manufacturerURL>                               \
          			<modelDescription>Wireless N 3G/4G Router MR3420</modelDescription>                                     \
  			<modelName>TL-MR3420</modelName>                                                                                \
                       			<modelNumber>2.0</modelNumber>                                                              \
                             			<modelURL>http://192.168.0.1:80</modelURL>                                          \
        		<serialNumber>none</serialNumber>                                                                           \
			<UDN>uuid:565aa949-67c1-4c0e-aa8f-f349e6f59311</UDN>                                                            \
			<UPC>00000-00001</UPC>                                                                                          \
			<serviceList>                                                                                                   \
				<service>                                                                                                   \
					<serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>                         \
					<serviceId>urn:wifialliance-org:serviceId:WFAWLANConfig1</serviceId>                                    \
					<controlURL>http://255.255.255.255:65535/WFAWLANConfig/control</controlURL>                             \
					<eventSubURL>http://255.255.255.255:65535/WFAWLANConfig/event</eventSubURL>                             \
					<SCPDURL>http://255.255.255.255:65535/wfc.xml</SCPDURL>                                                 \
				</service>                                                                                                  \
			</serviceList>                                                                                                  \
		</device>                                                                                                           \
   - WFAWC ends here -->                                                                                                    \
	</deviceList>                                                                                                           \
</device>                                                                                                                   \
</root>";

serviceType = "urn:schemas-upnp-org:service:WANIPConnection:1";

}

int main(int argc, char* argv[])
{

#ifdef _WIN32
	WSAData data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
		fprintf(stderr, "WSAStartup failed.\n");
		exit(1);
	}
#endif
	bool iRet;
	//for (int k = 0; k < 100; k++)
	{
		iRet = DiscoverUPNP();
		//cout << ">> " << k << " DiscoverUPNP returns " << iRet << endl;
		if (iRet == false)
		{
#ifdef _WIN32
			WSACleanup();
#endif
			return -2;
		}
	}
	//
	//return -1;

	//SetDummy1();
	
	iRet = GetDescription();

	iRet = ParseDescription();

	string hi = GetExternalAddress();


	iRet = AddPortMapping("I'm from Linux", "192.168.0.100", 1800, 1800, "UDP");

	printf("Control URL %s external address\n", controlURL.c_str());

	return 0;
}

