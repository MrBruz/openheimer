#include <sys/types.h>

#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <condition_variable>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <vector>

std::vector<std::thread> ThreadVector;

#define HANDSHAKE_SIZE 1024
#define STRING_BUF_SIZE 16
#define PROTOCOL_VERSION 210
#define TIMEOUT_SEC 1 // 1000ms

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
typedef SSIZE_T ssize_t;
#endif

using namespace std;

std::condition_variable cv;
std::mutex cv_m;

int threads = 100;
std::ifstream myfile("masscan.txt");

int connect_w_to(struct addrinfo *addr, time_t sec)
{
  int res;
  long arg;
  fd_set myset;
  struct timeval tv;
  int valopt;
  socklen_t lon;
  int soc;

  // Create socket
  soc = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (soc < 0)
  {
    fprintf(stderr, "Error creating socket (%d %s)\n", errno, strerror(errno));
    return -1;
  }

  // Set non-blocking
  if ((arg = fcntl(soc, F_GETFL, NULL)) < 0)
  {
    fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
    return -1;
  }
  arg |= O_NONBLOCK;
  if (fcntl(soc, F_SETFL, arg) < 0)
  {
    fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
    return -1;
  }
  // Trying to connect with timeout
  res = connect(soc, addr->ai_addr, addr->ai_addrlen);
  if (res < 0)
  {
    if (errno == EINPROGRESS)
    {
      do
      {
        tv.tv_sec = sec;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(soc, &myset);
        res = select(soc + 1, NULL, &myset, NULL, &tv);
        if (res < 0 && errno != EINTR)
        {
          fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
          return -1;
        }
        else if (res > 0)
        {
          // Socket selected for write
          lon = sizeof(int);
          if (getsockopt(soc, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
          {
            fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
            close(soc);
            return -1;
          }
          // Check the value returned...
          if (valopt)
          {
            return -1;
          }
          break;
        }
        else
        {
          return -1;
        }
      } while (1);
    }
    else
    {
      fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
      return -1;
    }
  }
  // Set to blocking mode again...
  if ((arg = fcntl(soc, F_GETFL, NULL)) < 0)
  {
    fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
    return -1;
  }
  arg &= (~O_NONBLOCK);
  if (fcntl(soc, F_SETFL, arg) < 0)
  {
    fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
    return -1;
  }

  return soc;
}

int set_timeout(int sfd, time_t sec)
{
  struct timeval timeout;
  timeout.tv_sec = sec;
  timeout.tv_usec = 0;

  // Receive
  if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
  {
    fprintf(stderr, "setsockopt failed\n");
    return -1;
  }

  // Send
  if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
  {
    fprintf(stderr, "setsockopt failed\n");
    return -1;
  }

  return 0;
}

size_t build_handshake(unsigned char *buffer, char *host, unsigned short port)
{
  size_t host_len = strlen(host);
  size_t len = 1 /* packet id */ + 2 /* Protocol version */;
  len += 1 /* str len */ + host_len;
  len += 2; // port
  len += 1; // state

  size_t i = 0;
  buffer[i++] = len;
  buffer[i++] = 0; /* packet id */
  buffer[i++] = PROTOCOL_VERSION;
  buffer[i++] = 1; /* encoded protocol version - varint */
  buffer[i++] = host_len;
  memcpy(buffer + i, host, host_len);
  i += host_len;
  buffer[i++] = (port >> 8) & 0xFF; /* port little-endian */
  buffer[i++] = port & 0xFF;
  buffer[i] = 1; // next state

  return len + 1; /* add length byte */
}

ssize_t read_byte(const int sfd, void *buf)
{
  ssize_t nread;
  nread = recv(sfd, buf, 1, 0);
  if (nread == -1)
  {
    //perror("Read byte");
    return (1);
  }
  return nread;
}

int read_varint(const int sfd)
{
  int numread = 0;
  int result = 0;
  int value;
  char byte;
  do
  {
    if (read_byte(sfd, &byte) == 0)
    {
      //fprintf(stderr, "Failed read varint: eof\n");

      return (-1);
    }
    value = byte & 0x7F;
    result |= value << (7 * numread);

    numread++;

    if (numread > 5)
    {
      //fprintf(stderr, "Error reading varint: varint too big\n");

      return (-1);
    }
  } while ((byte & 0x80) != 0);

  return result;
}

void ping_server(char *hostname, unsigned short port)
{
  //cout << "C" << endl;
  int sfd, s, json_len;
  char string[STRING_BUF_SIZE];
  char port_str[6];
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char byte;
  unsigned char handshake[HANDSHAKE_SIZE];
  char request[] = {0x1, 0x0};
  size_t len;
  ssize_t nread;

  if (strlen(hostname) > 250)
  {
    fprintf(stderr, "Hostname too long\n");
    return;
  }

  if (port == 0)
  {
    fprintf(stderr, "Invalid port\n");
    return;
  }

#ifdef _WIN32
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
  wVersionRequested = MAKEWORD(2, 2);

  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0)
  {
    /* Tell the user that we could not find a usable */
    /* Winsock DLL.                                  */
    fprintf(stderr, "WSAStartup failed with error: %d\n", err);
    return;
  }
  /* Confirm that the WinSock DLL supports 2.2.*/
  /* Note that if the DLL supports versions greater    */
  /* than 2.2 in addition to 2.2, it will still return */
  /* 2.2 in wVersion since that is the version we      */
  /* requested.                                        */

  if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
  {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    fprintf(stderr, "Could not find a usable version of Winsock.dll\n");
    WSACleanup();
    return;
  }
#endif

  /* Obtain address(es) matching host/port */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* TCP socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0; /* Any protocol */

  sprintf(port_str, "%d", port);
  s = getaddrinfo(hostname, port_str, &hints, &result);
  if (s != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return;
  }

  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */

  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = connect_w_to(rp, TIMEOUT_SEC);
    if (sfd != -1)
    {
      break;
    }

    close(sfd);
  }

  if (rp == NULL)
  { /* No address succeeded */
    //fprintf(stderr, "Could not connect\n");

    return;
  }

  if (set_timeout(sfd, TIMEOUT_SEC) == -1)
  {
    close(sfd);
    return;
  }

  freeaddrinfo(result);

  len = build_handshake(handshake, hostname, port);
  if (send(sfd, handshake, len, 0) != len)
  {
    //fprintf(stderr, "Failed to send handshake\n");
    close(sfd);
    return;
  }

  if (send(sfd, request, 2, 0) != 2)
  {
    //fprintf(stderr, "Failed to send request\n");
    close(sfd);
    return;
  }

  read_varint(sfd); /* read packet length */
  if (read_byte(sfd, &byte) == 0)
  { /* read packet id */
    //fprintf(stderr, "Failed to read\n");
    close(sfd);
    return;
  }
  if (byte != 0)
  {
    //fprintf(stderr, "Unknown packet id\n");
    close(sfd);
    return;
  }

  std::string jsonStuff;

  /* read json and print to stdout */
  json_len = read_varint(sfd);
  while (json_len > 0)
  {
    nread = recv(sfd, string, STRING_BUF_SIZE, 0);
    if (nread == -1)
    {
      //perror("json read");
      close(sfd);
      return;
    }

    json_len -= nread;

    std::string readBuffer(string, nread);

    jsonStuff += readBuffer;
  }

  close(sfd);

  cout << jsonStuff.c_str() << endl;
  return;
}

int get_number_of_lines()
{
  // new lines will be skipped unless we stop it from happening:
  myfile.unsetf(std::ios_base::skipws);

  // count the newlines with an algorithm specialized for counting:
  int line_count = std::count(
      std::istream_iterator<char>(myfile),
      std::istream_iterator<char>(),
      '\n');

  myfile.clear();
  myfile.seekg(0);

  return line_count;
}

void scan_ip_chunk(vector<string> array_of_servers)
{
  sleep(5);
  for (int i = 0; i < array_of_servers.size(); i++)
  {
    std::string str(array_of_servers[i]);
    std::string buf;                 // Have a buffer string
    std::stringstream ss(str);       // Insert the string into a stream
    std::vector<std::string> tokens; // Create vector to hold our words
    while (ss >> buf)
      tokens.push_back(buf);

    char *ip = (char *)tokens[3].c_str();
    unsigned short port = stoi(tokens[2]);
    ping_server(ip, port);
  }
}

int main()
{
  int line_count = get_number_of_lines();

  //Read lines into array
  std::string line;
  std::string line_array[line_count];
  int z = 0;
  while (std::getline(myfile, line))
  {
    line_array[z] = line;
    ++z;
  }

  int linesPerChunk = line_count / threads;

  cout << "Total IP's: " << line_count << endl;
  cout << "Total threads: " << threads << endl;
  cout << "IP's per thread: " << linesPerChunk << "\n";

  int extra = 0;
  int extra_times = 0;

  for (int i = 0; i < line_count;)
  {
    if (extra_times < line_count % threads)
    {
      extra = 1;
      ++extra_times;
    }
    else
    {
      extra = 0;
    }

    string current_thread_array[linesPerChunk + extra];
    for (int x = 0; x < linesPerChunk + extra; ++x)
    {
      current_thread_array[x] = line_array[i];
      ++i;
    }

    std::vector<std::string> vecOfStr(current_thread_array,
                                      current_thread_array +
                                          sizeof(current_thread_array) / sizeof(current_thread_array[0]));

    ThreadVector.emplace_back([test = std::move(vecOfStr)]()
                              { scan_ip_chunk(test); });
  }

  for (auto &t : ThreadVector)
  {
    t.join();
  }

  return 0;
}
