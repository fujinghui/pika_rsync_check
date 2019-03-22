#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <netinet/in.h>
#include <swift/shannon_db.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define BUFLEN   102400
#define MAXADDRLEN 256

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#define DEBUG(format, arg...) \
  fprintf(stderr, "%s, %s(), line=%d:" format "\n", __FILE__, __FUNCTION__, __LINE__, ##arg)

static std::atomic<bool> running(false);

#define PLATFORM_IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
static const bool kLittleEndian = PLATFORM_IS_LITTLE_ENDIAN;

std::string g_device = "/dev/kvdev0";
struct TestDB {
  shannon::DB* db;
  std::vector<shannon::ColumnFamilyHandle*> handles;
};
std::vector<TestDB*> dbs_g;

void EncodeFixed32(char *buf, uint32_t value) {
  if (kLittleEndian) {
    memcpy(buf, &value, sizeof(value));
  } else {
    buf[0] = value & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 24) & 0xff;
  }
}

uint32_t DecodeFixed32(const char* ptr) {
  if (kLittleEndian) {
    // Load the raw bytes
    uint32_t result;
    memcpy(&result, ptr, sizeof(result));  // gcc optimizes this to a plain load
    return result;
  } else {
    return ((static_cast<uint32_t>(static_cast<unsigned char>(ptr[0])))
        | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[1])) << 8)
        | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[2])) << 16)
        | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[3])) << 24));
  }
}

long get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 100000 + tv.tv_usec;
}

std::vector<TestDB*> OpenDB() {
  std::vector<TestDB*> test_dbs;
  std::vector<std::string> db_names;

  std::vector<string> families_names;
  db_names.push_back("db_strings");
  db_names.push_back("db_hashes");
  db_names.push_back("db_lists");
  db_names.push_back("db_sets");
  db_names.push_back("db_zsets");
  db_names.push_back("db_delkeys");
  for (auto db_name : db_names) {
    families_names.clear();
    shannon::Status s = shannon::DB::ListColumnFamilies(shannon::Options(), db_name,
                g_device, &families_names);
    assert(s.ok());
    std::vector<shannon::ColumnFamilyDescriptor> column_families;
    for (auto familyname : families_names) {
      column_families.push_back(
        shannon::ColumnFamilyDescriptor(familyname, shannon::ColumnFamilyOptions()));
    }
    std::cout<<std::endl;
    shannon::DB* db;
    std::vector<shannon::ColumnFamilyHandle*> handles;
    s = shannon::DB::Open(shannon::Options(), db_name, g_device,
                          column_families, &handles, &db);
    assert(s.ok());
    TestDB *test_db = new TestDB();
    test_db->db = db;
    test_db->handles = handles;
    test_dbs.push_back(test_db);
  }
  return test_dbs;
}

void CloseDB(std::vector<TestDB*>& test_dbs) {
  for (auto db : test_dbs) {
    for (auto cf : db->handles) {
      delete cf;
    }
    delete db;
  }
}

bool DataExists(std::string& db_name,
  std::string& cf_name,
  shannon::Slice& key,
  shannon::Slice& value) {
  for (auto test_db : dbs_g) {
    shannon::DB* db = test_db->db;
    if (shannon::Slice(db->GetName().data(), db->GetName().size()).compare(
        shannon::Slice(db_name.data(), db_name.size())) == 0) {
      for (auto cf : test_db->handles) {
        if (shannon::Slice(db->GetName().data(), cf->GetName().size()).compare(
          shannon::Slice(cf->GetName().data(), cf->GetName().size())) == 0) {
          std::string tvalue;
          shannon::Status s = db->Get(shannon::ReadOptions(), cf, key.ToString(), &tvalue);
          if (s.ok() && value == tvalue) {
            return true;
          }
          return false;
        }
      }
    }
  }
}

void DecodeDataPackage(char *buf, std::string* db_name,
                       std::string* cf_name,
                       shannon::Slice* key,
                       shannon::Slice* value) {
  int32_t offset = 0;
  int32_t db_name_size = DecodeFixed32(buf + offset);
  offset += 4;
  db_name->assign(buf + offset, db_name_size);
  offset += db_name_size;
  int32_t cf_name_size = DecodeFixed32(buf + offset);
  offset += 4;
  cf_name->assign(buf + offset, cf_name_size);
  offset += cf_name_size;
  int32_t key_size = DecodeFixed32(buf + offset);
  offset += 4;
  *key = shannon::Slice(buf + offset, key_size);
  offset += key_size;
  int32_t value_size = DecodeFixed32(buf + offset);
  offset += 4;
  *value = shannon::Slice(buf + offset, value_size);
}

int EncodeDataPackage(char *buf, std::string& db_name,
                       std::string& cf_name,
                       shannon::Slice& key,
                       shannon::Slice& value) {
  int offset = 0;
  EncodeFixed32(buf + offset, db_name.size());
  offset += 4;
  memcpy(buf + offset, db_name.data(), db_name.size());
  offset += db_name.size();
  EncodeFixed32(buf + offset, cf_name.size());
  offset += 4;
  memcpy(buf + offset, cf_name.data(), cf_name.size());
  offset += cf_name.size();
  EncodeFixed32(buf + offset, key.size());
  offset += 4;
  memcpy(buf + offset, key.data(), key.size());
  offset += key.size();
  EncodeFixed32(buf + offset, value.size());
  offset += 4;
  memcpy(buf + offset, value.data(), value.size());
  offset += value.size();
  return offset;
}

void start_server(int port) {
  int err = 0;
  int buf_len;
  char buf[BUFLEN];
  int server_sockfd;
  socklen_t server_len, client_len;
  memset(buf, 0, BUFLEN);
  struct sockaddr_in server_sockaddr, client_sockaddr;
  // create a socket.type is AF_INET, sock_stream
  if ((server_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    DEBUG("create socket failed!");
    goto errout;
  }
  server_sockaddr.sin_family = AF_INET;
  server_sockaddr.sin_port = htons(port);
  server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_len = sizeof(server_sockaddr);
  // bind a socket
  if (bind(server_sockfd, (struct sockaddr*)&server_sockaddr, server_len) < 0) {
    DEBUG("bind socket failed!");
    goto errout;
  }
  int count;
  DEBUG("start running!");
  while (running) {
    client_len = sizeof(client_sockaddr);
    count = recvfrom(server_sockfd, buf, BUFLEN, 0,
                    (struct sockaddr*)&client_sockaddr, &client_len);
    if (count == -1) {
      DEBUG("receive data failed!");
      return;
    }
    std::string db_name, cf_name;
    shannon::Slice key, value;
    DecodeDataPackage(buf, &db_name, &cf_name, &key, &value);
    if (DataExists(db_name, cf_name, key, value)) {
      sprintf(buf, "ok");
      buf[2] = 0;
      sendto(server_sockfd, buf, 2, 0, (struct sockaddr*)&client_sockaddr, client_len);
    } else {
      sprintf(buf, "no");
      buf[2] = 0;
      sendto(server_sockfd, buf, 2, 0, (struct sockaddr*)&client_sockaddr, client_len);
    }
  }
errout:
  err = errno;
  close(server_sockfd);
  errno = err;
}

void start_client(char *ip, int port) {
  long start_time, end_time;
  long frequency = 500000;         // 500ms
  long last_size = 0, cur_size = 0, total_size = 0;
  int client_fd;
  int per_count = 0;
  struct sockaddr_in ser_addr;
  char buf[BUFLEN], buf_len;

  client_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_fd < 0) {
    DEBUG("create socket failed!");
  }
  memset(&ser_addr, 0, sizeof(ser_addr));
  ser_addr.sin_family = AF_INET;
  // ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ser_addr.sin_addr.s_addr = inet_addr(ip);
  ser_addr.sin_port = htons(port);
  socklen_t slen;
  struct sockaddr_in src;
  start_time = get_time();
  for (auto test_db : dbs_g) {
    shannon::DB* db = test_db->db;
    for (auto handle : test_db->handles) {
      shannon::Iterator* iter = db->NewIterator(shannon::ReadOptions(), handle);
      assert(iter != NULL);
      for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
        shannon::Slice key = iter->key();
        shannon::Slice value = iter->value();
        std::string db_name = db->GetName();
        std::string cf_name = handle->GetName();
        int len = EncodeDataPackage(buf, db_name, cf_name, key, value);
        cur_size += (long)len;
        total_size += (long)len;
        slen = sizeof(struct sockaddr_in);
        sendto(client_fd, buf, len, 0, (struct sockaddr*)&ser_addr, slen);
        recvfrom(client_fd, buf, BUFLEN, 0, (struct sockaddr*)&src, &slen);
        if (memcmp(buf, "ok", 2) == 0) {
          per_count ++;
          end_time = get_time();
          if (end_time >= start_time + frequency) {
            double speed = cur_size * (1000000.0 /
                           (1.0 * frequency)) / 1024.0 / 1024.0;
            std::cout<<"speed:"<<speed<<std::endl;
            DEBUG("count:%d total:%lld speed:%lfMB\n", per_count, total_size, speed);
            per_count = 0;
            cur_size = 0;
            start_time = end_time;
          }
        } else {
          DEBUG("failed!");
          return;
        }
      }
      delete iter;
    }
  }
}

static void IntSigHandle(const int sig) {
  printf("Catch Signal %d, cleanup...\n", sig);
  running.store(false);
  printf("server exit");
  CloseDB(dbs_g);
}

static void SignalSetup() {
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, &IntSigHandle);
  signal(SIGQUIT, &IntSigHandle);
  signal(SIGTERM, &IntSigHandle);
}

void usage() {
  printf("usage:\n");
  printf("\t\tserver port. for example:server 9221\n");
  printf("\t\tclient ip port. for example:client 127.0.0.1 9221\n");
}

int main(int argc, char *argv[]) {
  int port = 9224;
  char *ip = NULL;
  if (argc <= 2) {
    usage();
    return 0;
  }
  if (argc >= 3) {
    running.store(true);
    SignalSetup();
    if (memcmp(argv[1], "server", 6) == 0) {
      dbs_g = OpenDB();
      port = atoi(argv[2]);
      start_server(port);
      CloseDB(dbs_g);
    } else if (memcmp(argv[1], "client", 6) == 0) {
      dbs_g = OpenDB();
      ip = argv[2];
      port = atoi(argv[3]);
      start_client(ip, port);
      CloseDB(dbs_g);
    }
    DEBUG("run end!");
  }
  return 0;
}
