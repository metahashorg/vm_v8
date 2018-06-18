#include <sniper/mhd/MHD.h>
#include <include/libplatform/libplatform.h>
#include <include/v8.h>
#include "include/v8-profiler.h"

#include "utils.h"

#ifndef V8_SERVICE
#define V8_SERVICE

#define HTTP_BAD_REQUEST_CODE 400
#define HTTP_OK_CODE 200

class V8Service: public sniper::mhd::MHD
{
public:
    V8Service()
	{}
    virtual ~V8Service();
	virtual bool init();
    virtual bool run(int thread_number, Request& mhd_req, Response& mhd_resp);

private:
    struct LocalStore
	{
    };

    bool ReadConfig();
    void ProcessRequest(Request& mhd_req, Response& mhd_resp);
    void Compile(const std::string& address, const std::string& code);
    std::string Run(const std::string& address, const std::string& code);
    std::string Dump(const std::string& address, const std::string& snapnum);
    std::string CreateAddress(uint8_t firstbyte);

    std::string GetBytecode(const char* jscode, std::string& cmpl,
                            std::vector<uint8_t>& snapshot, std::ofstream& errlog);
    std::vector<LocalStore*> local_store;
    std::string compileDirectory;
    std::string keysDirectory;
    SnapshotEnumerator* se;
};

void RunV8Service(const char* configpath);
#endif
