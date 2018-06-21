#include <sniper/mhd/MHD.h>
#include <include/libplatform/libplatform.h>
#include <include/v8.h>
#include "include/v8-profiler.h"

#include "utils.h"

#ifndef V8_SERVICE
#define V8_SERVICE

#define HTTP_BAD_REQUEST_CODE 400
#define HTTP_OK_CODE 200

//Внешняя переменная контракта
class Message
{
public:
    Message()
    {
        value = 0;
        balance = 0;
        from = "";
    }
    Message(int64_t val, int64_t bc, std::string& address) : value(val), balance(bc), from(address)
    {}
    int64_t value;
    int64_t balance;
    std::string from;
};

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
    bool Compile(const std::string& address, const std::string& code, std::string& err);
    std::string Run(const std::string& address, const std::string& code, const std::string& pubkey,
                    bool& rslt, std::string& err, uint8_t firstbyte);
    std::string Dump(const std::string& address, const std::string& snapnum);
    std::string CreateAddress(uint8_t firstbyte);
    std::string GetBytecode(const std::string& address, const char* jscode, std::string& cmpl,
                            std::vector<uint8_t>& snapshot, std::ofstream& errlog, std::string& jserr);
    bool InstallObject(Message* opts, v8::Isolate* isolate);
    v8::Local<v8::ObjectTemplate> MakeObjectTemplate(v8::Isolate* isolate);
    v8::Local<v8::Object> WrapObject(Message* obj, v8::Isolate* isolate);
    Message* UnwrapObject(v8::Local<v8::Object> obj, v8::Isolate* isolate);

    std::vector<LocalStore*> local_store;
    std::string compileDirectory;
    std::string keysDirectory;
    SnapshotEnumerator* se;
    v8::Global<v8::Context> context_;
    v8::Global<v8::ObjectTemplate> global_template_;
    Message msg;
};

void RunV8Service(const char* configpath);

#endif
