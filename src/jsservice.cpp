#include "jsservice.h"

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h++>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sniper/syslog/log.h>

#include "utils.h"
#include "stdcapture.hpp"

extern intptr_t original_external_references[];
extern std::ofstream g_errorlog;

static void sig_handler(int sig)
{
    (void) sig;
    exit(1);
}

V8Service::~V8Service()
{
    for (size_t i = 0; i < local_store.size(); i++)
    {
        if (local_store[i])
            delete local_store[i];
    }
    if (se)
        delete se;
}

bool V8Service::run(int thread_number, Request& mhd_req, Response& mhd_resp)
{
    LocalStore* store = local_store[thread_number];
    (void) store;
	ProcessRequest(mhd_req, mhd_resp);
    return true;
}

bool V8Service::init()
{
    signal(SIGTERM, sig_handler);
    if (!ReadConfig())
        return false;
    try
    {
        local_store.resize(get_threads());
        for(size_t i = 0; i < local_store.size(); i++)
            local_store[i] = new LocalStore;
        v8::V8::SetFlagsFromString("--trace-ignition", 16);
    }
    catch (std::exception& e)
    {
        log_err("Catch exception while init LocalStore: %s\n", e.what());
        return false;
    }
    return true;
}

bool V8Service::ReadConfig()
{
    libconfig::Config cfg;
	std::string cfgpath = get_config_path();
	if (cfgpath[cfgpath.size()-1] == '/')
		cfgpath.pop_back();

    try
    {
        cfg.readFile(cfgpath.c_str());
    }
    catch(const libconfig::FileIOException &fioex)
    {
        log_err("Config not found.\n");
        return false;
    }
    catch(libconfig::ParseException &pex)
    {
        log_err("Config parse error at %d - %s.\n", pex.getLine(), pex.getError());
        return false;
    }

    try
    {
        const libconfig::Setting& settings = cfg.getRoot()["settings"];
        int port;
        if (settings.lookupValue("port", port))
            set_port(port);
        else
        {
            log_err("Port not found.\n");
            return false;
        }
        if (!settings.lookupValue("compiledirectory", compileDirectory))
        {
            log_err("compiledirectory not found.\n");
            return false;
        }
        //Проверяем существование директории compileDirectory
        if (!IsDirectoryExist(compileDirectory.c_str()))
        {
            log_err("Invalid compiledirectory parameter.\n");
            return false;
        }
        else
        {
            se = new SnapshotEnumerator();
        }
        if (!settings.lookupValue("keysdirectory", keysDirectory))
        {
            log_err("keysdirectory not found.\n");
            return false;
        }
        if (!IsDirectoryExist(keysDirectory.c_str()))
        {
            log_err("Invalid keysdirectory parameter.\n");
            return false;
        }
        //Сервис всегда однопоточный
        set_threads(1);
        return true;
    }
    catch (const libconfig::SettingNotFoundException& e)
    {
        log_err("Setting does not found: %s\n", e.getPath());
    }
    catch (std::exception& e)
    {
        log_err("Unknown exception in %s: %s\n", __FUNCTION__, e.what());
    }

    return false;
}

void V8Service::ProcessRequest(Request& mhd_req, Response& mhd_resp)
{
    std::string address = "";
    std::string js = "";
    //Получаем режим запроса из url
    mhd_resp.headers["Content-Type"] = "text/plain";
    std::string action = mhd_req.params["act"];
    if (!action.empty())
    {
        //Режим компиляции кода
        if (action.compare("compile") == 0)
        {
            address = mhd_req.params["a"];
            js = mhd_req.post;
            if (!address.empty() && !js.empty())
            {
                Compile(address, js);
                mhd_resp.code = HTTP_OK_CODE;
            }
            else
            {
                log_err("One of the parameters for the compilation command is not specified.\n");
                mhd_resp.code = HTTP_BAD_REQUEST_CODE;
            }
        }
        else
        {
            //Режим выполнения кода
            if (action.compare("cmdrun") == 0)
            {
                std::string response = "";
                address = mhd_req.params["a"];
                js = mhd_req.post;
                if (!address.empty() && !js.empty())
                {
                    response = Run(address, js);
                    mhd_resp.data = response;
                    mhd_resp.code = HTTP_OK_CODE;
                }
                else
                {
                    log_err("One of the parameters for the run command is not specified.\n");
                    mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                }
            }
            else
            {
                if (action.compare("dump") == 0)
                {
                    std::string response = "";
                    address = mhd_req.params["a"];
                    std::string snapnum = mhd_req.params["state"];
                    if (!address.empty() && !snapnum.empty())
                    {
                        response = Dump(address, snapnum);
                        mhd_resp.data = response;
                        mhd_resp.code = HTTP_OK_CODE;
                    }
                    else
                    {
                        log_err("One of the parameters for the dump command is not specified.\n");
                        mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                    }
                }
                else
                {
                    if (action.compare("mh_gen") == 0)
                    {
                        mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                        std::string firstbyte = mhd_req.params["byte"];//В шестнадцатеричной форме
                        try
                        {
                            int byteint = std::stoi(firstbyte, 0, 16);
                            if (byteint >= 0 && byteint < 256)
                            {
                                uint8_t byte = (uint8_t)byteint;
                                std::string newaddr = CreateAddress(byte);
                                if (!newaddr.empty())
                                {
                                    mhd_resp.data = newaddr;
                                    mhd_resp.code = HTTP_OK_CODE;
                                }
                                else
                                    log_err("Create address error.\n");
                            }
                            else
                                log_err("Invalid byte value.\n");
                        }
                        catch (std::exception& ex)
                        {
                            log_err("Invalid byte value.\n");
                        }
                    }
                    else
                    {
                        //Режим не существует
                        log_err("Command %s not found.\n", action.c_str());
                        mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                    }
                }
            }
        }
    }
    else
    {
        //Режим использования не указан
        log_err("Command not specified.\n");
        mhd_resp.code = HTTP_BAD_REQUEST_CODE;
    }
}

void V8Service::Compile(const std::string& address, const std::string& code)
{
    std::string addrdir = compileDirectory + "/" + address;
    const int direrr = mkdir(addrdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (direrr < 0)
    {
        log_err("Error creating directory!n");
        return;
    }
    std::string dbgfilepath = addrdir + "/" + address + ".dbgi";
    std::string btfilepath = addrdir + "/" + address + ".bc";
    std::string cmplfilepath = addrdir + "/" + address + ".cmpl";
    std::string errlogfilepath = addrdir + "/" + address + ".log";
    std::string snapshotfilepath = addrdir + "/" + address + ".cmpl.shot";
    std::string jsfilepath = addrdir + "/" + address + ".js";
    std::ofstream dbgfile(dbgfilepath, std::ios::out | std::ios::app);
    std::ofstream btfile(btfilepath, std::ios::out | std::ios::app);
    std::ofstream cmplfile(cmplfilepath, std::ios::out | std::ios::app);
    std::ofstream errlogfile(errlogfilepath, std::ios::out | std::ios::app);
    std::ofstream snapshotfile(snapshotfilepath, std::ios::out | std::ios::app);
     std::ofstream jsfile(jsfilepath, std::ios::out | std::ios::app);
    if (!dbgfile || !btfile || !cmplfile || !errlogfile || !snapshotfile || !jsfile)
    {
        log_err("Open output files error.\n");
        return;
    }
    jsfile << code;
    std::string debuglog = "";
    std::string cmpl = "";
    std::vector<uint8_t> snapshot;
    std::string bytecode = GetBytecode(code.c_str(), cmpl, snapshot, errlogfile);
    if (!bytecode.empty())
    {
        dbgfile << bytecode;
        btfile << BytecodeToListing(bytecode);
        if (!cmpl.empty())//Ошибок при создании компилированного кода тоже не было
        {
            //Cохраняем компилированный скрипт в ADDR.cmpl
            cmplfile << cmpl;
            //Сохраняем файл снимка если он создан
            if (!snapshot.empty())
                snapshotfile.write((const char*)snapshot.data(), snapshot.size());
        }
    }
    dbgfile.close();
    btfile.close();
    cmplfile.close();
    errlogfile.close();
    snapshotfile.close();
    jsfile.close();
}

std::string V8Service::GetBytecode(const char* jscode, std::string& cmpl,
                                    std::vector<uint8_t>& snapshot, std::ofstream& errlog)
{
    StdCapture out;
    out.BeginCapture();
    std::string bytecode = "";
    cmpl.clear();
    v8::StartupData blob;
    {
        v8::SnapshotCreator* creator = NULL;
        v8::Isolate::CreateParams params;
        v8::Isolate* isolate = NULL;
        creator = new v8::SnapshotCreator(original_external_references);
        isolate = creator->GetIsolate();

        //Запуск isolate
        {
            v8::HandleScope handle_scope(isolate);
            v8::TryCatch try_catch(isolate);
            v8::Local<v8::Context> context = v8::Context::New(isolate);
            v8::Context::Scope context_scope(context);
            creator->SetDefaultContext(context);
            v8::Local<v8::Value> result;

            v8::Local<v8::String> source =
            v8::String::NewFromUtf8(isolate,
                                    jscode,
                                    v8::NewStringType::kNormal).ToLocalChecked();
            v8::Local<v8::Script> script;
            if (!v8::Script::Compile(context, source).ToLocal(&script))
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                errlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
                return "";
            }

            if (!script->Run(context).ToLocal(&result))
            {
                v8::Local<v8::Value> val = try_catch.Exception();
                if (!val->IsTrue())
                {
                    v8::String::Utf8Value error(isolate, try_catch.Exception());
                    errlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
                    return "";
                }
            }
            else
            {
                //v8::String::Utf8Value utf8(isolate, result);
                //errlog << __FUNCTION__ << ":" << *utf8 << std::endl;
            }
            //Сохраняем копию компилированного кода
            v8::Local<v8::Value> testresult;
            v8::ScriptOrigin origin(v8::String::NewFromUtf8(isolate,
                                    "test",
                                    v8::NewStringType::kNormal).ToLocalChecked());
            v8::ScriptCompiler::Source src(source, origin);
            v8::Local<v8::UnboundScript> unboundscript = v8::ScriptCompiler::CompileUnboundScript(isolate, &src, v8::ScriptCompiler::kProduceFullCodeCache).ToLocalChecked();
            v8::ScriptCompiler::CachedData* data = v8::ScriptCompiler::CreateCodeCache(unboundscript);
            if (data && data->length)
                cmpl.assign((const char*)data->data, data->length);
            else
            {
                errlog << "(" << __FUNCTION__ << "):Can not create code cache" << std::endl;
            }
        }
        //Получаем байткод
        out.EndCapture();
        bytecode = out.GetCapture();
        //Если все прошло удачно, то выгружаем итоговый снимок.
        blob = creator->CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
        snapshot.resize(blob.raw_size);
        memcpy(snapshot.data(), blob.data, blob.raw_size);

        if (creator)
            delete creator;
    }

    return bytecode;
}

std::string V8Service::Run(const std::string& address, const std::string& code)
{
    std::string execresult = "";
    std::string snapshot = "";
    std::unordered_map<std::string, std::vector<std::string> >::iterator it;
    se->Reload((compileDirectory + "/" + address).c_str());
    it = se->snapshotsnames.find(address);
    StdCapture out;
    out.BeginCapture();
    v8::StartupData blob;
    //Проверяем есть ли входной снимок
    v8::SnapshotCreator* creator = NULL;
    v8::Isolate::CreateParams params;
    v8::Isolate* isolate = NULL;
    if (it != se->snapshotsnames.end())
    {
        //Инициализация состояния из снимка
        std::string fullsnappath = compileDirectory + "/" + address + "/" + it->second[it->second.size()-1];
        snapshot = ReadFile(fullsnappath);
        if (!snapshot.empty())
        {
            blob.data = snapshot.data();
            blob.raw_size = snapshot.size();
            creator = new v8::SnapshotCreator(original_external_references, &blob);
            isolate = creator->GetIsolate();
        }
    }
    else
    {
        creator = new v8::SnapshotCreator(original_external_references);
        isolate = creator->GetIsolate();
    }
    //Запуск isolate
    {
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        creator->SetDefaultContext(context);
        v8::Local<v8::Value> result;

        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                code.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return "";
        }

        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
                return "";
            }
        }
        else
        {
            v8::String::Utf8Value utf8(isolate, result);
            execresult = *utf8;
        }
    }
    out.EndCapture();
    //Определяем номер последнего снимка
    std::string nextsnapnum = GetNextSnapNumber(it->second[it->second.size()-1]);
    //Если все прошло удачно, то выгружаем итоговый снимок.
    std::string newsnapsotpath = compileDirectory + "/" + address + "/" + address + "." +
                                 nextsnapnum + ".shot";
    std::string cmdjspath = compileDirectory + "/" + address + "/" + address + "." +
                                 nextsnapnum + ".js";
    std::ofstream snapout(newsnapsotpath.c_str(), std::ios::out | std::ios::app);
    std::ofstream cmdjs(cmdjspath.c_str(), std::ios::out | std::ios::app);
    if (!cmdjs || !snapout)
    {
        g_errorlog << __FUNCTION__ << ":Can not open output file" << std::endl;
        return "";
    }
    cmdjs << code;
    cmdjs.close();
    //Запрашиваем сборку мусора перед созданием снимка
    blob = creator->CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    snapout.write(blob.data, blob.raw_size);
    snapout.close();
    if (creator)
        delete creator;
    return execresult;
}

std::string V8Service::Dump(const std::string& address, const std::string& snapnum)
{
    std::string heapdump = "";
    v8::StartupData blob;
    v8::SnapshotCreator* creator = NULL;
    v8::Isolate* isolate = NULL;

    //Читаем файл со снимком
    std::string snappath = compileDirectory + "/" + address + "/" + address + "." +
                                    snapnum + ".shot";
    std::string snapcontent = ReadFile(snappath);
    if (!snapcontent.empty())
    {
        blob.data = snapcontent.data();
        blob.raw_size = snapcontent.size();
        creator = new v8::SnapshotCreator(original_external_references, &blob);
        if (creator)
        {
            isolate = creator->GetIsolate();
            {
                v8::HandleScope handle_scope(isolate);
                v8::TryCatch try_catch(isolate);
                v8::Local<v8::Context> context = v8::Context::New(isolate);
                v8::Context::Scope context_scope(context);
                creator->SetDefaultContext(context);
                v8::Local<v8::Value> result;

                v8::HeapProfiler* heapprofiler = isolate->GetHeapProfiler();
                const v8::HeapSnapshot* snapshot = heapprofiler->TakeHeapSnapshot();
                HeapSerialize s;
                snapshot->Serialize(&s);
                s.WaitForEnd();

                heapdump =
                        "{\n"
                            "\"vars\" : [],\n"
                            "\"functions\" : [],\n"
                            "\"native\" : \n"
                            + s.GetJson() +
                        "}";
            }
        }
        else
            g_errorlog << __FUNCTION__ << ":SnapshotCreator error" << std::endl;
    }
    else
        g_errorlog << __FUNCTION__ << ":Snapshot file reading error" << std::endl;

    return heapdump;
}

std::string V8Service::CreateAddress(uint8_t firstbyte)
{
    std::string pubkey = "";
    std::string privkey = "";
    std::string address = "";

    if (CreateECKeyPairAndAddr(privkey, pubkey, address, firstbyte))
    {
        //Сохраняем ключи в директории keysDirectory
        address = "0x" + address;
        std::string addrdir = keysDirectory + "/" + address;
        const int direrr = mkdir(addrdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (direrr < 0)
        {
            log_err("Error creating directory!n");
            return "";
        }
        std::string pubkeypath = addrdir + "/" + address + ".pub.der";
        std::string privkeypath = addrdir + "/" + address + ".priv.der";
        std::ofstream pubkeyfile(pubkeypath, std::ios::out | std::ios::app);
        std::ofstream privkeyfile(privkeypath, std::ios::out | std::ios::app);
        if (!pubkeyfile || !privkeyfile)
        {
            log_err("Error opening key files");
            return "";
        }
        pubkeyfile << pubkey;
        privkeyfile << privkey;
        pubkeyfile.close();
        privkeyfile.close();

        return address;
    }
    else
        return "";
}

void RunV8Service(const char* configpath)
{
    std::string path = "";
    if (configpath)
    {
        path.assign(configpath);
        V8Service ex;
        ex.start(path);
    }
}
