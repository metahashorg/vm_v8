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
#include "external/variables/msgDataFrom.hpp"
#include "external/variables/msgDataValue.hpp"

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
        g_errorlog << "Catch exception while init LocalStore:" << e.what() << std::endl;
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
        g_errorlog << "Config not found." << std::endl;
        return false;
    }
    catch(libconfig::ParseException &pex)
    {
        g_errorlog << "Config parse error at " << pex.getLine() << ":" << pex.getError() << std::endl;
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
            g_errorlog << "Port not found" << std::endl;
            return false;
        }
        if (!settings.lookupValue("compiledirectory", compileDirectory))
        {
            g_errorlog << "compiledirectory not found." << std::endl;
            return false;
        }
        //Проверяем существование директории compileDirectory
        if (!IsDirectoryExist(compileDirectory.c_str()))
        {
            g_errorlog << "Invalid compiledirectory parameter." << std::endl;
            return false;
        }
        else
        {
            se = new SnapshotEnumerator();
        }
        if (!settings.lookupValue("keysdirectory", keysDirectory))
        {
            g_errorlog << "keysdirectory not found." << std::endl;
            return false;
        }
        if (!IsDirectoryExist(keysDirectory.c_str()))
        {
            g_errorlog << "Invalid keysdirectory parameter" << std::endl;
            return false;
        }
        //Сервис всегда однопоточный
        set_threads(1);
        return true;
    }
    catch (const libconfig::SettingNotFoundException& e)
    {
        g_errorlog << "Setting does not found: " << e.getPath() << std::endl;
    }
    catch (std::exception& e)
    {
        g_errorlog << "Unknown exception in " << __FUNCTION__ << ":" << e.what() << std::endl;
    }

    return false;
}

void V8Service::ProcessRequest(Request& mhd_req, Response& mhd_resp)
{
    std::string address = "";
    std::string js = "";
    std::string pubkeyparam = "";
    std::string signatureparam = "";
    //Получаем режим запроса из url
    mhd_resp.headers["Content-Type"] = "text/plain";
    mhd_resp.headers["Access-Control-Allow-Origin"] = "*";
    std::string action = mhd_req.params["act"];
    if (!action.empty())
    {
        //Режим компиляции кода
        if (action.compare("compile") == 0)
        {
            address = mhd_req.params["a"];
            js = mhd_req.post;
            mhd_resp.code = HTTP_BAD_REQUEST_CODE;
            //Проверка подписи
            pubkeyparam = mhd_req.params["pubk"];
            signatureparam = mhd_req.params["sign"];
            if (!address.empty() && !js.empty() && !pubkeyparam.empty() && !signatureparam.empty())
            {
                if (CheckSign(mhd_req.post, signatureparam, pubkeyparam))
                {
                    std::string err = "";
                    if (Compile(address, js, err))
                    {
                        mhd_resp.code = HTTP_OK_CODE;
                    }
                    else
                    {
                        mhd_resp.data = err;
                    }
                }
                else
                    mhd_resp.data = "Signature verification failed.";
            }
            else
            {
                g_errorlog << "One of the parameters for the compilation command is not specified" << std::endl;
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
                mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                pubkeyparam = mhd_req.params["pubk"];
                signatureparam = mhd_req.params["sign"];
                std::string firstbyte = mhd_req.params["byte"];//В шестнадцатеричной форме
                try
                {
                    int byteint = std::stoi(firstbyte, 0, 16);
                    if (byteint >= 0 && byteint < 256)
                    {
                        if (!address.empty() && !js.empty() && !pubkeyparam.empty() && !signatureparam.empty())
                        {
                            if (CheckSign(mhd_req.post, signatureparam, pubkeyparam))
                            {
                                bool rslt = false;
                                std::string err = "";
                                response = Run(address, js, pubkeyparam, rslt, err, 0x4);
                                if (rslt)
                                {
                                    mhd_resp.data = response;
                                    mhd_resp.code = HTTP_OK_CODE;
                                }
                                else
                                {
                                    if (err.empty())
                                        err = "Internal service error";
                                    mhd_resp.data = err;
                                }
                            }
                            else
                                mhd_resp.data = "Signature verification failed.";
                        }
                        else
                        {
                            mhd_resp.data = "One of the parameters for the run command is not specified.";
                            g_errorlog << mhd_resp.data << std::endl;
                        }
                    }
                    else
                    {
                        mhd_resp.data = "Invalid netbyte value";
                        g_errorlog << mhd_resp.data << std::endl;
                    }
                }
                catch(const std::exception& ex)
                {
                    mhd_resp.data = "Invalid netbyte value";
                    log_err(mhd_resp.data.c_str());
                }
            }
            else
            {
                if (action.compare("dump") == 0)
                {
                    std::string response = "";
                    address = mhd_req.params["a"];
                    std::string snapnum = mhd_req.params["state"];
                    mhd_resp.code = HTTP_BAD_REQUEST_CODE;

                    if (!address.empty() && !snapnum.empty())
                    {
                        response = Dump(address, snapnum);
                        mhd_resp.data = response;
                        mhd_resp.code = HTTP_OK_CODE;
                    }
                    else
                        g_errorlog << "One of the parameters for the dump command is not specified." << std::endl;
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
                                    g_errorlog << "Create address error." << std::endl;
                            }
                            else
                                g_errorlog << "Invalid byte value." << std::endl;
                        }
                        catch (std::exception& ex)
                        {
                            g_errorlog << "Invalid byte value." << std::endl;
                        }
                    }
                    else
                    {
                        if (action.compare("mh_sign") == 0)
                        {
                            mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                            address = mhd_req.params["a"];
                            if (!address.empty())
                            {
                                //Ищем соответствущий адресу ключ
                                std::string keydir = keysDirectory + "/" + address;
                                std::string privkeypath = keydir + "/" + address + ".priv.der";
                                std::string pubkeypath = keydir + "/" + address + ".pub.der";
                                std::string privkeyhex = ReadFile(privkeypath);
                                std::string pubkeyhex = ReadFile(pubkeypath);
                                if (!privkeyhex.empty() && !pubkeyhex.empty())
                                {
                                    std::string signature = SignData(mhd_req.post, privkeyhex);
                                    if (!signature.empty())
                                    {
                                        std::string response = "{\n"
                                                                    "\"pubkey\":\"" + pubkeyhex + "\",\n"
                                                                    "\"signature\":\"" + signature + "\"\n"
                                                                "}\n";
                                        mhd_resp.data = response;
                                        mhd_resp.code = HTTP_OK_CODE;
                                    }
                                    else
                                        g_errorlog << "Data signing error" << std::endl;
                                }
                                else
                                    g_errorlog << "Private key file not found or empty." << std::endl;
                            }
                            else
                                g_errorlog << "Address parameter not found." << std::endl;
                        }
                        else
                        {
                            //Режим не существует
                            g_errorlog << "Command " << action <<  " not found." << std::endl;
                            mhd_resp.code = HTTP_BAD_REQUEST_CODE;
                        }
                    }
                }
            }
        }
    }
    else
    {
        //Режим использования не указан
        g_errorlog << "Command not specified." << std::endl;
        mhd_resp.code = HTTP_BAD_REQUEST_CODE;
    }
}

bool V8Service::Compile(const std::string& address, const std::string& code, std::string& err)
{
    bool rslt = false;
    err.clear();
    std::string addrdir = compileDirectory + "/" + address;
    const int direrr = mkdir(addrdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (direrr < 0)
    {
        log_err("Error creating directory!n");
        return false;
    }
    std::string dbgfilepath = addrdir + "/" + address + ".dbgi";
    std::string btfilepath = addrdir + "/" + address + ".bc";
    std::string cmplfilepath = addrdir + "/" + address + ".cmpl";
    std::string errlogfilepath = addrdir + "/" + address + ".log";
    std::string snapshotfilepath = addrdir + "/" + address + ".cmpl.shot";
    std::string jsfilepath = addrdir + "/" + address + ".js";

    std::ofstream errlogfile(errlogfilepath, std::ios::out | std::ios::app);
    std::ofstream jsfile(jsfilepath, std::ios::out | std::ios::app);
    if (!errlogfile || !jsfile)
    {
        log_err("Open output files error.\n");
        return false;
    }
    jsfile << code;
    jsfile.close();

    std::string debuglog = "";
    std::string cmpl = "";
    std::vector<uint8_t> snapshot;
    std::string bytecode = GetBytecode(address, code.c_str(), cmpl, snapshot, errlogfile, err);
    if (!bytecode.empty())
    {
        std::ofstream dbgfile(dbgfilepath, std::ios::out | std::ios::app);
        std::ofstream btfile(btfilepath, std::ios::out | std::ios::app);
        std::ofstream cmplfile(cmplfilepath, std::ios::out | std::ios::app);
        std::ofstream snapshotfile(snapshotfilepath, std::ios::out | std::ios::app);

        dbgfile << bytecode;
        btfile << BytecodeToListing(bytecode);
        if (!cmpl.empty())//Ошибок при создании компилированного кода тоже не было
        {
            //Cохраняем компилированный скрипт в ADDR.cmpl
            cmplfile << cmpl;
            //Сохраняем файл снимка если он создан
            if (!snapshot.empty())
            {
                snapshotfile.write((const char*)snapshot.data(), snapshot.size());
                rslt = true;
            }
        }

        dbgfile.close();
        btfile.close();
        cmplfile.close();
        snapshotfile.close();
    }
    else
    {
        if (err.empty())//Ошибка не связанная с js-кодом
            err = "Internal service error.";
    }
    errlogfile.close();

    return rslt;
}

std::string V8Service::GetBytecode(const std::string& address, const char* jscode, std::string& cmpl,
                                    std::vector<uint8_t>& snapshot, std::ofstream& errlog, std::string& jserr)
{
    intptr_t message_references[] = {
                                reinterpret_cast<intptr_t>(&msg),
                                reinterpret_cast<intptr_t>(&GetMsgValue),
                                reinterpret_cast<intptr_t>(&SetMsgValue),
                                reinterpret_cast<intptr_t>(&GetAddress),
                                reinterpret_cast<intptr_t>(&SetAddress),
                                0
                             };
    StdCapture out;
    out.BeginCapture();
    std::string bytecode = "";
    cmpl.clear();
    v8::StartupData blob;
    {
        v8::SnapshotCreator* creator = NULL;
        v8::Isolate::CreateParams params;
        v8::Isolate* isolate = NULL;
        creator = new v8::SnapshotCreator(message_references);
        isolate = creator->GetIsolate();
        //Запуск isolate
        {
            v8::HandleScope handle_scope(isolate);
            v8::TryCatch try_catch(isolate);
            v8::Local<v8::Context> context = v8::Context::New(isolate);
            v8::Context::Scope context_scope(context);
            //В случае компиляции msg.sender совпадает со значенением адреса отправителя
            msg.from = address;
            msg.value = 0;
            InstallMessageObject(isolate, &msg);
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
                jserr = "Compile error(" + std::string(__FUNCTION__) + "):" + *error;
                errlog << jserr << std::endl;
                return "";
            }

            if (!script->Run(context).ToLocal(&result))
            {
                v8::Local<v8::Value> val = try_catch.Exception();
                if (!val->IsTrue())
                {
                    v8::String::Utf8Value error(isolate, try_catch.Exception());
                    jserr = "Run error(" + std::string(__FUNCTION__) + "):" + *error;
                    errlog << jserr << std::endl;
                    return "";
                }
            }
            else
            {
                v8::String::Utf8Value utf8(isolate, result);
                errlog << __FUNCTION__ << ":" << *utf8 << std::endl;
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

std::string V8Service::Run(const std::string& address, const std::string& code, const std::string& pubkey,
                            bool& rslt, std::string& err, uint8_t firstbyte)
{
    intptr_t message_references[] = {
                                reinterpret_cast<intptr_t>(&msg),
                                reinterpret_cast<intptr_t>(&GetMsgValue),
                                reinterpret_cast<intptr_t>(&SetMsgValue),
                                reinterpret_cast<intptr_t>(&GetAddress),
                                reinterpret_cast<intptr_t>(&SetAddress),
                                0
                             };
    rslt = false;
    err.clear();
    std::string execresult = "";
    std::string snapshot = "";
    std::string nextsnapnum = "";
    std::unordered_map<std::string, std::vector<std::string> >::iterator it;
    se->Reload((compileDirectory + "/" + address).c_str());
    it = se->snapshotsnames.find(address);
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
            creator = new v8::SnapshotCreator(message_references, &blob);
            isolate = creator->GetIsolate();
        }
    }
    else
    {
        creator = new v8::SnapshotCreator(message_references);
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

        //Определяем номер последнего снимка
        nextsnapnum = GetNextSnapNumber(it->second[it->second.size()-1]);
        Message* nativemsg = NULL;
        v8::Local<v8::String> msgname = v8::String::NewFromUtf8(isolate,
                                                            "msg",
                                                            v8::NewStringType::kNormal).ToLocalChecked();
        v8::Local<v8::Value> msgobj = context->Global()->Get(context, msgname).ToLocalChecked();
        if (msgobj->IsObject())
        {
            v8::Local<v8::Object> obj = msgobj->ToObject();
            nativemsg = UnwrapObject(isolate, obj);
            if (nativemsg == NULL)
            {
                g_errorlog << __FUNCTION__ << " : nativemsg == null" << std::endl;
                return "";
            }
        }
        else
        {
            g_errorlog << __FUNCTION__ << " : msgobj not object" << std::endl;
            return "";
        }

        if (nativemsg != NULL)
        {
            if (nextsnapnum.compare("0") == 0)//Это инициализирующий запуск
            {
                nativemsg->from = address;
            }
            else
            {
                nativemsg->from = HexPubkeyToAddress(pubkey, firstbyte);
            }
        }

        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                code.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            err = "Compile error(" + std::string(__FUNCTION__) + "):" + *error;
            g_errorlog << err << std::endl;
            return "";
        }

        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                err = "Run error(" + std::string(__FUNCTION__) + "):" + *error;
                g_errorlog << err << std::endl;
                return "";
            }
        }
        else
        {
            v8::String::Utf8Value utf8(isolate, result);
            execresult = *utf8;
            g_errorlog << "result: " << execresult << std::endl;
        }
    }

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
    blob = creator->CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    snapout.write(blob.data, blob.raw_size);
    snapout.close();
    if (creator)
        delete creator;
    rslt = true;
    return execresult;
}

std::string V8Service::Dump(const std::string& address, const std::string& snapnum)
{
    intptr_t common_references[] = {0};
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
        creator = new v8::SnapshotCreator(common_references, &blob);
        if (creator)
        {
            isolate = creator->GetIsolate();
            {
            v8::HandleScope handle_scope(isolate);
            v8::TryCatch try_catch(isolate);
            v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
            v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
            v8::Context::Scope context_scope(context);
            creator->SetDefaultContext(context);
            v8::Local<v8::Value> result;
            v8::Local<v8::Object> globalobj = context->Global();
            //С целью правильной сериализации данных типа Map
            //определяем функцию replacer
            const char* replacersrc = "function replacer(name, val)\n"
                                   "{\n"
                                        "let ar = [];\n"
                                        "if ( val instanceof Map )\n"
                                        "{\n"
                                            "val.forEach((x, s) => {\n"
                                            "ar.push([s, x])\n"
                                            "})\n"
                                            "return ar;\n"
                                        "}\n"
                                        "else\n"
                                        "{\n"
                                            "return val;\n"
                                        "}\n"
                                    "};\n";

            v8::Local<v8::String> replacer =
            v8::String::NewFromUtf8(isolate,
                                    replacersrc,
                                    v8::NewStringType::kNormal).ToLocalChecked();
            v8::Local<v8::Script> rplscript;
            if (!v8::Script::Compile(context, replacer).ToLocal(&rplscript))
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Replacer compile error(" << __FUNCTION__ << "):" << *error << std::endl;
                return "";
            }
            //Определяем replacer в текущем контексте
            if (!rplscript->Run(context).ToLocal(&result))
            {
                v8::Local<v8::Value> val = try_catch.Exception();
                if (!val->IsTrue())
                {
                    v8::String::Utf8Value error(isolate, try_catch.Exception());
                    g_errorlog << "Replacer run error(" << __FUNCTION__ << "):" << *error << std::endl;
                    return "";
                }
            }
            else
            {
                //v8::String::Utf8Value utf8(isolate, result);
                //g_errorlog << __FUNCTION__ << ":" << *utf8 << std::endl;
            }

            //Перебираем переменные в куче.
            size_t i = 0;
            std::vector<std::vector<std::string>> symbols;
            symbols.resize(14);//Колл-во типов HeapGraphNode
            v8::HeapProfiler* heapprofiler = isolate->GetHeapProfiler();
            const v8::HeapSnapshot* snapshot = heapprofiler->TakeHeapSnapshot();
            const v8::HeapGraphNode* node = snapshot->GetRoot()->GetChild(1)->GetToNode();
            GetProperties(isolate, node, symbols);

            //Получаем значения переменных по имени из контекста
            std::string line = "";
            std::unordered_map<std::string, std::string> variables;
            std::vector<std::string> functions;
            if (!symbols[v8::HeapGraphNode::kObject].empty())
            {
                for (i = 0; i < symbols[v8::HeapGraphNode::kObject].size(); ++i)
                {
                    v8::Local<v8::String> objname = v8::String::NewFromUtf8(isolate,
                                                    symbols[v8::HeapGraphNode::kObject][i].c_str(),
                                                    v8::NewStringType::kNormal).ToLocalChecked();
                    //Получаем значение из контекста не вложенной переменной
                    v8::Local<v8::Value> value = context->Global()->Get(context, objname).ToLocalChecked();
                    if (value->IsFunction())
                        functions.push_back(symbols[v8::HeapGraphNode::kObject][i].c_str());
                    else
                    {
                        //Получаем json, соответствующий объекту
                        v8::Local<v8::Object> JSON = globalobj->Get(v8::String::NewFromUtf8(isolate, "JSON",
                                                        v8::NewStringType::kNormal).ToLocalChecked())->ToObject();
                        v8::Local<v8::Function> JSON_stringify = v8::Local<v8::Function>::Cast(JSON->Get(v8::String::NewFromUtf8(isolate, "stringify",
                                                                v8::NewStringType::kNormal).ToLocalChecked()));
                        v8::Local<v8::Value> args[] = {
                                                        value,
                                                        globalobj->Get(v8::String::NewFromUtf8(isolate, "replacer",
                                                        v8::NewStringType::kNormal).ToLocalChecked())->ToObject()
                                                       };

                        v8::Local<v8::Value> jsonvalue = JSON_stringify->Call(JSON, 2, args);
                        if (jsonvalue->IsString())
                        {
                            v8::String::Utf8Value obj(isolate, jsonvalue);
                            variables[symbols[v8::HeapGraphNode::kObject][i]] = *obj;
                        }
                    }
                }
            }

                //Собираем итоговый Json.
                heapdump =
                            "{\n"
                                "\"vars\" : [";
                //Добавляем все переменные
                for (auto it = variables.begin(); it != variables.end(); ++it)
                {
                    if (it->second.compare("undefined") != 0)
                        heapdump += "{\"" + it->first + "\":" + it->second + "},\n";
                }
                heapdump = heapdump.substr(0, heapdump.size()-2);
                //Функции пока отсутствуют
                heapdump +=    "],\n"
                                "\"functions\" : [\n";
                for (i = 0; i < functions.size(); ++i)
                    heapdump += "\"" + functions[i] + "\",\n";
                heapdump = heapdump.substr(0, heapdump.size()-2);
                heapdump +=     "]}";
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

//Внешние переменные
v8::Local<v8::ObjectTemplate> V8Service::MakeMessageTemplate(v8::Isolate* isolate)
{
    v8::EscapableHandleScope handle_scope(isolate);
    v8::Local<v8::ObjectTemplate> result = v8::ObjectTemplate::New(isolate);
    result->SetInternalFieldCount(2);
    //Создаем переменную value
    AddmsgDataFrom(&result, isolate);
    AddmsgDataValue(&result, isolate);
    return handle_scope.Escape(result);
}

v8::Local<v8::Object> V8Service::WrapMessageObject(v8::Isolate* isolate_, Message* obj)
{
    v8::EscapableHandleScope handle_scope(isolate_);
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::ObjectTemplate> raw_template = MakeMessageTemplate(isolate_);
    v8::Local<v8::ObjectTemplate> templ = v8::Local<v8::ObjectTemplate>::New(isolate_, raw_template);
    v8::Local<v8::Object> result = templ->NewInstance(isolate_->GetCurrentContext()).ToLocalChecked();
    v8::Local<v8::External> obj_ptr = v8::External::New(isolate_, obj);
    result->SetInternalField(0, obj_ptr);
    return handle_scope.Escape(result);
}

void V8Service::InstallMessageObject(v8::Isolate* isolate_, Message* data)
{
    v8::HandleScope handle_scope(isolate_);
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::Object> opts_obj = WrapMessageObject(isolate_, data);
    v8::Local<v8::Context> context =
    v8::Local<v8::Context>::New(isolate_, isolate_->GetCurrentContext());
    context->Global()->Set(context,
                            v8::String::NewFromUtf8(isolate_, "msg", v8::NewStringType::kNormal).ToLocalChecked(), opts_obj).FromJust();
}

Message* V8Service::UnwrapObject(v8::Isolate* isolate_, v8::Local<v8::Object> obj)
{
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::External> field = v8::Local<v8::External>::Cast(obj->GetInternalField(0));
    void* ptr = field->Value();
    return static_cast<Message*>(ptr);
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
