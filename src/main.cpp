#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <locale>

#include <unistd.h>
#include <fcntl.h>

#include "include/libplatform/libplatform.h"
#include "include/v8.h"
#include "include/v8-profiler.h"

#include "utils.h"
#include "stdcapture.hpp"

#include "external/functions/print.hpp"
#include "external/variables/value.hpp"
#include "external/functions/meta_sha256.hpp"
#include "external/functions/meta_MHC_check_sign.hpp"
#include "external/functions/meta_MHC_addr_from_pub_key.hpp"

#include "jsservice.h"

//Лог програмных ошибок и ошибок js
std::ofstream g_errorlog;

//командная строка
enum Mode
{
    SHOW_BYTECODE,
    INS_COUNT,
    MEMORY_USAGE,
    EXTERNAL_TEST,
    SHA256_TEST,
    SIGNATURE_TEST,
    ADDRESS_TEST,
    COMPILE_TEST,
    STATE_TEST,
    SERVICE_RUN,
    SNAPSHOT_DUMP_TEST
};

struct CmdLine
{
    Mode mode;
    std::string code;
    std::string address;
	std::string codecache;
	std::string command;
	std::string insnap;
	std::string outsnap;
	std::string config;
};

bool ParseCmdLine(int argc, char** argv, CmdLine& cmdline)
{
    bool result = false;
    if (argc >= 3 && strcmp(argv[1], "-mode") == 0)
    {
        if (strcmp(argv[2], "bt") == 0 && argc == 5)
        {
            cmdline.mode = SHOW_BYTECODE;
            cmdline.code = ReadFile(argv[4]);
            if (!cmdline.code.empty())
                result = true;
        }
        if (strcmp(argv[2], "btcount") == 0 && argc == 5)
        {
            cmdline.mode = INS_COUNT;
            cmdline.code = ReadFile(argv[4]);
            if (!cmdline.code.empty())
                result = true;
        }
        if (strcmp(argv[2], "mem") == 0 && argc == 5)
        {
            cmdline.mode = MEMORY_USAGE;
            cmdline.code = ReadFile(argv[4]);
            if (!cmdline.code.empty())
                result = true;
        }
        if (strcmp(argv[2], "external") == 0 && argc == 5)
        {
            cmdline.mode = EXTERNAL_TEST;
            cmdline.code = argv[4];
            result = true;
        }

        if (strcmp(argv[2], "sha256") == 0 && argc == 5)
        {
            cmdline.mode = SHA256_TEST;
            cmdline.code = argv[4];
            result = true;
        }
        if (strcmp(argv[2], "newaddr") == 0 && argc == 5)
        {
            cmdline.mode = ADDRESS_TEST;
            cmdline.code = argv[4];
            result = true;
        }
        if (strcmp(argv[2], "sig") == 0 && argc == 3)
        {
            cmdline.mode = SIGNATURE_TEST;
            result = true;
        }
        if (strcmp(argv[2], "compile") == 0 && argc == 7)
        {
            cmdline.mode = COMPILE_TEST;
            cmdline.address = argv[4];
            cmdline.code = ReadFile(argv[6]);
            result = true;
        }
        if (strcmp(argv[2], "run") == 0)
        {
            if (argc == 13)//Инициализация из файла
            {
                if (strcmp(argv[3], "-a") == 0 &&
                    strcmp(argv[5], "-cmd") == 0 &&
                    strcmp(argv[7], "-js") == 0 &&
                    strcmp(argv[9], "-cmpl") == 0 &&
                    strcmp(argv[11], "-snap_o") == 0
                    )
                {
                    cmdline.mode = STATE_TEST;
                    cmdline.address = argv[4];
                    cmdline.code = ReadFile(argv[8]);
                    cmdline.codecache = ReadFile(argv[10]);
                    cmdline.command = ReadFile(argv[6]);
                    cmdline.outsnap = argv[12];
                    result = true;
                }
            }
            else
            {
                if (argc == 11)//Инициализация из снимка
                {
                    if (strcmp(argv[3], "-a") == 0 &&
                        strcmp(argv[5], "-cmd") == 0 &&
                        strcmp(argv[7], "-snap_i") == 0 &&
                        strcmp(argv[9], "-snap_o") == 0
                        )
                    {
                        cmdline.mode = STATE_TEST;
                        cmdline.address = argv[4];
                        cmdline.command = ReadFile(argv[6]);
                        cmdline.insnap = ReadFile(argv[8]);
                        cmdline.outsnap = argv[10];
                        cmdline.code.clear();
                        cmdline.codecache.clear();
                        result = true;
                    }
                }
            }

        }
        if (strcmp(argv[2], "dump") == 0 && argc == 7)
        {
            cmdline.mode = SNAPSHOT_DUMP_TEST;
            cmdline.address = argv[4];
            cmdline.insnap = ReadFile(argv[6]);
            result = true;
        }
        if (strcmp(argv[2], "service") == 0 && argc == 4)
        {
            cmdline.mode = SERVICE_RUN;
            cmdline.config = argv[3];
            result = true;
        }

    }
    return result;
}

void Usage(const char* progname)
{
    printf(
            "Usage: %s \n"
            "-mode bt -js [js file path] - show bytecode\n"
            "-mode btcount -js [js file path] - instructions count\n"
            "-mode mem -js [js file path] - show memory usage\n"
            "-mode external -intarg [integer] - external variable and function test\n"
            "-mode sha256 -strarg [string] - sha256 function test\n"
            "-mode sig - signature test\n"
            "-mode newaddr -strarg [pubkey(hex string)] - address test\n"
            "-mode compile -a ADDR -js FILE.JS - compile test\n"
            "-mode run -a ADDR -cmd run.js -js FILE.JS -cmpl FILE.cmpl -snap_o I_FILE.shot - contract state test(init from file)\n"
            "-mode run -a ADDR -cmd run.js -snap_i I_FILE.shot -snap_o I_FILE.shot - contract state test(init from snapshot)\n"
            "-mode service [config file path] - run program in service mode\n"
            "-mode dump -a ADDR -snap_i [snapshot file path] - dump functions and variables from snapshot\n"
            ,
            progname
        );
}

std::string GetBytecode(const char* jscode, std::string& cmpl)
{
    intptr_t common_references[] = {0};
    StdCapture out;
    std::string bytecode = "";
    cmpl.clear();
    //Установка флага вывода байткода
    v8::V8::SetFlagsFromString("--trace-ignition", 16);
    v8::SnapshotCreator* creator = NULL;
    v8::Isolate* isolate = NULL;
    creator = new v8::SnapshotCreator(common_references);
    isolate = creator->GetIsolate();
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);

        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode,
                                v8::NewStringType::kNormal).ToLocalChecked();
        out.BeginCapture();
        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return "";
        }

        v8::Local<v8::Value> result;
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
        out.EndCapture();
        //Если выполнение удачно, то сохраняем копию компилированного кода
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
            g_errorlog << "(" << __FUNCTION__ << "):Can not create code cache" << std::endl;
        }

        v8::String::Utf8Value utf8(isolate, result);
        bytecode = out.GetCapture();
    }
    delete creator;
    return bytecode;
}

//Измерение колл-ва памяти
std::unordered_map<std::string, int> g_counters;

static int* LookupCounters(const char* name)
{
    static std::unordered_set<std::string> interesting_counters
    {
        "c:V8.OsMemoryAllocated",
        "c:V8.ZoneSegmentBytes",
    };

    if (interesting_counters.find(name) != interesting_counters.end())
    {
        auto it = g_counters.find(name);
        if (it == g_counters.end())
            return &g_counters.emplace(name, 0).first->second;
        else
            return &it->second;
    }

    return NULL;
}

void SetupCounters(v8::Isolate* isolate)
{
    isolate->Enter();
    isolate->SetCounterFunction(LookupCounters);
    isolate->Exit();
}

void DumpCounters(v8::Isolate* isolate)
{
    v8::HeapStatistics heapstat;
    {
        v8::Locker lock(isolate);
        v8::Isolate::Scope scope(isolate);
        isolate->GetHeapStatistics(&heapstat);
    }
    printf("Total heap size = %ld\n", heapstat.total_heap_size());
    if (!g_counters.empty())
    {
        for (auto it : g_counters)
            printf("%s = %d\n", it.first.c_str(), it.second);
    }
    else
        g_errorlog << "(" << __FUNCTION__ << "):Memory counters not found" << std::endl;
}

void RunScript(v8::Isolate* isolate, const std::string& code)
{
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::TryCatch try_catch(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source =
    v8::String::NewFromUtf8(isolate,
                    code.c_str(),
                    v8::NewStringType::kNormal).ToLocalChecked();

    v8::Local<v8::Script> script;
    if (!v8::Script::Compile(context, source).ToLocal(&script))
    {
        v8::String::Utf8Value error(isolate, try_catch.Exception());
        g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
        return;
    }

    v8::Local<v8::Value> result;
    if (!script->Run(context).ToLocal(&result))
    {
        v8::Local<v8::Value> val = try_catch.Exception();
        if (!val->IsTrue())
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
        }
    }
}

void ShowMemoryUsage(const std::string& code)
{
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    SetupCounters(isolate);
    RunScript(isolate, code);
    DumpCounters(isolate);
}

//Тест внешней функции и переменной
v8::Local<v8::ObjectTemplate> MakeObjectTemplate(v8::Isolate* isolate)
{
    v8::EscapableHandleScope handle_scope(isolate);
    v8::Local<v8::ObjectTemplate> result = v8::ObjectTemplate::New(isolate);
    result->SetInternalFieldCount(1);
    //Создаем переменную value
    AddDataValue(&result, isolate);
    return handle_scope.Escape(result);
}

v8::Local<v8::Object> WrapObject(v8::Isolate* isolate_, Data* obj)
{
    v8::EscapableHandleScope handle_scope(isolate_);
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::ObjectTemplate> raw_template = MakeObjectTemplate(isolate_);
    v8::Local<v8::ObjectTemplate> templ = v8::Local<v8::ObjectTemplate>::New(isolate_, raw_template);
    v8::Local<v8::Object> result = templ->NewInstance(isolate_->GetCurrentContext()).ToLocalChecked();
    v8::Local<v8::External> obj_ptr = v8::External::New(isolate_, obj);
    result->SetInternalField(0, obj_ptr);
    return handle_scope.Escape(result);
}

void InstallObjects(v8::Isolate* isolate_, Data* data)
{
    v8::HandleScope handle_scope(isolate_);
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::Object> opts_obj = WrapObject(isolate_, data);
    v8::Local<v8::Context> context =
    v8::Local<v8::Context>::New(isolate_, isolate_->GetCurrentContext());
    context->Global()->Set(context,
                            v8::String::NewFromUtf8(isolate_, "Data", v8::NewStringType::kNormal).ToLocalChecked(), opts_obj).FromJust();
}

void ExternalTest(const std::string& code)
{
    Data data;
    data.value = std::stoi(code);
    std::string jscode = "print(Data.value)";
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        //Регистрируем функцию печати
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        //Устанавливаем объект типа Data как внешнюю переменную
        InstallObjects(isolate, &data);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return;
        }

        v8::Local<v8::Value> result;
        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
            }
        }
    }
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;
}

//Тест sha256
void SHA256Test(const std::string& data)
{
    std::string jscode = "print(meta_sha256(\"" + data + "\"));";
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddSHA256(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return;
        }

        v8::Local<v8::Value> result;
        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
            }
        }
    }
    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;
}

//Тест функции проверки сигнатуры
void SignatureCheckTest()
{
    std::string jscode = "";
    //Собираем код
    std::string hex_pubkey = "3059301306072a8648ce3d020106082a8648ce3d0301070342000439bb171cffe714dcea16ca9c7d76dc6d305a1bcdb1fb062c2b95101d03da91bec12bc320e2f137df309f7f4e89c4336a575178b13b70da906cb2d38aa01c6d7c";
    std::string hex_sign = "1059e0e4e99fc4b974455f75b95abd2eb82c03a4720de2d8dcdc3e09159803c2f81665fc45f6359e5b3d5737b76c22fb83bb2c3cdb74330d6ce3ac8418911369";
    std::string data = "data for test";
    jscode = "var pubkey = \"" + hex_pubkey + "\";\n";
    jscode += "var sign = \"" + hex_sign + "\";\n";
    jscode += "var data = \"" + data + "\";\n";
    jscode += "if (meta_MHC_check_sign(pubkey, sign, data))\n";
    jscode += "print(\"Verified OK.\");\nelse\n";
    jscode += "print(\"Signature virification error.\");";

    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddCheckSign(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return;
        }

        v8::Local<v8::Value> result;
        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
            }
        }
    }
    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;
}

//Тест функции генерации адреса
void CreateAddressTest(const std::string& hex_pubkey)
{
    std::string jscode = "print(meta_MHC_addr_from_pub_key(\"" + hex_pubkey + "\"))";

    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::TryCatch try_catch(isolate);
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddAddressFromPubkey(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
            return;
        }

        v8::Local<v8::Value> result;
        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
            }
        }
    }
    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;
}

//Тест компиляции
void CompileTest(const std::string& address, const std::string& code)
{
    std::string dbgfilepath = address + ".dbgi";
    std::string btfilepath = address + ".bc";
    std::string cmplfilepath = address + ".cmpl";
    std::ofstream dbgfile(dbgfilepath, std::ios::out | std::ios::app);
    std::ofstream btfile(btfilepath, std::ios::out | std::ios::app);
    std::ofstream cmplfile(cmplfilepath, std::ios::out | std::ios::app);
    if (!dbgfile || !btfile || !cmplfile)
    {
        printf("Open output files error.\n");
        return;
    }

    std::string debuglog = "";
    std::string cmpl = "";
    std::string bytecode = GetBytecode(code.c_str(), cmpl);
    if (!bytecode.empty())//Произошла ошибка выполнения
    {
        dbgfile << bytecode;
        btfile << BytecodeToListing(bytecode);
        if (!cmpl.empty())//Ошибок при создании компилированного кода тоже не было
        {
            //Cохраняем компилированный скрипт в ADDR.cmpl
            cmplfile << cmpl;
        }
    }
    dbgfile.close();
    btfile.close();
    cmplfile.close();
}

void ContractStateTest(const CmdLine& cmdline)
{
    intptr_t common_references[] = {0};
    v8::StartupData blob;
    {
        //Проверяем есть ли входной снимок
        v8::SnapshotCreator* creator = NULL;
        v8::Isolate::CreateParams params;
        v8::Isolate* isolate = NULL;
        if (!cmdline.insnap.empty())
        {
            //Инициализация состояния из снимка
            blob.data = cmdline.insnap.data();
            blob.raw_size = cmdline.insnap.size();
            creator = new v8::SnapshotCreator(common_references, &blob);
            isolate = creator->GetIsolate();
        }
        else
        {
            creator = new v8::SnapshotCreator(common_references);
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

            //Инициализация состояния из файла
            if (!cmdline.code.empty())
            {
                v8::Local<v8::String> initsource =
                v8::String::NewFromUtf8(isolate,
                                        cmdline.code.c_str(),
                                        v8::NewStringType::kNormal).ToLocalChecked();

                //Компилируем контракт с кэшем его кода
                v8::ScriptCompiler::CachedData* cache = new v8::ScriptCompiler::CachedData((const uint8_t*)cmdline.codecache.data(),
                                                            cmdline.codecache.size(),
                                                            v8::ScriptCompiler::CachedData::BufferNotOwned);

                v8::Local<v8::Value> testresult;
                v8::ScriptOrigin origin(v8::String::NewFromUtf8(isolate,
                                        "test",
                                        v8::NewStringType::kNormal).ToLocalChecked());
                v8::ScriptCompiler::Source src(initsource, origin, cache);
                v8::Local<v8::UnboundScript> unboundscript = v8::ScriptCompiler::CompileUnboundScript(isolate,
                                                            &src, v8::ScriptCompiler::kConsumeCodeCache).ToLocalChecked();

                if (!unboundscript->BindToCurrentContext()->Run(context).ToLocal(&result))
                {
                    v8::Local<v8::Value> val = try_catch.Exception();
                    if (!val->IsTrue())
                    {
                        v8::String::Utf8Value error(isolate, try_catch.Exception());
                        g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
                        return;
                    }
                }
            }

            //Компилируем и выполняем код из run.js
            v8::Local<v8::String> cmdsource =
            v8::String::NewFromUtf8(isolate,
                                    cmdline.command.c_str(),
                                    v8::NewStringType::kNormal).ToLocalChecked();
            v8::Local<v8::Script> cmdscript;
            if (!v8::Script::Compile(context, cmdsource).ToLocal(&cmdscript))
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                g_errorlog << "Compile error(" << __FUNCTION__ << "):" << *error << std::endl;
                return;
            }

            if (!cmdscript->Run(context).ToLocal(&result))
            {
                v8::Local<v8::Value> val = try_catch.Exception();
                if (!val->IsTrue())
                {
                    v8::String::Utf8Value error(isolate, try_catch.Exception());
                    g_errorlog << "Run error(" << __FUNCTION__ << "):" << *error << std::endl;
                    return;
                }
            }
            else
            {
                v8::String::Utf8Value utf8(isolate, result);
                g_errorlog << __FUNCTION__ << ":" << *utf8 << std::endl;
            }
        }
        //Если все прошло удачно, то выгружаем итоговый снимок.
        std::ofstream snapout(cmdline.outsnap.c_str(), std::ios::out | std::ios::app);
        //Запрашиваем сборку мусора перед созданием снимка
        blob = creator->CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
        snapout.write(blob.data, blob.raw_size);
        snapout.close();
        if (creator)
            delete creator;
    }
}

//Тест разбора содержимого снимка
//Версия с JSON::Stringify
void SnapshotDumpTest(const CmdLine& cmdline)
{
    intptr_t common_references[] = {0};
    v8::StartupData blob;
    v8::SnapshotCreator* creator = NULL;
    v8::Isolate* isolate = NULL;
    blob.data = cmdline.insnap.data();
    blob.raw_size = cmdline.insnap.size();
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
                return;
            }
            //Определяем replacer в текущем контексте
            if (!rplscript->Run(context).ToLocal(&result))
            {
                v8::Local<v8::Value> val = try_catch.Exception();
                if (!val->IsTrue())
                {
                    v8::String::Utf8Value error(isolate, try_catch.Exception());
                    g_errorlog << "Replacer run error(" << __FUNCTION__ << "):" << *error << std::endl;
                    return;
                }
            }
            else
            {
                v8::String::Utf8Value utf8(isolate, result);
                g_errorlog << __FUNCTION__ << ":" << *utf8 << std::endl;
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
            std::string heapdump =
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
            printf("%s\n", heapdump.c_str());
        }
    }
}


int main(int argc, char* argv[])
{
    g_errorlog.open ("err.log", std::ofstream::out | std::ofstream::app);
    if (!g_errorlog)
    {
        printf("Can not open error log.\n");
        return 0;
    }

    v8::V8::InitializeICUDefaultLocation(argv[0]);
    v8::V8::InitializeExternalStartupData(argv[0]);
    std::unique_ptr<v8::Platform> platform =  std::unique_ptr<v8::Platform>(v8::platform::CreateDefaultPlatform());
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    CmdLine cmdline;
    std::string bytecode;
    std::string cmpl;
    if (ParseCmdLine(argc, argv, cmdline))
    {
        if (cmdline.mode == SHOW_BYTECODE)
        {
            bytecode = GetBytecode(cmdline.code.c_str(), cmpl);
            if (!bytecode.empty())
                printf("%s\n", bytecode.c_str());
        }
        if (cmdline.mode == INS_COUNT)
        {
            std::unordered_map<std::string, size_t> instructions;
            bytecode = GetBytecode(cmdline.code.c_str(), cmpl);
            if (!bytecode.empty())
            {
                ParseBytecode(bytecode, instructions);
                for (auto it = instructions.begin(); it != instructions.end(); ++it)
                    printf("%s = %ld\n", it->first.c_str(),  it->second);
            }
        }
        if (cmdline.mode == MEMORY_USAGE)
            ShowMemoryUsage(cmdline.code);
        if (cmdline.mode == EXTERNAL_TEST)
            ExternalTest(cmdline.code);
        if (cmdline.mode == SHA256_TEST)
            SHA256Test(cmdline.code);
        if (cmdline.mode == SIGNATURE_TEST)
            SignatureCheckTest();
        if (cmdline.mode == ADDRESS_TEST)
            CreateAddressTest(cmdline.code);
        if (cmdline.mode == COMPILE_TEST)
            CompileTest(cmdline.address, cmdline.code);
        if (cmdline.mode == STATE_TEST)
            ContractStateTest(cmdline);
        if (cmdline.mode == SERVICE_RUN)
            RunV8Service(cmdline.config.c_str());
        if (cmdline.mode == SNAPSHOT_DUMP_TEST)
            SnapshotDumpTest(cmdline);
    }
    else
    {
        printf("Invalid command line.\n");
        Usage(argv[0]);
    }
    g_errorlog.close();
    return 0;
}
