#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <locale>

#include <unistd.h>
#include <fcntl.h>

#include "include/libplatform/libplatform.h"
#include "include/v8.h"

#include "utils.h"
#include "stdcapture.hpp"

#include "external/functions/print.hpp"
#include "external/variables/value.hpp"
#include "external/functions/meta_sha256.hpp"
#include "external/functions/meta_MHC_check_sign.hpp"
#include "external/functions/meta_MHC_addr_from_pub_key.hpp"

//командная строка
enum Mode
{
    SHOW_BYTECODE,
    INS_COUNT,
    MEMORY_USAGE,
    INIT_CONTRACT,
    DUMP_CONTRACT,
    EXTERNAL_TEST,
    SHA256_TEST,
    SIGNATURE_TEST,
    ADDRESS_TEST,
    COMPILE_TEST
};

struct CmdLine
{
    Mode mode;
    std::string code;
    std::string address;
};

bool ParseCmdLine(int argc, char** argv, CmdLine& cmdline)
{
    bool result = false;
    if (argc >= 3 && strcmp(argv[1], "-mode") == 0)
    {
        Mode mode = (Mode)atoi(argv[2]);
        if ( (mode == SHOW_BYTECODE && argc == 4) ||
             (mode == INS_COUNT && argc == 4) ||
             (mode == MEMORY_USAGE && argc == 4)
            )
        {
            cmdline.mode = mode;
            cmdline.code = ReadFile(argv[3]);
            if (!cmdline.code.empty())
                result = true;
        }
        if (mode == INIT_CONTRACT && argc == 3)
        {
            cmdline.mode = mode;
            cmdline.code.clear();
            result = true;
        }
        if ( (mode == EXTERNAL_TEST && argc == 4) ||
            (mode == SHA256_TEST && argc == 4) ||
            (mode == ADDRESS_TEST && argc == 4) )
        {
            cmdline.mode = mode;
            cmdline.code = argv[3];
            result = true;
        }
        if (mode == SIGNATURE_TEST && argc == 3)
        {
            cmdline.mode = mode;
            result = true;
        }
        if (mode == COMPILE_TEST && argc == 5)
        {
            cmdline.mode = mode;
            cmdline.address = argv[3];
            cmdline.code = ReadFile(argv[4]);
            result = true;
        }
    }
    return result;
}

void Usage(const char* progname)
{
    printf(
            "Usage: ./%s -mode [0-2] [js file path]\n"
            "0 - show bytecode\n"
            "1 - instructions count\n"
            "2 - show memory usage\n"
            "3 - initialization of the contract status in the stack (Not ready yet)\n"
            "4 - read the status of a contract from the stack\n"
            "5 - external variable and function test\n"
            "6 - sha256 function test\n"
            "7 - signature test\n"
            "8 - address test\n"
            "9 - compile test\n"
            ,
            progname
        );
}

std::string GetBytecode(const char* jscode, std::string& err, std::string& cmpl)
{
    StdCapture out;
    out.BeginCapture();
    std::string bytecode = "";
    err.clear();
    cmpl.clear();
    //Установка флага вывода байткода
    v8::V8::SetFlagsFromString("--trace-ignition", 16);
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
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

        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script))
        {
            v8::String::Utf8Value error(isolate, try_catch.Exception());
            err = *error;
            return "";
        }

        v8::Local<v8::Value> result;
        if (!script->Run(context).ToLocal(&result))
        {
            v8::Local<v8::Value> val = try_catch.Exception();
            if (!val->IsTrue())
            {
                v8::String::Utf8Value error(isolate, try_catch.Exception());
                err = *error;
                return "";
            }
        }

        //Если выполнение удачно, то сохраняем копию компилированного кода
        v8::Local<v8::Value> testresult;
        v8::ScriptOrigin origin(v8::String::NewFromUtf8(isolate,
                                "test",
                                v8::NewStringType::kNormal).ToLocalChecked());
        v8::ScriptCompiler::Source src(source, origin);
        v8::Local<v8::UnboundScript> unboundscript = v8::ScriptCompiler::CompileUnboundScript(isolate, &src, v8::ScriptCompiler::kProduceFullCodeCache).ToLocalChecked();
        v8::ScriptCompiler::CachedData* data = v8::ScriptCompiler::CreateCodeCache(unboundscript);
        if (data && data->length)
        {
            cmpl.resize(data->length);
            memcpy((void*)cmpl.data(), data->data, data->length);
        }
        else
            err += "Can not create code cache\n";

        v8::String::Utf8Value utf8(isolate, result);
        out.EndCapture();
        bytecode = out.GetCapture();
    }

    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;
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
}

void RunScript(v8::Isolate* isolate, const std::string& code)
{
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source =
    v8::String::NewFromUtf8(isolate,
                    code.c_str(),
                    v8::NewStringType::kNormal).ToLocalChecked();

    v8::Local<v8::Script> script =
    v8::Script::Compile(context, source).ToLocalChecked();
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
    (void)result;
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
v8::Global<v8::Context> context_;
v8::Global<v8::ObjectTemplate> global_template_;

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
    if (global_template_.IsEmpty())
    {
        v8::Local<v8::ObjectTemplate> raw_template = MakeObjectTemplate(isolate_);
        global_template_.Reset(isolate_, raw_template);
    }
    v8::Local<v8::ObjectTemplate> templ = v8::Local<v8::ObjectTemplate>::New(isolate_, global_template_);
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
    v8::Local<v8::Context>::New(isolate_, context_);
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
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        //Регистрируем функцию печати
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        context_.Reset(isolate, context);
        //Устанавливаем объект типа Data кака переменную
        InstallObjects(isolate, &data);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
        script->Run(context).ToLocalChecked();
    }
    //isolate->Dispose();
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
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddSHA256(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
        script->Run(context).ToLocalChecked();
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
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddCheckSign(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
        script->Run(context).ToLocalChecked();
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
        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
        AddAddressFromPubkey(&global, isolate);
        AddPrint(&global, isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate, NULL, global);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                                jscode.c_str(),
                                v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
        script->Run(context).ToLocalChecked();
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
    std::string err = "";
    std::string cmpl = "";
    std::string bytecode = GetBytecode(code.c_str(), err, cmpl);
    if (!bytecode.empty())//Произошла ошибка выполнения
    {
        //Создаем файл с байткодом
        dbgfile << bytecode;
        btfile << BytecodeToListing(bytecode);
        if (err.empty())//Ошибок при создании компилированного кода тоже не было
        {
            //Cохраняем компилированный скрипт в ADDR.cmpl
            cmplfile << cmpl;
        }
    }
    dbgfile.close();
    btfile.close();
    cmplfile.close();
}

int main(int argc, char* argv[])
{
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
    std::string err;
    std::string cmpl;
    if (ParseCmdLine(argc, argv, cmdline))
    {
        if (cmdline.mode == SHOW_BYTECODE)
        {
            bytecode = GetBytecode(cmdline.code.c_str(), err, cmpl);
            printf("%s\n", bytecode.c_str());
        }
        if (cmdline.mode == INS_COUNT)
        {
            std::unordered_map<std::string, size_t> instructions;
            bytecode = GetBytecode(cmdline.code.c_str(), err, cmpl);
            ParseBytecode(bytecode, instructions);
            for (auto it = instructions.begin(); it != instructions.end(); ++it)
                printf("%s = %ld\n", it->first.c_str(),  it->second);
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
    }
    else
    {
        printf("Invalid command line.\n");
        Usage(argv[0]);
    }

    return 0;
}
