#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <locale>

#include "include/libplatform/libplatform.h"
#include "include/v8.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string>

std::string ReadFile(const std::string& path)
{
    std::ifstream input(path, std::ifstream::binary);
    std::string str = "";

    if (input)
    {
        input.seekg(0, input.end);
        size_t length = input.tellg();
        input.seekg(0, input.beg);
        str.resize(length, ' ');
        input.read(&*str.begin(), length);
        input.close();
    }
    return str;
}

//командная строка
enum Mode
{
    SHOW_BYTECODE,
    INS_COUNT,
    MEMORY_USAGE,
    INIT_CONTRACT,
    DUMP_CONTRACT,
    EXTERNAL_TEST
};

struct CmdLine
{
    Mode mode;
    std::string code;
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
        if (mode == EXTERNAL_TEST && argc == 3)
        {
            cmdline.mode = mode;
            cmdline.code.clear();
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
            "3 - initialization of the contract status in the stack\n"
            "4 - read the status of a contract from the stack\n"
            "5 - external variable and function test\n"
            ,
            progname
        );
}

//Вспомогательный класс
class StdCapture
{
public:
    StdCapture(): m_oldStdOut(0), m_oldStdErr(0), m_capturing(false), m_init(false)
    {
        m_pipe[READ] = 0;
        m_pipe[WRITE] = 0;
        if (pipe(m_pipe) == -1)
            return;
        m_oldStdOut = dup(fileno(stdout));
        m_oldStdErr = dup(fileno(stderr));
        if (m_oldStdOut == -1 || m_oldStdErr == -1)
            return;

        m_init = true;
    }

    ~StdCapture()
    {
        if (m_oldStdOut > 0)
            close(m_oldStdOut);
        if (m_oldStdErr > 0)
            close(m_oldStdErr);
        if (m_pipe[READ] > 0)
            close(m_pipe[READ]);
        if (m_pipe[WRITE] > 0)
            close(m_pipe[WRITE]);
    }

    void BeginCapture()
    {
        if (!m_init)
            return;
        if (m_capturing)
            EndCapture();
        fflush(stdout);
        fflush(stderr);
        dup2(m_pipe[WRITE], fileno(stdout));
        dup2(m_pipe[WRITE], fileno(stderr));
        m_capturing = true;
    }

    bool EndCapture()
    {
        if (!m_init)
            return false;
        if (!m_capturing)
            return false;
        fflush(stdout);
        fflush(stderr);
        dup2(m_oldStdOut, fileno(stdout));
        dup2(m_oldStdErr, fileno(stderr));
        m_captured.clear();

        std::string buf;
        const int bufSize = 1024;
        buf.resize(bufSize);
        int bytesRead = 0;
        bytesRead = read(m_pipe[READ], &(*buf.begin()), bufSize);

        while(bytesRead == bufSize)
        {
            m_captured += buf;
            bytesRead = read(m_pipe[READ], &(*buf.begin()), bufSize);
        }
        if (bytesRead > 0)
        {
            buf.resize(bytesRead);
            m_captured += buf;
        }
        return true;
    }

    std::string GetCapture() const
    {
        std::string::size_type idx = m_captured.find_last_not_of("\r\n");
        if (idx == std::string::npos)
            return m_captured;
        else
            return m_captured.substr(0, idx+1);
    }

private:
    enum PIPES { READ, WRITE };
    int m_pipe[2];
    int m_oldStdOut;
    int m_oldStdErr;
    bool m_capturing;
    bool m_init;
    std::string m_captured;
};

std::string GetBytecode(const char* jscode)
{
    StdCapture out;
    out.BeginCapture();
    std::string bytecode;
    //Установка флага вывода байткода
    v8::V8::SetFlagsFromString("--trace-ignition", 16);
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);

        v8::Local<v8::String> source =
        v8::String::NewFromUtf8(isolate,
                        jscode,
                        v8::NewStringType::kNormal).ToLocalChecked();

        v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
        v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

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

void ParseBytecode(const std::string& bytecode, std::unordered_map<std::string, size_t>& instructions)
{
    std::string ins = "";
    std::string remainder = "";
    std::string text = bytecode;
    size_t i,j;

    std::stringstream ss(text);
    std::string item;
    std::vector<std::string> lines;
    while (std::getline(ss, item, (char)0x0A))
        lines.push_back(item);

    for (size_t k = 0; k < lines.size(); ++k)
    {
        i = lines[k].find('@');//Это строка инструкции
        if (i != std::string::npos)
        {
            i += 27;//Указывает на первый байт инструкции.
            j = lines[k].find(' ', i);
            ins = lines[k].substr(i, j-i);

            auto it = instructions.find(ins);
            if (it != instructions.end())
                it->second++;
            else
                instructions[ins] = 1;
        }
    }
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
#include "external/externalfunc.hpp"

void ExternalTest()
{
    std::string jscode = "print(10);";
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

int main(int argc, char* argv[])
{
    v8::V8::InitializeICUDefaultLocation(argv[0]);
    v8::V8::InitializeExternalStartupData(argv[0]);
    std::unique_ptr<v8::Platform> platform =  std::unique_ptr<v8::Platform>(v8::platform::CreateDefaultPlatform());
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();

    CmdLine cmdline;
    std::string bytecode;
    if (ParseCmdLine(argc, argv, cmdline))
    {
        if (cmdline.mode == SHOW_BYTECODE)
        {
            bytecode = GetBytecode(cmdline.code.c_str());
            printf("%s\n", bytecode.c_str());
        }
        if (cmdline.mode == INS_COUNT)
        {
            std::unordered_map<std::string, size_t> instructions;
            bytecode = GetBytecode(cmdline.code.c_str());
            ParseBytecode(bytecode, instructions);
            for (auto it = instructions.begin(); it != instructions.end(); ++it)
                printf("%s = %ld\n", it->first.c_str(),  it->second);
        }
        if (cmdline.mode == MEMORY_USAGE)
        {
            ShowMemoryUsage(cmdline.code);
        }
        if (cmdline.mode == INIT_CONTRACT)
        {
            //InitContractState();
        }
        if (cmdline.mode == EXTERNAL_TEST)
        {
            ExternalTest();
        }
    }
    else
    {
        printf("Invalid command line.\n");
        Usage(argv[0]);
    }

    return 0;
}
