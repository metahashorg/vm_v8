#include <include/libplatform/libplatform.h>
#include <include/v8.h>

#ifndef PRINT_FUNCTION
#define PRINT_FUNCTION

extern std::ofstream g_errorlog;

void print(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if (args.Length() != 1)
    {
        g_errorlog << "Invalid arguments(" << __FUNCTION__ << ")" << std::endl;
        return;
    }

    v8::Isolate* isolate = args.GetIsolate();
    v8::TryCatch try_catch(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Value> arg = args[0];
    if(arg->IsUint32())
    {
        int val = arg->ToUint32(isolate->GetCurrentContext()).ToLocalChecked()->Value();
        printf("%d\n", val);
    }
    else
    {
        if (arg->IsString())
        {
            v8::String::Utf8Value param1(arg->ToString());
            printf("%s\n", *param1);
        }
        else
            g_errorlog << "Invalid argument type(" << __FUNCTION__ << ")" << std::endl;
    }
}

void AddPrint(v8::Local<v8::ObjectTemplate>* global, v8::Isolate* isolate)
{
    v8::Local<v8::FunctionTemplate> printfunc = v8::FunctionTemplate::New(isolate, print);
    (*global)->Set(v8::String::NewFromUtf8(isolate, "print"), printfunc);
}

#endif
