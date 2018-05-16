#include <include/libplatform/libplatform.h>
#include <include/v8.h>

#ifndef TEST_VARIABLE
#define TEST_VARIABLE

struct Data
{
    size_t value;
};

void GetValue(v8::Local<v8::String> property,
               const v8::PropertyCallbackInfo<v8::Value>& info)
{
    v8::TryCatch try_catch(info.GetIsolate());
    v8::Local<v8::Object> self = info.Holder();
    v8::Local<v8::External> wrap = v8::Local<v8::External>::Cast(self->GetInternalField(0));
    void* ptr = wrap->Value();
    int value = static_cast<Data*>(ptr)->value;
    info.GetReturnValue().Set(value);
}

void SetValue(v8::Local<v8::String> property, v8::Local<v8::Value> value,
               const v8::PropertyCallbackInfo<void>& info)
{
    v8::TryCatch try_catch(info.GetIsolate());
    v8::Local<v8::Object> self = info.Holder();
    v8::Local<v8::External> wrap = v8::Local<v8::External>::Cast(self->GetInternalField(0));
    void* ptr = wrap->Value();
    static_cast<Data*>(ptr)->value = value->Int32Value();
}

void AddDataValue(v8::Local<v8::ObjectTemplate>* tpl, v8::Isolate* isolate)
{
    (*tpl)->SetAccessor(v8::String::NewFromUtf8(isolate, "value"), GetValue, SetValue);
}

#endif
