/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef JSON_WRAPPER_H
#define JSON_WRAPPER_H

#include <glog/logging.h>
#include <json/json.h>
#undef TRUE  // json.h pollution
#undef FALSE  // json.h pollution
#include <netinet/in.h>  // for resolv.h
#include <resolv.h>  // for b64_ntop

#include <sstream>

class JsonArray;

// It appears that a new object, e.g. from a string, has a reference count
// of 1, and that any objects "got" from it will get freed when it is freed.

// Note that a JsonObject that is not Ok() should not be used for anything.
class JsonObject {
 public:
  explicit JsonObject(json_object *obj) : obj_(obj) {}

  explicit JsonObject(const std::ostringstream &response) {
    obj_ = json_tokener_parse(response.str().c_str());
  }

  explicit JsonObject(const std::string &response) {
    obj_ = json_tokener_parse(response.c_str());
  }

  JsonObject(const JsonArray &from, int offset,
             json_type type = json_type_object);

  JsonObject() : obj_(NULL) {}

  ~JsonObject() {
    if (obj_)
        json_object_put(obj_);
  }

  // Get the object out, and stop tracking it so we _won't_ put() it
  // when we are destroyed. The caller needs to ensure it is freed.
  json_object *Extract() {
    json_object *tmp = obj_;
    obj_ = NULL;
    return tmp;
  }

  bool Ok() const { return obj_ != NULL; }

  bool IsType(json_type type) const { return json_object_is_type(obj_, type); }

  const char *ToJson() const {
    return json_object_to_json_string(obj_);
  }

 protected:
  JsonObject(const JsonObject &from, const char *field, json_type type) {
    obj_ = json_object_object_get(from.obj_, field);
    if (obj_ != NULL) {
      if (!json_object_is_type(obj_, type)) {
        LOG(ERROR) << "Don't understand " << field << " field: "
                   << from.ToJson();
        obj_ = NULL;
        return;
      }
    } else {
      LOG(ERROR) << "No " << field << " field";
      return;
    }
    // Increment reference count
    json_object_get(obj_);
  }

  json_object *obj_;

};

class JsonBoolean : public JsonObject {
 public:
  JsonBoolean(const JsonObject &from, const char *field)
    : JsonObject(from, field, json_type_boolean) {}

  bool Value() { return json_object_get_boolean(obj_); }
};

class JsonString : public JsonObject {
 public:
  JsonString(const JsonObject &from, const char *field)
    : JsonObject(from, field, json_type_string) {}

  JsonString(const JsonArray &from, int offset)
    : JsonObject(from, offset, json_type_string) {}

  const char *Value() { return json_object_get_string(obj_); }

  std::string FromBase64() {
    const char *value = Value();
    size_t length = strlen(value);
    // Lazy: base 64 encoding is always >= in length to decoded value
    // (equality occurs for zero length).
    u_char buf[length];
    length = b64_pton(value, buf, length);
    return std::string((char *)buf, length);
  }
    
};

class JsonInt : public JsonObject {
 public:
  explicit JsonInt(json_object *jint) : JsonObject(jint) {}
  JsonInt(const JsonObject &from, const char *field)
    : JsonObject(from, field, json_type_int) {}

  int64_t Value() const { return json_object_get_int64(obj_); }
};

class JsonArray : public JsonObject {
 public:
  JsonArray(const JsonObject &from, const char *field)
    : JsonObject(from, field, json_type_array) {}

  JsonArray() {
    obj_ = json_object_new_array();
  }

  void Add(json_object *addand) {
    json_object_array_add(obj_, addand);
  }

  int Length() const { return json_object_array_length(obj_); }
};

JsonObject::JsonObject(const JsonArray &from, int offset, json_type type) {
  obj_ = json_object_array_get_idx(from.obj_, offset);
  if (obj_ != NULL) {
    if (!json_object_is_type(obj_, type)) {
      LOG(ERROR) << "Don't understand index " << offset << ": "
                 << from.ToJson();
      obj_ = NULL;
      return;
    }
  } else {
    LOG(ERROR) << "No index " << offset;
    return;
  }
  json_object_get(obj_);
}

std::string ToBase64(const std::string &from) {
  // base 64 is 4 output bytes for every 3 input bytes (rounded up).
  size_t length = ((from.size() + 2) / 3) * 4;
  char buf[length + 1];
  length = b64_ntop((const u_char *)from.data(), from.length(), buf,
                    length + 1);
  return std::string((char *)buf, length);
}

#endif
