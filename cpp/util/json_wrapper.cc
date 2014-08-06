#include "json_wrapper.h"


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
