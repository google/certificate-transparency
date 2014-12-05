#include "util/fake_etcd.h"

#include <glog/logging.h>

#include "util/json_wrapper.h"

namespace cert_trans {
namespace {


std::string EnsureEndsWithSlash(const std::string& s) {
  if (s.empty() || s.back() != '/') {
    return s + '/';
  } else {
    return s;
  }
}


}  // namespace


class FakeEtcdClient::FakeWatcher : public EtcdClient::Watcher {
 public:
  FakeWatcher(FakeEtcdClient* client, const std::string& key,
              const WatchCallback& cb);

  virtual ~FakeWatcher();

 private:
  FakeEtcdClient* const client_;
  const std::string key_;
  const WatchCallback cb_;
};


FakeEtcdClient::FakeWatcher::FakeWatcher(FakeEtcdClient* client,
                                         const std::string& key,
                                         const WatchCallback& cb)
    : client_(client), key_(key), cb_(cb) {
  std::vector<Update> initial_updates;
  for (const auto& pair : client_->entries_) {
    if (pair.first.find(key_) == 0) {
      initial_updates.push_back(Update(pair.second, true /*exists*/));
    }
  }
  client_->ScheduleCallback(std::bind(cb_, initial_updates));
  client_->watches_[key_].push_back(
      std::make_pair(cb_, static_cast<void*>(this)));
}


FakeEtcdClient::FakeWatcher::~FakeWatcher() {
  client_->RemoveWatcher(static_cast<void*>(this));
}


FakeEtcdClient::FakeEtcdClient() : index_(1), pool_(1) {
}


void FakeEtcdClient::DumpEntries() {
  for (const auto& pair : entries_) {
    VLOG(1) << pair.second.ToString();
  }
}


EtcdClient::Watcher* FakeEtcdClient::CreateWatcher(
    const std::string& key, const Watcher::WatchCallback& cb) {
  return new FakeWatcher(this, key, cb);
}


void FakeEtcdClient::Generic(const std::string& key,
                             const std::map<std::string, std::string>& params,
                             evhttp_cmd_type verb, const GenericCallback& cb) {
  PurgeExpiredEntries();
  switch (verb) {
    case EVHTTP_REQ_GET:
      HandleGet(key, params, cb);
      break;
    case EVHTTP_REQ_POST:
      HandlePost(key, params, cb);
      break;
    case EVHTTP_REQ_PUT:
      HandlePut(key, params, cb);
      break;
    case EVHTTP_REQ_DELETE:
      HandleDelete(key, params, cb);
      break;
    default:
      CHECK(false) << "Unsupported verb " << verb;
  }
  DumpEntries();
}


// TODO(alcutter): replace these with building a JsonObject directly.
std::string JsonForNode(const EtcdClient::Node& node) {
  std::ostringstream oss;
  oss << "{\n"
      << "  \"modifiedIndex\" : " << std::to_string(node.modified_index_)
      << ",\n"
      << "  \"createdIndex\" : " << std::to_string(node.created_index_)
      << ",\n"
      << "  \"key\": \"" << node.key_ << "\",\n";
  if (!node.deleted_) {
    oss << "  \"value\" : \"" << node.value_ << "\"\n";
  }
  oss << "}\n";
  return oss.str();
}


std::string JsonForEntry(const EtcdClient::Node& node,
                         const std::string& action) {
  std::ostringstream oss;
  oss << "{ \"node\" : " << JsonForNode(node) << ",\n"
      << "  \"action\" : \"" << action << "\"\n"
      << "}";
  return oss.str();
}


std::string JsonForDir(const std::vector<EtcdClient::Node>& nodes,
                       const std::string& action) {
  std::ostringstream oss;
  oss << "{\n\"node\" : \n{"
      << "  \"createdIndex\" : 1,\n"
      << "  \"modifiedIndex\" : 1,\n"
      << "  \"dir\" : true,\n";
  if (nodes.size() > 0) {
    oss << "  \"nodes\" : [\n";
    for (const auto& node : nodes) {
      oss << JsonForNode(node) << ", ";
    }
    oss << "  ]\n";
  }
  oss << "  \"action\" : \"" << action << "\",\n"
      << "  }\n"
      << "}";
  return oss.str();
}


void FakeEtcdClient::PurgeExpiredEntries() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires_ < std::chrono::system_clock::now()) {
      VLOG(1) << "Deleting expired entry " << it->first;
      it->second.deleted_ = true;
      NotifyForPath(it->first);
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
}


void FakeEtcdClient::NotifyForPath(const std::string& path) {
  VLOG(1) << "notifying " << path;
  const bool exists(entries_.find(path) != entries_.end());
  CHECK(exists);
  const Node& node(entries_.find(path)->second);
  for (const auto& pair : watches_) {
    if (path.find(pair.first) == 0) {
      for (const auto& cb_cookie : pair.second) {
        ScheduleCallback(
            std::bind(cb_cookie.first,
                      std::vector<Watcher::Update>{
                          Watcher::Update(node, !node.deleted_)}));
      }
    }
  }
}


void FakeEtcdClient::GetSingleEntry(const std::string& key,
                                    const GenericCallback& cb) {
  if (entries_.find(key) != entries_.end()) {
    const Node& node(entries_.find(key)->second);
    return ScheduleCallback(
        std::bind(cb, util::Status::OK,
                  std::make_shared<JsonObject>(JsonForEntry(node, "get")),
                  index_));
  } else {
    return ScheduleCallback(
        std::bind(cb, util::Status(util::error::NOT_FOUND, "not found"),
                  std::make_shared<JsonObject>(), index_));
  }
}


void FakeEtcdClient::GetDirectory(const std::string& key,
                                  const GenericCallback& cb) {
  VLOG(1) << "GET DIR";
  CHECK(key.back() == '/');
  std::vector<Node> nodes;
  for (const auto& pair : entries_) {
    if (pair.first.find(key) == 0) {
      nodes.push_back(pair.second);
    }
  }
  VLOG(1) << "..";
  const std::string json(JsonForDir(nodes, "get"));
  VLOG(1) << "GET DIR " << key << " : " << json;
  return ScheduleCallback(std::bind(cb, util::Status::OK,
                                    std::make_shared<JsonObject>(json),
                                    index_));
}


void FakeEtcdClient::HandleGet(
    const std::string& key, const std::map<std::string, std::string>& params,
    const GenericCallback& cb) {
  VLOG(1) << "GET " << key;
  std::lock_guard<std::mutex> lock(mutex_);
  if (key.back() == '/') {
    return GetDirectory(key, cb);
  } else {
    return GetSingleEntry(key, cb);
  }
}


void MaybeSetExpiry(const std::map<std::string, std::string>& params,
                    EtcdClient::Node* node) {
  if (params.find("ttl") != params.end()) {
    const std::string& ttl(params.find("ttl")->second);
    node->expires_ = std::chrono::system_clock::now() +
                     std::chrono::duration<int>(std::stoi(ttl));
  }
}


bool GetParam(const std::map<std::string, std::string>& params,
              const std::string& name, std::string* out) {
  if (params.find(name) == params.end()) {
    return false;
  }
  *out = params.find(name)->second;
  return true;
}


util::Status FakeEtcdClient::CheckCompareFlags(
    const std::map<std::string, std::string> params, const std::string& key) {
  const bool entry_exists(entries_.find(key) != entries_.end());
  std::string prev_exist;
  if (GetParam(params, "prevExist", &prev_exist)) {
    if (entry_exists && prev_exist == "false") {
      return util::Status(util::error::FAILED_PRECONDITION,
                          key + " Already exists");
    } else if (!entry_exists && prev_exist == "true") {
      return util::Status(util::error::FAILED_PRECONDITION,
                          key + " Not found");
    }
  }
  std::string prev_index;
  if (GetParam(params, "prevIndex", &prev_index)) {
    if (!entry_exists) {
      return util::Status(util::error::FAILED_PRECONDITION,
                          "Node doesn't exist: " + key);
    }
    const std::string modified_index(
        std::to_string(entries_[key].modified_index_));
    if (prev_index != modified_index) {
      return util::Status(util::error::FAILED_PRECONDITION,
                          "Incorrect index:  prevIndex=" + prev_index +
                              " but modified_index_=" + modified_index);
    }
  }
  return util::Status::OK;
}


void FakeEtcdClient::HandlePost(
    const std::string& key, const std::map<std::string, std::string>& params,
    const GenericCallback& cb) {
  VLOG(1) << "POST " << key;
  std::lock_guard<std::mutex> lock(mutex_);
  const std::string path(EnsureEndsWithSlash(key) + std::to_string(index_));
  CHECK(params.find("value") != params.end());
  const std::string& value(params.find("value")->second);
  Node node(index_, index_, path, value);
  MaybeSetExpiry(params, &node);
  entries_[path] = node;

  ++index_;
  ScheduleCallback(
      std::bind(cb, util::Status::OK,
                std::make_shared<JsonObject>(JsonForEntry(node, "create")),
                index_));
  NotifyForPath(path);
}


void FakeEtcdClient::HandlePut(
    const std::string& key, const std::map<std::string, std::string>& params,
    const GenericCallback& cb) {
  VLOG(1) << "PUT " << key;
  std::lock_guard<std::mutex> lock(mutex_);
  CHECK(key.back() != '/');
  CHECK(params.find("value") != params.end());
  const std::string& value(params.find("value")->second);
  Node node(index_, index_, key, value);
  MaybeSetExpiry(params, &node);
  util::Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    ScheduleCallback(
        std::bind(cb, status, std::make_shared<JsonObject>(), index_));
    return;
  }
  if (entries_.find(key) != entries_.end()) {
    VLOG(1) << "Keeping original created_index_";
    node.created_index_ = entries_.find(key)->second.created_index_;
  }

  entries_[key] = node;
  ++index_;
  const std::string json(JsonForEntry(node, "set"));
  VLOG(1) << "put(" << key << "):\n" << json;
  ScheduleCallback(std::bind(cb, util::Status::OK,
                             std::make_shared<JsonObject>(json), index_));
  NotifyForPath(key);
}


void FakeEtcdClient::HandleDelete(
    const std::string& key, const std::map<std::string, std::string>& params,
    const GenericCallback& cb) {
  VLOG(1) << "DELETE " << key;
  std::lock_guard<std::mutex> lock(mutex_);
  CHECK(key.back() != '/');
  util::Status status(CheckCompareFlags(params, key));
  if (!status.ok()) {
    ScheduleCallback(
        std::bind(cb, status, std::make_shared<JsonObject>(), index_));
    return;
  }
  LOG(INFO) << entries_[key].ToString();
  entries_[key].deleted_ = true;
  LOG(INFO) << entries_[key].ToString();
  ++index_;
  ScheduleCallback(std::bind(cb, util::Status::OK,
                             std::make_shared<JsonObject>(
                                 JsonForEntry(entries_[key], "delete")),
                             index_));
  NotifyForPath(key);
  entries_.erase(key);
}


void FakeEtcdClient::RemoveWatcher(const void* cookie) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& pair : watches_) {
    for (auto it(pair.second.begin()); it != pair.second.end();) {
      if (it->second == cookie) {
        VLOG(1) << "Removing watcher " << it->second << " on " << pair.first;
        it = pair.second.erase(it);
      } else {
        ++it;
      }
    }
  }
}


void FakeEtcdClient::ScheduleCallback(const std::function<void()>& cb) {
  pool_.Add(cb);
}


}  // namespace cert_trans
