#include "util/libevent_wrapper.h"

#include <climits>
#include <event2/thread.h>
#include <glog/logging.h>
#include <math.h>
#include <signal.h>

using std::bind;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;
using std::function;
using std::lock_guard;
using std::mutex;
using std::placeholders::_1;
using std::recursive_mutex;
using std::shared_ptr;
using std::string;
using std::vector;
using util::TaskHold;

namespace {

void FreeEvDns(evdns_base* dns) {
  if (dns) {
    evdns_base_free(dns, true);
  }
}


static void Handler_ExitLoop(evutil_socket_t sig, short events, void* base) {
  event_base_loopexit((event_base*)base, NULL);
}


void SetExitLoopHandler(event_base* base, int signum) {
  struct event* signal_event;
  signal_event = evsignal_new(base, signum, Handler_ExitLoop, base);
  CHECK_NOTNULL(signal_event);
  CHECK_GE(event_add(signal_event, NULL), 0);
}


void DelayCancel(event* timer, util::Task* task) {
  event_del(timer);
  task->Return(util::Status::CANCELLED);
}


void DelayDispatch(evutil_socket_t sock, short events, void* userdata) {
  static_cast<util::Task*>(CHECK_NOTNULL(userdata))->Return();
}


__thread bool on_event_thread = false;


}  // namespace

namespace cert_trans {
namespace libevent {


struct HttpServer::Handler {
  Handler(const string& _path, const HandlerCallback& _cb)
      : path(_path), cb(_cb) {
  }

  const string path;
  const HandlerCallback cb;
};


Base::Base()
    : base_(CHECK_NOTNULL(event_base_new()), event_base_free),
      dns_(nullptr, FreeEvDns),
      wake_closures_(event_new(base_.get(), -1, 0, &Base::RunClosures, this),
                     &event_free) {
  evthread_make_base_notifiable(base_.get());
}


Base::~Base() {
}


// static
bool Base::OnEventThread() {
  return on_event_thread;
}


// static
void Base::CheckNotOnEventThread() {
  CHECK_EQ(false, OnEventThread());
}


void Base::Add(const function<void()>& cb) {
  lock_guard<mutex> lock(closures_lock_);
  closures_.push_back(cb);
  event_active(wake_closures_.get(), 0, 0);
}


void Base::Delay(const duration<double>& delay, util::Task* task) {
  // If the delay is zero (or less?), what the heck, we're done!
  if (delay <= delay.zero()) {
    task->Return();
    return;
  }

  // Make sure nothing "bad" happens while we're still setting up our
  // callbacks.
  TaskHold hold(task);

  event* timer(CHECK_NOTNULL(evtimer_new(base_.get(), &DelayDispatch, task)));

  // Ensure that the cancellation callback is run on this libevent::Base, to
  // avoid races during cancellation.

  // Cancellation callbacks are always called before the task enters
  // the DONE state (and "timer" is freed), and "event_del" is
  // thread-safe, so it does not matter on which thread "DelayCancel"
  // is called on.
  task->WhenCancelled(bind(DelayCancel, timer, task));

  task->CleanupWhenDone(bind(event_free, timer));

  timeval tv;
  const seconds sec(duration_cast<seconds>(delay));
  tv.tv_sec = sec.count();
  tv.tv_usec = duration_cast<microseconds>(delay - sec).count();

  CHECK_EQ(evtimer_add(timer, &tv), 0);
}


void Base::Dispatch() {
  SetExitLoopHandler(base_.get(), SIGHUP);
  SetExitLoopHandler(base_.get(), SIGINT);
  SetExitLoopHandler(base_.get(), SIGTERM);

  // There should /never/ be more than 1 thread trying to call Dispatch(), so
  // we should expect to always own the lock here.
  CHECK(dispatch_lock_.try_lock());
  LOG_IF(WARNING, on_event_thread)
      << "Huh?, Are you calling Dispatch() from a libevent thread?";
  const bool old_on_event_thread(on_event_thread);
  on_event_thread = true;
  CHECK_EQ(event_base_dispatch(base_.get()), 0);
  on_event_thread = old_on_event_thread;
  dispatch_lock_.unlock();
}


void Base::DispatchOnce() {
  // Only one thread can be running a dispatch loop at a time
  lock_guard<mutex> lock(dispatch_lock_);
  LOG_IF(WARNING, on_event_thread)
      << "Huh?, Are you calling Dispatch() from a libevent thread?";
  const bool old_on_event_thread(on_event_thread);
  on_event_thread = true;
  CHECK_EQ(event_base_loop(base_.get(), EVLOOP_ONCE), 0);
  on_event_thread = old_on_event_thread;
}


void Base::LoopExit() {
  event_base_loopexit(base_.get(), nullptr);
}


event* Base::EventNew(evutil_socket_t& sock, short events,
                      Event* event) const {
  return CHECK_NOTNULL(
      event_new(base_.get(), sock, events, &Event::Dispatch, event));
}


evhttp* Base::HttpNew() const {
  return CHECK_NOTNULL(evhttp_new(base_.get()));
}


evdns_base* Base::GetDns() {
  lock_guard<mutex> lock(dns_lock_);

  if (!dns_) {
    dns_.reset(CHECK_NOTNULL(evdns_base_new(base_.get(), 1)));
  }

  return dns_.get();
}


evhttp_connection* Base::HttpConnectionNew(const string& host,
                                           unsigned short port) {
  return CHECK_NOTNULL(
      evhttp_connection_base_new(base_.get(), GetDns(), host.c_str(), port));
}


void Base::RunClosures(evutil_socket_t sock, short flag, void* userdata) {
  Base* self(static_cast<Base*>(CHECK_NOTNULL(userdata)));

  vector<function<void()>> closures;
  {
    lock_guard<mutex> lock(self->closures_lock_);
    closures.swap(self->closures_);
  }

  for (const auto& closure : closures) {
    closure();
  }
}


Event::Event(const Base& base, evutil_socket_t sock, short events,
             const Callback& cb)
    : cb_(cb), ev_(base.EventNew(sock, events, this)) {
}


Event::~Event() {
  event_free(ev_);
}


void Event::Add(const duration<double>& timeout) const {
  timeval tv;
  timeval* tvp(NULL);

  if (timeout != duration<double>::zero()) {
    const seconds sec(duration_cast<seconds>(timeout));
    tv.tv_sec = sec.count();
    tv.tv_usec = duration_cast<microseconds>(timeout - sec).count();
    tvp = &tv;
  }

  CHECK_EQ(event_add(ev_, tvp), 0);
}


void Event::Dispatch(evutil_socket_t sock, short events, void* userdata) {
  static_cast<Event*>(userdata)->cb_(sock, events);
}


HttpServer::HttpServer(const Base& base) : http_(base.HttpNew()) {
}


HttpServer::~HttpServer() {
  evhttp_free(http_);
  for (vector<Handler*>::iterator it = handlers_.begin();
       it != handlers_.end(); ++it) {
    delete *it;
  }
}


void HttpServer::Bind(const char* address, ev_uint16_t port) {
  CHECK_EQ(evhttp_bind_socket(http_, address, port), 0);
}


bool HttpServer::AddHandler(const string& path, const HandlerCallback& cb) {
  Handler* handler(new Handler(path, cb));
  handlers_.push_back(handler);

  return evhttp_set_cb(http_, path.c_str(), &HandleRequest, handler) == 0;
}


void HttpServer::HandleRequest(evhttp_request* req, void* userdata) {
  static_cast<Handler*>(userdata)->cb(req);
}


EventPumpThread::EventPumpThread(const shared_ptr<Base>& base)
    : base_(base),
      pump_thread_(bind(&EventPumpThread::Pump, this)) {
}


EventPumpThread::~EventPumpThread() {
  base_->LoopExit();
  pump_thread_.join();
}


void EventPumpThread::Pump() {
  // Make sure there's at least the evdns listener, so that Dispatch()
  // doesn't return immediately with nothing to do.
  base_->GetDns();
  base_->Dispatch();
}


}  // namespace libevent
}  // namespace cert_trans
