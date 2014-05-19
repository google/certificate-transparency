#include "sqlite_db.cc"

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"

template class SQLiteDB<ct::LoggedCertificate>;
