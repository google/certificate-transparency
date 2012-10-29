#include <glog/logging.h>
#include <stdint.h>

#include "client.h"
#include "ct.h"
#include "ct.pb.h"
#include "log_client.h"
#include "serial_hasher.h"
#include "serializer.h"

using ct::LogEntry;
using ct::ClientLookup;
using ct::ClientMessage;
using ct::ServerError;
using ct::ServerMessage;
using ct::MerkleAuditProof;
using ct::SignedCertificateTimestamp;
using ct::protocol::kPacketPrefixLength;
using ct::protocol::kMaxPacketLength;
using std::string;

const ct::protocol::Version LogClient::kProtocolVersion = ct::protocol::V1;
const ct::protocol::Format LogClient::kPacketFormat = ct::protocol::PROTOBUF;
const ct::Version LogClient::kCtVersion = ct::V1;

LogClient::LogClient(const string &server, uint16_t port)
    : client_(server, port) {
}

LogClient::~LogClient() {}

bool LogClient::Connect() { return client_.Connect(); }

void LogClient::Disconnect() { client_.Disconnect(); }

bool LogClient::UploadSubmission(const string &submission, bool pre,
                                 SignedCertificateTimestamp *sct) {
  ClientMessage message;
  if (pre)
    message.set_command(ClientMessage::SUBMIT_CA_BUNDLE);
  else
    message.set_command(ClientMessage::SUBMIT_BUNDLE);

  message.set_submission_data(submission);

  if (!SendMessage(message))
    return false;

  ServerMessage reply;
  if (!ReadReply(&reply))
    return false;

  bool ret = false;
  switch (reply.response()) {
    case ServerMessage::ERROR:
      LOG(ERROR) << "CT server replied with error " << reply.error().code()
                 << ": " << ErrorString(reply.error().code());
      if (reply.error().has_error_message())
        LOG(ERROR) << "Error message: " << reply.error().error_message();
      else
        LOG(ERROR) << "Sorry, that's all we know.";
      break;
    case ServerMessage::SIGNED_CERTIFICATE_TIMESTAMP:
      if (reply.sct().version() != kCtVersion) {
        LOG(ERROR) << "Server replied with a bad SCT version "
                   << reply.sct().version();
        break;
      }
      LOG(INFO) << "Submission successful.";
      sct->CopyFrom(reply.sct());
      ret = true;
      break;
    default:
      LOG(ERROR) << "Unexpected server response code " << reply.response();
  }
  return ret;
}

bool LogClient::QueryAuditProof(const LogEntry &entry,
                                const SignedCertificateTimestamp &sct,
                                MerkleAuditProof *proof) {
  CHECK(sct.has_timestamp()) << "Missing SCT timestamp";
  CHECK_EQ(kCtVersion, sct.version()) << "SCT has unknown version";

  ClientMessage message;
  message.set_command(ClientMessage::LOOKUP_AUDIT_PROOF);
  message.mutable_lookup()->set_type(
      ClientLookup::MERKLE_AUDIT_PROOF_BY_TIMESTAMP_AND_HASH);
  message.mutable_lookup()->set_certificate_timestamp(sct.timestamp());
  message.mutable_lookup()->set_certificate_sha256_hash(
      Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry)));
  if (!SendMessage(message))
    return false;
  ServerMessage reply;
  if (!ReadReply(&reply))
    return false;

  bool ret = false;
  switch (reply.response()) {
    case ServerMessage::ERROR:
      LOG(ERROR) << "CT server replied with error " << reply.error().code()
                 << ": " << ErrorString(reply.error().code());
      if (reply.error().has_error_message())
        LOG(ERROR) << "Error message: " << reply.error().error_message();
      else
        LOG(ERROR) << "Sorry, that's all we know.";
      break;
    case ServerMessage::MERKLE_AUDIT_PROOF:
      if (reply.merkle_proof().version() != kCtVersion) {
        LOG(ERROR) << "Server replied with a bad Merkle proof version "
                   << reply.merkle_proof().version();
        break;
      }
      LOG(INFO) << "Proof retrieved";
      proof->CopyFrom(reply.merkle_proof());
      ret = true;
      break;
    default:
      LOG(ERROR) << "Unexpected server response code " << reply.response();
  }
  return ret;
}

// static
string LogClient::ErrorString(ServerError::ErrorCode error) {
  switch (error) {
    case ServerError::BAD_VERSION:
      return "bad version";
    case ServerError::UNSUPPORTED_FORMAT:
      return "unsupported message format";
    case ServerError::INVALID_MESSAGE:
      return "invalid message";
    case ServerError::UNSUPPORTED_COMMAND:
      return "unsupported command";
    case ServerError::REJECTED:
      return "rejected";
    case ServerError::NOT_FOUND:
      return "not found";
    default:
      return "unknown error code";
  }
}

bool LogClient::SendMessage(const ClientMessage &message) {
  string serialized_message;
  CHECK(message.SerializeToString(&serialized_message));
  if (serialized_message.size() > kMaxPacketLength) {
    LOG(ERROR) << "Message length exceeds allowed maximum";
    return false;
  }

  string packet;
  packet.append(Serializer::SerializeUint(kProtocolVersion, 1));
  packet.append(Serializer::SerializeUint(kPacketFormat, 1));
  packet.append(Serializer::SerializeUint(serialized_message.length(),
                                          kPacketPrefixLength));
  packet.append(serialized_message);

  return client_.Write(packet);
}

bool LogClient::ReadReply(ServerMessage *message) {
  // Read the version.
  string version_byte;
  if (!client_.Read(1, &version_byte))
    return false;

  // We have to initialize to make the compiler happy,
  // so initialize to an invalid enum.
  int version = -1;
  Deserializer::DeserializeResult res =
      Deserializer::DeserializeUint(version_byte, 1, &version);
  DCHECK_EQ(Deserializer::OK, res);

  if (version != kProtocolVersion) {
    LOG(ERROR) << "Unexpected server reply: packet version "
               << version << " unsupported.";
    // We don't understand the server; no point continuing.
    LOG(ERROR) << "Disconnecting.";
    client_.Disconnect();
    return false;
  }

  // Read the format.
  string format_byte;
  if (!client_.Read(1, &format_byte))
    return false;

  // We have to initialize to make the compiler happy,
  // so initialize to an invalid enum.
  int format = -1;
  res = Deserializer::DeserializeUint(format_byte, 1, &format);
  DCHECK_EQ(Deserializer::OK, res);

  if (format != kPacketFormat) {
    LOG(ERROR) << "Unexpected server reply: message format "
               << format << " unsupported.";
    // We don't understand the server; no point continuing.
    LOG(ERROR) << "Disconnecting.";
    client_.Disconnect();
    return false;
  }

  string serialized_packet_length;
  if (!client_.Read(kPacketPrefixLength, &serialized_packet_length))
    return false;

  size_t packet_length = kMaxPacketLength + 1;
  res = Deserializer::DeserializeUint(serialized_packet_length,
                                      kPacketPrefixLength,
                                      &packet_length);
  DCHECK_EQ(Deserializer::OK, res);
  string data;
  if (packet_length > kMaxPacketLength || !client_.Read(packet_length, &data))
    return false;

  ServerMessage recv_message;
  if (!recv_message.ParseFromString(data))
    return false;
  message->CopyFrom(recv_message);
  return true;
}
