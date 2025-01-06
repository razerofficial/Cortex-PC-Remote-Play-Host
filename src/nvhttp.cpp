/**
 * @file src/nvhttp.h
 * @brief todo
 */

// macros
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <filesystem>

// lib includes
#include <Simple-Web-Server/server_http.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <string>

// local includes
#include "config.h"
#include "crypto.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "system_tray.h"
#include "utility.h"
#include "uuid.h"
#include "video.h"
#include <openssl/md5.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#if RAZER_MOD == 1
#include "RazerState.h"
#include "RazerNamedPipe.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <sddl.h>
#include <Wtsapi32.h>  // For WTS functions
#include "UIScaleHelper.h"
#include "audio.h"
#endif

#if RAZER_MOD == 1
std::string current_device_nickname = "";
std::string url_decode(const std::string url) {
    std::string decoded;
    for (size_t i = 0; i < url.length(); ++i) {
        if (url[i] == '%') {
            if (i + 2 < url.length()) {
                std::istringstream hex_stream(url.substr(i + 1, 2));
                int hex_value;
                hex_stream >> std::hex >> hex_value;
                decoded += static_cast<char>(hex_value);
                i += 2;
            }
        } else if (url[i] == '+') {
            decoded += ' ';
        } else {
            decoded += url[i];
        }
    }
    return decoded;
}

std::string to_hex(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

class DelayedFunction {
public:
    DelayedFunction()
        : delay_ms_(0), is_running_(false) {}

    void start(std::function<void()> func, int delay_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        func_ = func;
        delay_ms_ = delay_ms;
        if (is_running_) {
            BOOST_LOG(info) << "fresh delay " << delay_ms_;
            refresh_delay();
        } else {
            BOOST_LOG(info) << "start a new virtual display detect thread " << delay_ms_;
            is_running_ = true;
            thread_ = std::thread(&DelayedFunction::run, this);
            thread_.detach();
        }
    }

    void stop() {
        {
            //std::lock_guard<std::mutex> lock(mutex_);
            is_running_ = false;
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    ~DelayedFunction() {
        stop();
    }

private:
    void run() {
        start_time_ = std::chrono::steady_clock::now();

        while (is_running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            {
              std::lock_guard<std::mutex> lock(mutex_);
              auto elapsed_time = std::chrono::steady_clock::now() - start_time_;
              if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time).count() >= delay_ms_) {
                  func_();
                  stop();
              }
            }
        }
    }

    void refresh_delay() {
        start_time_ = std::chrono::steady_clock::now();
    }

    std::function<void()> func_;
    int delay_ms_;
    bool is_running_;
    std::thread thread_;
    std::mutex mutex_;
    std::chrono::time_point<std::chrono::steady_clock> start_time_;
};
#endif

using namespace std::literals;
namespace nvhttp {
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;  
  crypto::cert_chain_t cert_chain;

  class SunshineHttpsServer: public SimpleWeb::Server<SimpleWeb::HTTPS> {
  public:
    SunshineHttpsServer(const std::string &certification_file, const std::string &private_key_file):
        SimpleWeb::Server<SimpleWeb::HTTPS>::Server(certification_file, private_key_file) {}

    std::function<int(SSL *)> verify;
    std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)> on_verify_failed;

  protected:
    void
    after_bind() override {
      SimpleWeb::Server<SimpleWeb::HTTPS>::after_bind();

      if (verify) {
        context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
        context.set_verify_callback([](int verified, boost::asio::ssl::verify_context &ctx) {
          // To respond with an error message, a connection must be established
          return 1;
        });
      }
    }

    // This is Server<HTTPS>::accept() with SSL validation support added
    void
    accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
        auto lock = connection->handler_runner->continue_lock();
        if (!lock)
          return;

        if (ec != SimpleWeb::error::operation_aborted)
          this->accept();

        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

        if (!ec) {
          boost::asio::ip::tcp::no_delay option(true);
          SimpleWeb::error_code ec;
          session->connection->socket->lowest_layer().set_option(option, ec);

          session->connection->set_timeout(config.timeout_request);
          session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
            session->connection->cancel_timeout();
            auto lock = session->connection->handler_runner->continue_lock();
            if (!lock)
              return;
            if (!ec) {
              if (verify && !verify(session->connection->socket->native_handle()))
                this->write(session, on_verify_failed);
              else
                this->read(session);
            }
            else if (this->on_error)
              this->on_error(session->request, ec);
          });
        }
        else if (this->on_error)
          this->on_error(session->request, ec);
      });
    }
  };

  using https_server_t = SunshineHttpsServer;
  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;

  struct conf_intern_t {
    std::string servercert;
    std::string pkey;
  } conf_intern;

  struct client_t {
    std::string uniqueID;
    std::vector<std::string> certs;
  };

  struct pair_session_t {
    struct {
      std::string uniqueID;
      std::string cert;
    } client;

    std::unique_ptr<crypto::aes_t> cipher_key;
    std::vector<uint8_t> clienthash;

    std::string serversecret;
    std::string serverchallenge;

    struct {
      util::Either<
        std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>,
        std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>>
        response;
      std::string salt;
    } async_insert_pin;
  };

#if RAZER_MOD == 1
  struct RazerData {
      std::string uuid;
      std::string secret;
      std::string expire;
      crypto::aes_t aesKey;
  };
#endif

  // uniqueID, session
  std::unordered_map<std::string, pair_session_t> map_id_sess;
  std::unordered_map<std::string, client_t> map_id_client;
  std::atomic<uint32_t> session_id_counter;

#if RAZER_MOD == 1
  std::string last_pincode = "";
  DelayedFunction _virtudal_display_stream_detect;
#endif

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;
  using resp_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>;
  using req_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request>;

  enum class op_e {
    ADD,
    REMOVE
  };

  std::string
  get_arg(const args_t &args, const char *name, const char *default_value = nullptr) {
    auto it = args.find(name);
    if (it == std::end(args)) {
      if (default_value != NULL) {
        return std::string(default_value);
      }

      throw std::out_of_range(name);
    }
    return it->second;
  }

  void
  save_state() {
    pt::ptree root;

    if (fs::exists(config::nvhttp.file_state)) {
      try {
        pt::read_json(config::nvhttp.file_state, root);
      }
      catch (std::exception &e) {
        BOOST_LOG(error) << "Couldn't read "sv << config::nvhttp.file_state << ": "sv << e.what();
        return;
      }
    }

    root.erase("root"s);

    root.put("root.uniqueid", http::unique_id);
    auto &nodes = root.add_child("root.devices", pt::ptree {});
    for (auto &[_, client] : map_id_client) {
      pt::ptree node;

      node.put("uniqueid"s, client.uniqueID);

      pt::ptree cert_nodes;
      for (auto &cert : client.certs) {
        pt::ptree cert_node;
        cert_node.put_value(cert);
        cert_nodes.push_back(std::make_pair(""s, cert_node));
      }
      node.add_child("certs"s, cert_nodes);

      nodes.push_back(std::make_pair(""s, node));
    }

    try {
      pt::write_json(config::nvhttp.file_state, root);
    }
    catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't write "sv << config::nvhttp.file_state << ": "sv << e.what();
      return;
    }
  }

  void
  load_state() {
    if (!fs::exists(config::nvhttp.file_state)) {
      BOOST_LOG(info) << "File "sv << config::nvhttp.file_state << " doesn't exist"sv;
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }

    pt::ptree root;
    try {
      pt::read_json(config::nvhttp.file_state, root);
    }
    catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't read "sv << config::nvhttp.file_state << ": "sv << e.what();

      return;
    }

    auto unique_id_p = root.get_optional<std::string>("root.uniqueid");
    if (!unique_id_p) {
      // This file doesn't contain moonlight credentials
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }
    http::unique_id = std::move(*unique_id_p);

    auto device_nodes = root.get_child("root.devices");

    for (auto &[_, device_node] : device_nodes) {
      auto uniqID = device_node.get<std::string>("uniqueid");
      auto &client = map_id_client.emplace(uniqID, client_t {}).first->second;

      client.uniqueID = uniqID;

      for (auto &[_, el] : device_node.get_child("certs")) {
        client.certs.emplace_back(el.get_value<std::string>());
      }
    }
  }

  void
  update_id_client(const std::string &uniqueID, std::string &&cert, op_e op) {
    switch (op) {
      case op_e::ADD: {
        auto &client = map_id_client[uniqueID];
        client.certs.emplace_back(std::move(cert));
        client.uniqueID = uniqueID;
      } break;
      case op_e::REMOVE:
        map_id_client.erase(uniqueID);
        break;
    }

    if (!config::sunshine.flags[config::flag::FRESH_STATE]) {
      save_state();
    }
  }

  std::shared_ptr<rtsp_stream::launch_session_t>
  make_launch_session(bool host_audio, const args_t &args) {
    auto launch_session = std::make_shared<rtsp_stream::launch_session_t>();

    launch_session->id = ++session_id_counter;

    auto rikey = util::from_hex_vec(get_arg(args, "rikey"), true);
    std::copy(rikey.cbegin(), rikey.cend(), std::back_inserter(launch_session->gcm_key));

    launch_session->host_audio = host_audio;
    std::stringstream mode = std::stringstream(get_arg(args, "mode", "0x0x0"));
    // Split mode by the char "x", to populate width/height/fps
    int x = 0;
    std::string segment;
    while (std::getline(mode, segment, 'x')) {
      if (x == 0) launch_session->width = atoi(segment.c_str());
      if (x == 1) launch_session->height = atoi(segment.c_str());
      if (x == 2) launch_session->fps = atoi(segment.c_str());
      x++;
    }
    launch_session->unique_id = (get_arg(args, "uniqueid", "unknown"));
    launch_session->appid = util::from_view(get_arg(args, "appid", "unknown"));
    launch_session->enable_sops = util::from_view(get_arg(args, "sops", "0"));
    launch_session->surround_info = util::from_view(get_arg(args, "surroundAudioInfo", "196610"));
    launch_session->gcmap = util::from_view(get_arg(args, "gcmap", "0"));
    launch_session->enable_hdr = util::from_view(get_arg(args, "hdrMode", "0"));

    // Encrypted RTSP is enabled with client reported corever >= 1
    auto corever = util::from_view(get_arg(args, "corever", "0"));
    if (corever >= 1) {
      launch_session->rtsp_cipher = crypto::cipher::gcm_t {
        launch_session->gcm_key, false
      };
      launch_session->rtsp_iv_counter = 0;
    }
    launch_session->rtsp_url_scheme = launch_session->rtsp_cipher ? "rtspenc://"s : "rtsp://"s;

    // Generate the unique identifiers for this connection that we will send later during RTSP handshake
    unsigned char raw_payload[8];
    RAND_bytes(raw_payload, sizeof(raw_payload));
    launch_session->av_ping_payload = util::hex_vec(raw_payload);
    RAND_bytes((unsigned char *) &launch_session->control_connect_data, sizeof(launch_session->control_connect_data));

    launch_session->iv.resize(16);
    uint32_t prepend_iv = util::endian::big<uint32_t>(util::from_view(get_arg(args, "rikeyid")));
    auto prepend_iv_p = (uint8_t *) &prepend_iv;
    std::copy(prepend_iv_p, prepend_iv_p + sizeof(prepend_iv), std::begin(launch_session->iv));
    return launch_session;
  }

  void
  getservercert(pair_session_t &sess, pt::ptree &tree, const std::string &pin) {
    if (sess.async_insert_pin.salt.size() < 32) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Salt too short");
      return;
    }

    std::string_view salt_view { sess.async_insert_pin.salt.data(), 32 };

    auto salt = util::from_hex<std::array<uint8_t, 16>>(salt_view, true);

    auto key = crypto::gen_aes_key(salt, pin);
    sess.cipher_key = std::make_unique<crypto::aes_t>(key);

    tree.put("root.paired", 1);
    tree.put("root.plaincert", util::hex_vec(conf_intern.servercert, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  void
  serverchallengeresp(pair_session_t &sess, pt::ptree &tree, const args_t &args) {
    auto encrypted_response = util::from_hex_vec(get_arg(args, "serverchallengeresp"), true);

    std::vector<uint8_t> decrypted;
    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    cipher.decrypt(encrypted_response, decrypted);

    sess.clienthash = std::move(decrypted);

    auto serversecret = sess.serversecret;
    auto sign = crypto::sign256(crypto::pkey(conf_intern.pkey), serversecret);

    serversecret.insert(std::end(serversecret), std::begin(sign), std::end(sign));

    tree.put("root.pairingsecret", util::hex_vec(serversecret, true));
    tree.put("root.paired", 1);
    tree.put("root.<xmlattr>.status_code", 200);
  }

  void
  clientchallenge(pair_session_t &sess, pt::ptree &tree, const args_t &args) {
    auto challenge = util::from_hex_vec(get_arg(args, "clientchallenge"), true);

    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    std::vector<uint8_t> decrypted;
    cipher.decrypt(challenge, decrypted);

    auto x509 = crypto::x509(conf_intern.servercert);
    auto sign = crypto::signature(x509);
    auto serversecret = crypto::rand(16);

    decrypted.insert(std::end(decrypted), std::begin(sign), std::end(sign));
    decrypted.insert(std::end(decrypted), std::begin(serversecret), std::end(serversecret));

    auto hash = crypto::hash({ (char *) decrypted.data(), decrypted.size() });
    auto serverchallenge = crypto::rand(16);

    std::string plaintext;
    plaintext.reserve(hash.size() + serverchallenge.size());

    plaintext.insert(std::end(plaintext), std::begin(hash), std::end(hash));
    plaintext.insert(std::end(plaintext), std::begin(serverchallenge), std::end(serverchallenge));

    std::vector<uint8_t> encrypted;
    cipher.encrypt(plaintext, encrypted);

    sess.serversecret = std::move(serversecret);
    sess.serverchallenge = std::move(serverchallenge);

    tree.put("root.paired", 1);
    tree.put("root.challengeresponse", util::hex_vec(encrypted, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  void
  clientpairingsecret(std::shared_ptr<safe::queue_t<crypto::x509_t>> &add_cert, pair_session_t &sess, pt::ptree &tree, const args_t &args) {
    auto &client = sess.client;

    auto pairingsecret = util::from_hex_vec(get_arg(args, "clientpairingsecret"), true);
    if (pairingsecret.size() <= 16) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Clientpairingsecret too short");
      return;
    }

    std::string_view secret { pairingsecret.data(), 16 };
    std::string_view sign { pairingsecret.data() + secret.size(), pairingsecret.size() - secret.size() };

    auto x509 = crypto::x509(client.cert);
    auto x509_sign = crypto::signature(x509);

    std::string data;
    data.reserve(sess.serverchallenge.size() + x509_sign.size() + secret.size());

    data.insert(std::end(data), std::begin(sess.serverchallenge), std::end(sess.serverchallenge));
    data.insert(std::end(data), std::begin(x509_sign), std::end(x509_sign));
    data.insert(std::end(data), std::begin(secret), std::end(secret));

    auto hash = crypto::hash(data);

    // if hash not correct, probably MITM
    if (!std::memcmp(hash.data(), sess.clienthash.data(), hash.size()) && crypto::verify256(crypto::x509(client.cert), secret, sign)) {
      tree.put("root.paired", 1);
      add_cert->raise(crypto::x509(client.cert));

      auto it = map_id_sess.find(client.uniqueID);

      update_id_client(client.uniqueID, std::move(client.cert), op_e::ADD);
      map_id_sess.erase(it);
    }
    else {
      map_id_sess.erase(client.uniqueID);
      tree.put("root.paired", 0);
    }

    tree.put("root.<xmlattr>.status_code", 200);
  }

  template <class T>
  struct tunnel;

  template <>
  struct tunnel<SimpleWeb::HTTPS> {
    static auto constexpr to_string = "HTTPS"sv;
  };

  template <>
  struct tunnel<SimpleWeb::HTTP> {
    static auto constexpr to_string = "NONE"sv;
  };

  template <class T>
  void
  print_req(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    BOOST_LOG(debug) << "TUNNEL :: "sv << tunnel<T>::to_string;

    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  template <class T>
  void
  rz_print_req(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    BOOST_LOG(info) << "TUNNEL :: "sv << tunnel<T>::to_string;

    BOOST_LOG(info) << "METHOD :: "sv << request->method;
    BOOST_LOG(info) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(info) << name << " -- " << val;
    }

    BOOST_LOG(info) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      if(name == "razer_hash")
        continue;
      BOOST_LOG(info) << name << " -- " << val;
    }

    BOOST_LOG(info) << " [--] "sv;
  }

 template <class T>
  void
  print_res(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response) {
    std::stringstream ss;
    ss << response->rdbuf();

    // BOOST_LOG(info) << "response :: "sv << ss.str();
  }

  template <class T>
  void
  not_found(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response
      << "HTTP/1.1 404 NOT FOUND\r\n"
      << data.str();

    response->close_connection_after_response = true;
  }

  std::array<uint8_t, MD5_DIGEST_LENGTH> 
  string_to_md5(const std::string& str) {
    std::array<uint8_t, 16> digest;
    MD5((const unsigned char*)str.c_str(), str.length(), digest.data());
    return digest;
  }

  static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
      ((std::string*)userp)->append((char*)contents, size * nmemb);
      return size * nmemb;
  }

  std::string
  getStrInHtml(std::string html, std::string key) {
    std::string prefix_key = "<" + key + ">";
    std::string postfix_key = "</" + key + ">";
    std::size_t found_head = html.find(prefix_key);
    std::size_t found_tail = html.find(postfix_key);

    if (found_head == std::string::npos || found_tail == std::string::npos) {
      return "";
    } else {
      return html.substr (found_head+prefix_key.length(),found_tail-found_head-prefix_key.length());
    }
  }
#if RAZER_MOD == 1
  crypto::aes_t getPinAesKey(){
    //BOOST_LOG(info) << " : " << util::hex_vec(salt_view) << "\n";
    std::string salt_view = util::from_hex_vec(config::sunshine.razer_pair_token, true);
    return crypto::gen_aes_key(salt_view);
  }

  std::vector<RazerData> getPinAesKey_v2(std::string jwt_token, std::string env) {
    const char* url;
    /*if (env == "dev") {
      url = "https://nexus-dev.mobile.razer.com/neuron/api/secret/read";
    } else */if (env == "staging") {
      url = "https://nexus-rc.mobile.razer.com/neuron/api/secret/read";
    } else {
      url = "https://nexus-prod.mobile.razer.com/neuron/api/secret/read";
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        BOOST_LOG(error) << "Failed to initialize libcurl" << std::endl;
        return {};
    }

    struct curl_slist* headers = NULL;
    std::string jwt_header = "X-Razer-JWT: " + jwt_token;
    headers = curl_slist_append(headers, jwt_header.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    //curl_easy_setopt(curl, CURLOPT_CAINFO, "./credentials/cacert-2024-03-11.pem");
    
    std::string result;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return {};
    }

    curl_easy_cleanup(curl);
    json jsonResponse = json::parse(result);
    
    std::vector<RazerData> razerDataList;
    for (const auto& item : jsonResponse) {
      RazerData data;
      data.uuid = item["uuid"];
      data.secret = item["secret"];
      data.expire = item["expire"];
      razerDataList.push_back(data);

    }
    return razerDataList;
  }
  

  std::string
  decryptPinCode(crypto::aes_t key, std::string razerHash) {
    std::vector<uint8_t> decrypted_pin;
    crypto::cipher::ecb_t cipher(key, false);

    cipher.decrypt(razerHash, decrypted_pin);

    std::string pin_16szie(decrypted_pin.begin(), decrypted_pin.end());
    
    std::string pin(4, '\0');
    for (int i = 0; i < 4; ++i) {
      pin[i] = pin_16szie[i];
    }

    return pin;
  }
#endif

  bool isAllDigits(const std::string& str) {
      // Use std::all_of to check if all characters in the string are digits
      return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
  }

  std::mutex pair_mutex;

  template <class T>
  void
  pair(std::shared_ptr<safe::queue_t<crypto::x509_t>> &add_cert, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    //potential crash when multiple threads are trying to enter this function
    std::lock_guard<std::mutex> lock(pair_mutex);
    print_req<T>(request);
    rz_print_req<T>(request);
    
    pt::ptree tree;

    auto fg = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto args = request->parse_query_string();
    if (args.find("uniqueid"s) == std::end(args)) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing uniqueid parameter");

      return;
    }

    auto uniqID { get_arg(args, "uniqueid") };
    auto sess_it = map_id_sess.find(uniqID);

    args_t::const_iterator it;
    if (it = args.find("phrase"); it != std::end(args)) {
      if (it->second == "getservercert"sv) {
        pair_session_t sess;

        sess.client.uniqueID = std::move(uniqID);
        sess.client.cert = util::from_hex_vec(get_arg(args, "clientcert"), true);

        #if RAZER_MOD == 1
        bool isRazerId = false;
        std::string pinCode = "";
        it = args.find("razer_uuid");
        if ( it != std::end(args) && config::razerSettings.IDPairing != "Disable") {
          // Parse html parameters, razer_uuid, razer_hash, jwt.

          auto env { get_arg(args, "env") };
          auto razer_pincode_uuid { get_arg(args, "razer_pincode_uuid") };
          auto razer_pincode = util::from_hex_vec(get_arg(args, "razer_pincode"), true);

          std::vector<RazerData> razerDataList = getPinAesKey_v2(config::sunshine.razer_pair_token, env);
          if(razerDataList.size() != 0){
            for (const auto& item : razerDataList) {
              if (razer_pincode_uuid == item.uuid) {
                BOOST_LOG(info) << "Pin uuid matched";
                std::array<uint8_t, 16> razer_md5 = string_to_md5(item.secret); //MD5 of secret
                std::string razer_info_str(razer_md5.begin(), razer_md5.end()); //to string
                std::string_view salt_view { razer_info_str.data(), 16 }; //to string cutting to 16bit
                crypto::aes_t aesKey = crypto::gen_aes_key(salt_view); //aesKey
                pinCode = decryptPinCode(aesKey, razer_pincode); //
              } else {
                BOOST_LOG(warning) << "Pin uuid did not matched: " << item.uuid << "\n";
              }
            }

            if(pinCode.size() == 4){
              BOOST_LOG(info) << "Do Razer Id pairing";
              std::cout << "    - Decrypted PIN : " << pinCode << "\n";
              std::cout << "    - PIN size: " << pinCode.size() << "\n";
              isRazerId = true;
            }
            else{
              std::cout << "    - Decrypted PIN : " << pinCode << "\n";
              std::cout << "    - PIN size: " << pinCode.size() << "\n";
              BOOST_LOG(warning) << "Wrong PIN code format, not do Razer Id pairing";
              isRazerId = false;
            }
          }
          else
            BOOST_LOG(warning) << "No Razer PIN from server";
        }
        #endif

        BOOST_LOG(debug) << sess.client.cert;
        auto ptr = map_id_sess.emplace(sess.client.uniqueID, std::move(sess)).first;

        ptr->second.async_insert_pin.salt = std::move(get_arg(args, "salt"));
        if (config::sunshine.flags[config::flag::PIN_STDIN]) {
          std::string pin;

          BOOST_LOG(info) << "Please insert pin: "sv;
          std::getline(std::cin, pin);

          getservercert(ptr->second, tree, pin);
        }
        else {
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
          system_tray::update_tray_require_pin();
#endif
          ptr->second.async_insert_pin.response = std::move(response);

          fg.disable();

          #if RAZER_MOD == 1
          auto deviceNickname { url_decode(get_arg(args, "devicenickname" , "")) };
          if (isRazerId) {
            if(config::razerSettings.IDPairing == "Automatic")
            {
              BOOST_LOG(info) << "Enter PIN automatically." << "\n";
              auto pairResult = pin(pinCode);
              BOOST_LOG(info) << "Success pair ?" << pairResult << "with " << deviceNickname;
              if(pairResult)
                rz_state::SendNormalEvent(rz_state::CortexEvent::Cortex_Event_RazerID_pair_Success);
              else
                rz_state::SendNormalEvent(rz_state::CortexEvent::Cortex_Event_RazerID_pair_Failed);
            }
            else if(config::razerSettings.IDPairing == "Manual")
            {
              BOOST_LOG(info) << deviceNickname << " is waiting for pair agree." << "\n";
              last_pincode = pinCode;              
              rz_state::updateCurrentState("RequirePinAgree", "", deviceNickname);
            }
          }
          else{
            BOOST_LOG(info) << deviceNickname << " is waiting for PIN input." << "\n";
            rz_state::updateCurrentState("RequirePin", "", deviceNickname);
          }
          #endif
          
          return;
        }
      }
      else if (it->second == "pairchallenge"sv) {
        tree.put("root.paired", 1);
        tree.put("root.<xmlattr>.status_code", 200);
      }
    }
    else if (it = args.find("clientchallenge"); it != std::end(args)) {
      clientchallenge(sess_it->second, tree, args);
    }
    else if (it = args.find("serverchallengeresp"); it != std::end(args)) {
      serverchallengeresp(sess_it->second, tree, args);
    }
    else if (it = args.find("clientpairingsecret"); it != std::end(args)) {
      clientpairingsecret(add_cert, sess_it->second, tree, args);
    }
    else {
      tree.put("root.<xmlattr>.status_code", 404);
      tree.put("root.<xmlattr>.status_message", "Invalid pairing request");
    }
  }

#if RAZER_MOD == 1
  bool
  pinLast(bool isAgree){
    if(isAgree)
    {
      auto ret = pin(last_pincode);
      rz_state::updateCurrentState("unknown", "", "");
      if(ret)
        rz_state::SendNormalEvent(rz_state::CortexEvent::Cortex_Event_RazerID_pair_Success);
      else
        rz_state::SendNormalEvent(rz_state::CortexEvent::Cortex_Event_RazerID_pair_Failed);
        
      return ret;
    }
    else
    {
      rz_state::SendNormalEvent(rz_state::CortexEvent::Cortex_Event_RazerID_pair_Deny);
      rz_state::updateCurrentState("unknown", "", "");
      return false;
    }
  }
#endif

  /**
   * @brief Compare the user supplied pin to the Moonlight pin.
   * @param pin The user supplied pin.
   * @return `true` if the pin is correct, `false` otherwise.
   *
   * EXAMPLES:
   * ```cpp
   * bool pin_status = nvhttp::pin("1234");
   * ```
   */
  bool
  pin(std::string pin) {
    pt::ptree tree;
    if (map_id_sess.empty()) {
      return false;
    }

    // ensure pin is 4 digits
    if (pin.size() != 4) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put(
        "root.<xmlattr>.status_message", "Pin must be 4 digits, " + std::to_string(pin.size()) + " provided");
      return false;
    }

    // ensure all pin characters are numeric
    if (!std::all_of(pin.begin(), pin.end(), ::isdigit)) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Pin must be numeric");
      return false;
    }

    auto &sess = std::begin(map_id_sess)->second;
    getservercert(sess, tree, pin);

    // response to the request for pin
    std::ostringstream data;
    pt::write_xml(data, tree);

    auto &async_response = sess.async_insert_pin.response;
    if (async_response.has_left() && async_response.left()) {
      async_response.left()->write(data.str());
    }
    else if (async_response.has_right() && async_response.right()) {
      async_response.right()->write(data.str());
    }
    else {
      return false;
    }

    // reset async_response
    async_response = std::decay_t<decltype(async_response.left())>();
    // response to the current request
    return true;
  }

  #if RAZER_MOD == 1
  DEVMODE GetCurrentMonitorInfo(){
    DISPLAY_DEVICE displayDevice;
    displayDevice.cb = sizeof(DISPLAY_DEVICE);
    DEVMODE devMode;

    for (int i = 0; EnumDisplayDevices(nullptr, i, &displayDevice, 0); ++i) {
        if(std::string_view(displayDevice.DeviceID) == "RazerVisualMonitorIddDriver")
          continue; // not count virtual display

        if (displayDevice.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) {
            BOOST_LOG(debug) << L"Primary Screen: " << displayDevice.DeviceName << std::endl;

            if (EnumDisplaySettings(displayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode)) {
                BOOST_LOG(debug) << L"Resolution: " << devMode.dmPelsWidth << L"x" << devMode.dmPelsHeight
                           << L" @ " << devMode.dmDisplayFrequency << L"Hz" << std::endl;
                return devMode;
            } else {
                BOOST_LOG(error) << L"Failed to get display settings for the primary screen.";
            }
            break;
        }
    }

    return devMode;
  }

  // int IsMonitorActive(DWORD Width, DWORD Height, DWORD RefreshRate){
  //   //BOOST_LOG(info) << "monitor active ?: Width= " << Width << " Height = " << Height << " RefreshRate = " << RefreshRate;
  //   //BOOST_LOG(info) << "monitor info Width= " << devMode.dmPelsWidth << " Height = " << devMode.dmPelsHeight << " RefreshRate = " << devMode.dmDisplayFrequency;

  //   auto isInRange = [](int value, int center) {
  //     return value >= center - 1 && value <= center + 1;
  //   };

  //   if(Width == devMode.dmPelsWidth && Height == devMode.dmPelsHeight && isInRange(RefreshRate, devMode.dmDisplayFrequency))
  //     return 1;
  //   else
  //     return 0;
  // }
 
  #endif

  template <class T>
  void
  serverinfo(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    int pair_status = 0;
    if constexpr (std::is_same_v<SimpleWeb::HTTPS, T>) {
      auto args = request->parse_query_string();
      auto clientID = args.find("uniqueid"s);

      if (clientID != std::end(args)) {
        if (auto it = map_id_client.find(clientID->second); it != std::end(map_id_client)) {
          pair_status = 1;
        }
      }
    }

    auto local_endpoint = request->local_endpoint();

    pt::ptree tree;

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.hostname", config::nvhttp.sunshine_name);

    tree.put("root.appversion", VERSION);
    tree.put("root.GfeVersion", GFE_VERSION);
    tree.put("root.uniqueid", http::unique_id);
    tree.put("root.HttpsPort", net::map_port(PORT_HTTPS));
    tree.put("root.ExternalPort", net::map_port(PORT_HTTP));
    tree.put("root.MaxLumaPixelsHEVC", video::active_hevc_mode > 1 ? "1869449984" : "0");

    // Only include the MAC address for requests sent from paired clients over HTTPS.
    // For HTTP requests, use a placeholder MAC address that Moonlight knows to ignore.
    if constexpr (std::is_same_v<SimpleWeb::HTTPS, T>) {
      tree.put("root.mac", platf::get_mac_address(net::addr_to_normalized_string(local_endpoint.address())));
    }
    else {
      tree.put("root.mac", "00:00:00:00:00:00");
    }

#if RAZER_MOD == 1
    auto mac_address = platf::get_mac_address(net::addr_to_normalized_string(local_endpoint.address()));    
    auto hash_mac = crypto::hash(mac_address);
    auto machine_identifier = to_hex(hash_mac.data(), hash_mac.size());
    tree.put("root.MachineIdentifier", machine_identifier);
#endif

    // Moonlight clients track LAN IPv6 addresses separately from LocalIP which is expected to
    // always be an IPv4 address. If we return that same IPv6 address here, it will clobber the
    // stored LAN IPv4 address. To avoid this, we need to return an IPv4 address in this field
    // when we get a request over IPv6.
    //
    // HACK: We should return the IPv4 address of local interface here, but we don't currently
    // have that implemented. For now, we will emulate the behavior of GFE+GS-IPv6-Forwarder,
    // which returns 127.0.0.1 as LocalIP for IPv6 connections. Moonlight clients with IPv6
    // support know to ignore this bogus address.
    if (local_endpoint.address().is_v6() && !local_endpoint.address().to_v6().is_v4_mapped()) {
      tree.put("root.LocalIP", "127.0.0.1");
    }
    else {
      tree.put("root.LocalIP", net::addr_to_normalized_string(local_endpoint.address()));
    }

#if RAZER_MOD == 1
    auto args = request->parse_query_string();
    auto razeruuid = args.find("razer_uuid"s);
    if(razeruuid != args.end()){
      //BOOST_LOG(info) << "incoming razer_uuid = " << razeruuid->second;
      tree.put("root.RazerIdIdentifier", config::sunshine.razer_uuid == razeruuid->second);
      //tree.put("root.incomingRazerUUID", razeruuid->second)
      tree.put("root.RazerIdPairStatus", config::razerSettings.IDPairing);
    }

    bool isHdrSupported = false;
    bool isHdrEnabled = false;
    if (platf::CheckPrimaryScreenHDR(isHdrSupported, isHdrEnabled)){
      //tree.put("root.PrimayMonitorHhrSupported", isHdrSupported == true ? 1: 0);
      tree.put("root.PrimayMonitorHdrEnabled", isHdrEnabled == true ? 1: 0);
    }

    tree.put("root.CurrentSessionCount", rtsp_stream::session_count());
#endif

    uint32_t codec_mode_flags = SCM_H264;
    if (video::active_hevc_mode >= 2) {
      codec_mode_flags |= SCM_HEVC;
    }
    if (video::active_hevc_mode >= 3) {
      codec_mode_flags |= SCM_HEVC_MAIN10;
    }
    if (video::active_av1_mode >= 2) {
      codec_mode_flags |= SCM_AV1_MAIN8;
    }
    if (video::active_av1_mode >= 3) {
      codec_mode_flags |= SCM_AV1_MAIN10;
    }
    tree.put("root.ServerCodecModeSupport", codec_mode_flags);

 #if RAZER_MOD == 1
    auto dev = GetCurrentMonitorInfo();
    pt::ptree primary_display_node;
    primary_display_node.put("Width", dev.dmPelsWidth);
    primary_display_node.put("Height", dev.dmPelsHeight);
    primary_display_node.put("RefreshRate", dev.dmDisplayFrequency);

    pt::ptree primary_display_nodes;
    primary_display_nodes.add_child("DisplayMode", primary_display_node);
    tree.add_child("root.PrimaryDisplayMode", primary_display_nodes);
 #endif

    pt::ptree display_nodes;
    for (auto &resolution : config::nvhttp.resolutions) {
      auto pred = [](auto ch) { return ch == ' ' || ch == '\t' || ch == 'x'; };

      auto middle = std::find_if(std::begin(resolution), std::end(resolution), pred);
      if (middle == std::end(resolution)) {
        BOOST_LOG(warning) << resolution << " is not in the proper format for a resolution: WIDTHxHEIGHT"sv;
        continue;
      }

      auto width = util::from_chars(&*std::begin(resolution), &*middle);
      auto height = util::from_chars(&*(middle + 1), &*std::end(resolution));
      for (auto fps : config::nvhttp.fps) {
        pt::ptree display_node;
        display_node.put("Width", width);
        display_node.put("Height", height);
        display_node.put("RefreshRate", fps);
        display_nodes.add_child("DisplayMode", display_node);
      }
    }

    if (!config::nvhttp.resolutions.empty()) {
      tree.add_child("root.SupportedDisplayMode", display_nodes);
    }
    auto current_appid = proc::proc.running();
    tree.put("root.PairStatus", pair_status);
    tree.put("root.currentgame", current_appid);
    tree.put("root.state", 
    current_appid > 0 ? 

    "SUNSHINE_SERVER_BUSY" : "SUNSHINE_SERVER_FREE");

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
  }

#if RAZER_MOD == 1
  // Function to get the current user's SID
  std::string GetLoggedInUserSid() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();  // Get the active session ID
    HANDLE userToken = nullptr;

    if (!WTSQueryUserToken(sessionId, &userToken)) {  // Get the user token for the session
        std::cerr << "Failed to query user token. Error: " << GetLastError() << std::endl;
        return "";
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(userToken, TokenUser, nullptr, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token information size. Error: " << GetLastError() << std::endl;
        CloseHandle(userToken);
        return "";
    }

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(new BYTE[tokenInfoLength]);
    if (!GetTokenInformation(userToken, TokenUser, tokenUser, tokenInfoLength, &tokenInfoLength)) {
        std::cerr << "Failed to get token information. Error: " << GetLastError() << std::endl;
        delete[] tokenUser;
        CloseHandle(userToken);
        return "";
    }

    char* sidString = nullptr;
    if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString)) {
        std::cerr << "Failed to convert SID to string. Error: " << GetLastError() << std::endl;
        delete[] tokenUser;
        CloseHandle(userToken);
        return "";
    }

    std::string result(sidString);
    LocalFree(sidString);
    delete[] tokenUser;
    CloseHandle(userToken);
    return result;
  }
  
  // Function to get the background type for the current user
  std::string GetBackgroundTypeForCurrentUser() {
      std::string userSid = GetLoggedInUserSid();
      if (userSid.empty()) {
          return "unknown";  // Return "unknown" if SID is not retrieved
      }
      //BOOST_LOG(info) << " current sid = " << userSid;
      // Construct the full registry path for the user's wallpaper settings
      const char* regSubPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers";
      std::string regPath = userSid + "\\" + regSubPath;

      HKEY hKey;
      // Open the registry key for the user's wallpaper settings
      if (RegOpenKeyEx(HKEY_USERS, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
          return "unknown";  // Return "unknown" if the registry key can't be opened
      }

      DWORD backgroundType = 0;
      DWORD bufferSize = sizeof(backgroundType);

      // Query the value of "BackgroundType" from the registry
      if (RegQueryValueEx(hKey, "BackgroundType", NULL, NULL, (LPBYTE)&backgroundType, &bufferSize) == ERROR_SUCCESS) {
          RegCloseKey(hKey);  // Close the registry key after querying
          // Return the corresponding background type based on the registry value
          switch (backgroundType) {
              case 0:
                  return "picture";  // Picture wallpaper
              case 1:
                  return "solidcolor";  // Solid color wallpaper
              case 2:
                  return "slideshow";  // Slideshow wallpaper
              case 3:
                  return "spotlight";  // Spotlight wallpaper
              default:
                  return "unknown";  // Return "unknown" if an unexpected value is found
          }
      } else {
          RegCloseKey(hKey);  // Close the registry key if the value could not be read
          return "unknown";  // Return "unknown" if the query failed
      }
  }
  
  std::string GetBackgroundType() {
      const char* regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers";
      
      HKEY hKey;
      if (RegOpenKeyEx(HKEY_CURRENT_USER, regPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
          return "unknown";
      }

      DWORD backgroundType = 0;
      DWORD bufferSize = sizeof(backgroundType);

      if (RegQueryValueEx(hKey, "BackgroundType", NULL, NULL, (LPBYTE)&backgroundType, &bufferSize) == ERROR_SUCCESS) {
          switch (backgroundType) {
              case 0:
                  return "picture";
              case 1:
                  return "solidcolor";
              case 2:
                  return "slideshow";
              case 3:
                  return "spotlight";
              default:
                  return "unknown";
          }
      } else {
          return "unknown";
      }

      RegCloseKey(hKey);
  } 

  // Function to get the slideshow interval for the current user in SYSTEM context
  std::string GetSlideshowIntervalForCurrentuser() {
      std::string userSid = GetLoggedInUserSid();
      if (userSid.empty()) {
          return "-1";  // Return "unknown" if SID is not retrieved
      }

      const char* regSubPath = "Control Panel\\Personalization\\Desktop Slideshow";
      std::string regPath = userSid + "\\" + regSubPath;

      HKEY hKey;
      if (RegOpenKeyEx(HKEY_USERS, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
          return "-1";  // Return error code if registry key cannot be opened
      }

      DWORD interval = 0;
      DWORD bufferSize = sizeof(interval);

      // First attempt to get the "Interval" value
      if (RegQueryValueEx(hKey, "Interval", NULL, NULL, (LPBYTE)&interval, &bufferSize) == ERROR_SUCCESS) {
          RegCloseKey(hKey);
          int intervalMinutes = interval / 1000 / 60;  // Convert milliseconds to minutes
          return std::to_string(intervalMinutes);
      } else {
          // If "Interval" is not found, check for "LastTickHigh" (default 30 minutes)
          if (RegQueryValueEx(hKey, "LastTickHigh", NULL, NULL, (LPBYTE)&interval, &bufferSize) == ERROR_SUCCESS) {
              RegCloseKey(hKey);
              return std::to_string(30);  // Default interval (30 minutes) if "LastTickHigh" is found
          } else {
              RegCloseKey(hKey);
              return "-1";  // Return error if neither value is found
          }
      }
  }

  std::string GetSlideshowInterval() {
      const char* regPath = "Control Panel\\Personalization\\Desktop Slideshow";

      HKEY hKey;
      if (RegOpenKeyEx(HKEY_CURRENT_USER, regPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
          return "-1";
      }

      DWORD interval = 0;
      DWORD bufferSize = sizeof(interval);

      if (RegQueryValueEx(hKey, "Interval", NULL, NULL, (LPBYTE)&interval, &bufferSize) == ERROR_SUCCESS) {
          RegCloseKey(hKey);          
 
          int intervalMinutes = interval / 1000 / 60;
          return std::to_string(intervalMinutes);
      } else  if (RegQueryValueEx(hKey, "LastTickHigh", NULL, NULL, (LPBYTE)&interval, &bufferSize) == ERROR_SUCCESS) {
          // defaul interval(=30min) is not stored, only detect the LastTickHigh key
          RegCloseKey(hKey);
          return std::to_string(30);     
      }else{
          RegCloseKey(hKey);
          return "-1";        
      }
  }

  std::string getDesktopWallpaperPath(){
    char wallpaperPath[MAX_PATH];    
    if (SystemParametersInfo(SPI_GETDESKWALLPAPER, MAX_PATH, wallpaperPath, 0) == false) {
        BOOST_LOG(error) << "could not get wallpaper background image path";
    }
    return wallpaperPath;
  }
  
  std::string getDesktopSolidColor(){
    COLORREF desktopColor = GetSysColor(COLOR_DESKTOP);

    int red = GetRValue(desktopColor);
    int green = GetGValue(desktopColor);
    int blue = GetBValue(desktopColor);

    std::stringstream ss;
    ss << "#" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << red
       << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << green
       << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << blue;

    BOOST_LOG(info) << "desktopbackground color (RGB): " <<  ss.str();
    return ss.str();
  }

  std::string GetCurrentTimestamp() {
    boost::posix_time::ptime currentTime = boost::posix_time::second_clock::local_time();

    std::string timestamp = boost::posix_time::to_iso_extended_string(currentTime);

    timestamp = timestamp.substr(0, 16);

    return timestamp;
  }

  void FillDesktopApp(pt::ptree &desktopApp, proc::ctx_t &proc){
    auto wallpapper = getDesktopWallpaperPath();        
    desktopApp.put("CustomImagePath", wallpapper);
    proc.custom_image_path = desktopApp.get<std::string>("CustomImagePath"s);

    auto bgType  = GetBackgroundTypeForCurrentUser();
    desktopApp.put("WallpaperType", bgType);
    if(bgType == "solidcolor")
      desktopApp.put("DesktopWallpaperColor", getDesktopSolidColor());

    desktopApp.put("WallpaperSildeIntervalMinute", GetSlideshowIntervalForCurrentuser());

    desktopApp.put("CurrentTimestamp", GetCurrentTimestamp());

    std::ostringstream tempdata;      
    pt::write_xml(tempdata, desktopApp);
    //BOOST_LOG(info) << tempdata.str();
  }
#endif

  void
  applist(resp_https_t response, req_https_t request) {
    print_req<SimpleWeb::HTTPS>(request);

    pt::ptree tree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;      
      pt::write_xml(data, tree);
      response->write(data.str());
     
      response->close_connection_after_response = true;
    });

    auto &apps = tree.add_child("root", pt::ptree {});

    apps.put("<xmlattr>.status_code", 200);

    auto count = 0;
    for (auto &proc : proc::proc.get_apps()) {
      pt::ptree app;
      count++;
      app.put("IsHdrSupported"s, video::active_hevc_mode == 3 ? 1 : 0);
      app.put("AppTitle"s, proc.name);
      app.put("ID", proc.id);
      app.put("GUID", proc.guid);
      
#if RAZER_MOD == 1
      //speical cover image for desktop
      if(proc.name == "Desktop"){
        FillDesktopApp(app, proc);
      }
      else{
        if(proc.custom_image_path.empty())
        {
          app.put("CustomImagePath", proc.image_path);
        }
        else
        {
          if(proc.custom_image_path.find("http") == std::string::npos)
          {
            app.put("CustomImagePath", "");
          }
          else
            app.put("CustomImagePath", proc.custom_image_path);
        }

        if(!proc.launch_type.empty())
        {
          app.put("GamePlatform", proc.launch_type);
        }
      }
#endif
      apps.push_back(std::make_pair("App", std::move(app)));
    }

    BOOST_LOG(info) << " Total applist size = " << count;
  }

  void
  launch(bool &host_audio, resp_https_t response, req_https_t request) {
    rz_print_req<SimpleWeb::HTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    if (rtsp_stream::session_count() == config::stream.channels) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 5031);
      tree.put("root.<xmlattr>.status_message", "The host's concurrent stream limit has been reached. Stop an existing stream or increase the 'Channels' value in Cortex Remote Play Host Settings.");

      return;
    }

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args) ||
      args.find("localAudioPlayMode"s) == std::end(args) ||
      args.find("appid"s) == std::end(args)) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required launch parameter");

      return;
    }

    auto appid = util::from_view(get_arg(args, "appid"));

    auto current_appid = proc::proc.running();

    if (current_appid > 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "An app is already running on this host");

      return;
    }
#if defined RAZER_MOD && RAZER_MOD == 1
    auto virtualDisplayType = get_arg(args, "virtualDisplay", "");
    BOOST_LOG(info) << "Launch Session: Do client ask for virtual display ? " << virtualDisplayType;
    if(virtualDisplayType == "1" || virtualDisplayType == "2")
    {
      platf::SaveCurrentAudioDevice();
      auto virtualDisplayMode = get_arg(args, "virtualDisplayMode", "1920x1080x60");
      const char* programData = std::getenv("ProgramData");
      if (programData) {
        std::filesystem::path programDataPath(programData);
        programDataPath /= "Razer";
        programDataPath /= "RemotePlayHost";
        programDataPath /= "VirtualDisplayConfig.txt";
        file_handler::write_file(programDataPath.string().c_str(), virtualDisplayMode);
      }

      std::stringstream ss;
      std::string IsOnlyVirtualDisplay = (virtualDisplayType == "2" ? "1" : "0");
      ss << virtualDisplayMode << "x" << IsOnlyVirtualDisplay;
      BOOST_LOG(info) << "Client ask for virtual display: " << ss.str();
      rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugin, "client", ss.str());
      BOOST_LOG(info) << "update event done.";

      auto funcDestroyVD = []() { 
        BOOST_LOG(info) << "delay check the session count " << rtsp_stream::session_count();
        if(rtsp_stream::session_count() <= 0){
          BOOST_LOG(info) << "destroy the virtual display";
          rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "abort_launch");
        }
      };
      _virtudal_display_stream_detect.start(funcDestroyVD, 30000); //30 seconds

      //FIXME!
      Sleep(4000);

      auto uiscale = get_arg(args, "UIscale", "-1");      
      if(uiscale != "-1")
            ui_scale::SetVirtualDisplayUIScaling(stoi(uiscale));
    }
    else
    {
      BOOST_LOG(info) << "No virtual display.";
    }

    auto timeToTerminateApp  = get_arg(args, "timeToTerminateApp", "-1");
    BOOST_LOG(info) << "Termiante applcaition countdown = " << timeToTerminateApp; 
    rz_state::SetCountdownTimer(timeToTerminateApp);
#endif

    // Probe encoders again before streaming to ensure our chosen
    // encoder matches the active GPU (which could have changed
    // due to hotplugging, driver crash, primary monitor change,
    // or any number of other factors).
    if (rtsp_stream::session_count() == 0) {
      if (video::probe_encoders()) {
        tree.put("root.<xmlattr>.status_code", 5032);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");
        tree.put("root.gamesession", 0);

#if RAZER_MOD == 1
        rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "GPU_failure");
#endif
        return;
      }
    }

    host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
#if RAZER_MOD == 1    
    if(config::audio.virtual_sink.length() > 0){
      //set to auto, force to 
      //steam -> razer - > current sink
      BOOST_LOG(info) << "audio sink set auto, we go with mute host flow";
      host_audio = false;
    }
#endif

    auto launch_session = make_launch_session(host_audio, args);

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);
#if RAZER_MOD == 1
        rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "encryption_failure");
#endif
      return;
    }


    if (appid > 0) {
      auto err = proc::proc.execute(appid, launch_session);
      if (err) {
        tree.put("root.<xmlattr>.status_code", err);
        tree.put("root.<xmlattr>.status_message", "Failed to start the specified application");
        tree.put("root.gamesession", 0);
#if RAZER_MOD == 1
        rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "launchApp_failure");
#endif
        return;
      }
    }

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.sessionUrl0", launch_session->rtsp_url_scheme +
                                   net::addr_to_url_escaped_string(request->local_endpoint().address()) + ':' +
                                   std::to_string(net::map_port(rtsp_stream::RTSP_SETUP_PORT)));
    tree.put("root.gamesession", 1);

#if RAZER_MOD ==1 
    current_device_nickname = url_decode(get_arg(args, "devicenickname", ""));
#endif

    BOOST_LOG(info) << "launch_session_raise";
    rtsp_stream::launch_session_raise(launch_session);
    BOOST_LOG(info) << "launch_session_raise end";
  }

  void
  resume(bool &host_audio, resp_https_t response, req_https_t request) {
    rz_print_req<SimpleWeb::HTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    // It is possible that due a race condition that this if-statement gives a false negative,
    // that is automatically resolved in rtsp_server_t
    if (rtsp_stream::session_count() == config::stream.channels) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 5031);
      tree.put("root.<xmlattr>.status_message", "The host's concurrent stream limit has been reached. Stop an existing stream or increase the 'Channels' value in Cortex Remote Play Host Settings.");

      return;
    }

    auto current_appid = proc::proc.running();
    if (current_appid == 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 5033);
      tree.put("root.<xmlattr>.status_message", "No running app to resume");

      return;
    }

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args)) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required resume parameter");

      return;
    }

#if defined RAZER_MOD && RAZER_MOD == 1
    auto virtualDisplayType = get_arg(args, "virtualDisplay", "");
    BOOST_LOG(info) << "Resume Session: Do client ask for virtual display ? " << virtualDisplayType;
    if(virtualDisplayType == "1" || virtualDisplayType == "2")
    {
      platf::SaveCurrentAudioDevice();
      auto virtualDisplayMode = get_arg(args, "virtualDisplayMode", "1920x1080x60");
      const char* programData = std::getenv("ProgramData");
      if (programData) {
        std::filesystem::path programDataPath(programData);
        programDataPath /= "Razer";
        programDataPath /= "RemotePlayHost";
        programDataPath /= "VirtualDisplayConfig.txt";
        file_handler::write_file(programDataPath.string().c_str(), virtualDisplayMode);
      }

      std::stringstream ss;
      std::string IsOnlyVirtualDisplay = (virtualDisplayType == "2" ? "1" : "0");
      ss << virtualDisplayMode << "x" << IsOnlyVirtualDisplay;
      BOOST_LOG(info) << "Client ask for virtual display: " << ss.str();
      rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugin, "client", ss.str());
      BOOST_LOG(info) << "update event done.";
      //FIXME!
      Sleep(4000);
      auto uiscale = get_arg(args, "UIscale", "-1");      
      if(uiscale != "-1")
            ui_scale::SetVirtualDisplayUIScaling(stoi(uiscale));

      auto funcDestroyVD = []() { 
        BOOST_LOG(info) << "delay check the session count " << rtsp_stream::session_count();
        if(rtsp_stream::session_count() <= 0){
          BOOST_LOG(info) << "destroy the virtual display";
          rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "abort_launch");
        }
      };
      _virtudal_display_stream_detect.start(funcDestroyVD, 30000); //30 seconds
    }
    else
    {
      BOOST_LOG(info) << "No virtual display.";
    }

    auto timeToTerminateApp  = get_arg(args, "timeToTerminateApp", "-1");
    BOOST_LOG(info) << "Termiante applcaition countdown = " << timeToTerminateApp; 
    rz_state::SetCountdownTimer(timeToTerminateApp);
#endif

    if (rtsp_stream::session_count() == 0) {
      // Probe encoders again before streaming to ensure our chosen
      // encoder matches the active GPU (which could have changed
      // due to hotplugging, driver crash, primary monitor change,
      // or any number of other factors).
      if (video::probe_encoders()) {
        tree.put("root.resume", 0);
        tree.put("root.<xmlattr>.status_code", 5032);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");
#if RAZER_MOD == 1
        rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "GPU_failure");
#endif
        return;
      }

      // Newer Moonlight clients send localAudioPlayMode on /resume too,
      // so we should use it if it's present in the args and there are
      // no active sessions we could be interfering with.
      if (args.find("localAudioPlayMode"s) != std::end(args)) {
        host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
        #if RAZER_MOD == 1    
        if(config::audio.virtual_sink.length() != 0){
          //wheter auto or not, force to 
          //steam -> razer - > current sink
          // current sink is not mute actually 
          BOOST_LOG(info) << "audio sink set auto, we go with mute host flow";
          host_audio = false;
        }
        #endif
      }
    }

    auto launch_session = make_launch_session(host_audio, args);

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);
#if RAZER_MOD == 1
      rz_state::updateEvent(Command_Protocol_VirtualDisplay_Plugout, "client", "Encryption_failure");
#endif
      return;
    }

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.sessionUrl0", launch_session->rtsp_url_scheme +
                                   net::addr_to_url_escaped_string(request->local_endpoint().address()) + ':' +
                                   std::to_string(net::map_port(rtsp_stream::RTSP_SETUP_PORT)));
    tree.put("root.resume", 1);

#if RAZER_MOD ==1 
    current_device_nickname = url_decode(get_arg(args, "devicenickname", ""));
    rz_state::CancelGameCloseCountdown();
#endif

    rtsp_stream::launch_session_raise(launch_session);
  }

  void
  cancel(resp_https_t response, req_https_t request) {
    print_req<SimpleWeb::HTTPS>(request);

    BOOST_LOG(info) << "Cancel Session..";

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    // It is possible that due a race condition that this if-statement gives a false positive,
    // the client should try again
    if (rtsp_stream::session_count() != 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 5034);
      tree.put("root.<xmlattr>.status_message", "All sessions must be disconnected before quitting");
      BOOST_LOG(warning) << "All sessions must be disconnected before quitting, session count =  " << rtsp_stream::session_count();
      return;
    }

    tree.put("root.cancel", 1);
    tree.put("root.<xmlattr>.status_code", 200);


    if (proc::proc.running() > 0) {
      #if RAZER_MOD == 1
      rz_state::ForceStopGameCloseCountdown();
      #endif
      BOOST_LOG(info) << "find a running applcaiton[" << proc::proc.get_last_run_app_name() << "], termiante it!";
      proc::proc.terminate();
    }
  }

  void
  appasset(resp_https_t response, req_https_t request) {
    rz_print_req<SimpleWeb::HTTPS>(request);

    auto args = request->parse_query_string();
    auto app_image = proc::proc.get_app_image(util::from_view(get_arg(args, "appid")));

    std::ifstream in(app_image, std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    if(in.is_open() == false)
    {
      BOOST_LOG(error) << " appasset open file failed";
      response->write(SimpleWeb::StatusCode::success_no_content, headers);
    }
    else
      response->write(SimpleWeb::StatusCode::success_ok, in, headers);

    response->close_connection_after_response = true;
  }

  /**
   * @brief Start the nvhttp server.
   *
   * EXAMPLES:
   * ```cpp
   * nvhttp::start();
   * ```
   */
  void
  start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_http = net::map_port(PORT_HTTP);
    auto port_https = net::map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];

    if (!clean_slate) {
      load_state();
    }

    conf_intern.pkey = file_handler::read_file(config::nvhttp.pkey.c_str());
    conf_intern.servercert = file_handler::read_file(config::nvhttp.cert.c_str());

    for (auto &[_, client] : map_id_client) {
      for (auto &cert : client.certs) {
        cert_chain.add(crypto::x509(cert));
      }
    }

    auto add_cert = std::make_shared<safe::queue_t<crypto::x509_t>>(30);

    // resume doesn't always get the parameter "localAudioPlayMode"
    // launch will store it in host_audio
    bool host_audio {};

    https_server_t https_server { config::nvhttp.cert, config::nvhttp.pkey };
    http_server_t http_server;

    // Verify certificates after establishing connection
    https_server.verify = [add_cert](SSL *ssl) {
      crypto::x509_t x509 { SSL_get_peer_certificate(ssl) };
      if (!x509) {
        BOOST_LOG(info) << "unknown -- denied"sv;
        return 0;
      }

      int verified = 0;

      auto fg = util::fail_guard([&]() {
        char subject_name[256];

        X509_NAME_oneline(X509_get_subject_name(x509.get()), subject_name, sizeof(subject_name));

        BOOST_LOG(debug) << subject_name << " -- "sv << (verified ? "verified"sv : "denied"sv);
      });

      while (add_cert->peek()) {
        char subject_name[256];

        auto cert = add_cert->pop();
        X509_NAME_oneline(X509_get_subject_name(cert.get()), subject_name, sizeof(subject_name));

        BOOST_LOG(debug) << "Added cert ["sv << subject_name << ']';
        cert_chain.add(std::move(cert));
      }

      auto err_str = cert_chain.verify(x509.get());
      if (err_str) {
        BOOST_LOG(warning) << "SSL Verification error :: "sv << err_str;

        return verified;
      }

      verified = 1;

      return verified;
    };

    https_server.on_verify_failed = [](resp_https_t resp, req_https_t req) {
      pt::ptree tree;
      auto g = util::fail_guard([&]() {
        std::ostringstream data;

        pt::write_xml(data, tree);
        resp->write(data.str());
        resp->close_connection_after_response = true;
      });

      tree.put("root.<xmlattr>.status_code"s, 401);
      tree.put("root.<xmlattr>.query"s, req->path);
      tree.put("root.<xmlattr>.status_message"s, "The client is not authorized. Certificate verification failed."s);
    };

    https_server.default_resource["GET"] = not_found<SimpleWeb::HTTPS>;
    https_server.resource["^/serverinfo$"]["GET"] = serverinfo<SimpleWeb::HTTPS>;
    https_server.resource["^/pair$"]["GET"] = [&add_cert](auto resp, auto req) { pair<SimpleWeb::HTTPS>(add_cert, resp, req); };
    https_server.resource["^/applist$"]["GET"] = applist;
    https_server.resource["^/appasset$"]["GET"] = appasset;
    https_server.resource["^/launch$"]["GET"] = [&host_audio](auto resp, auto req) { launch(host_audio, resp, req); };
    https_server.resource["^/resume$"]["GET"] = [&host_audio](auto resp, auto req) { resume(host_audio, resp, req); };
    https_server.resource["^/cancel$"]["GET"] = cancel;

    https_server.config.reuse_address = true;
    https_server.config.address = net::af_to_any_address_string(address_family);
    https_server.config.port = port_https;

    http_server.default_resource["GET"] = not_found<SimpleWeb::HTTP>;
    http_server.resource["^/serverinfo$"]["GET"] = serverinfo<SimpleWeb::HTTP>;
    http_server.resource["^/pair$"]["GET"] = [&add_cert](auto resp, auto req) { pair<SimpleWeb::HTTP>(add_cert, resp, req); };

    http_server.config.reuse_address = true;
    http_server.config.address = net::af_to_any_address_string(address_family);
    http_server.config.port = port_http;

    auto accept_and_run = [&](auto *http_server) {
      try {
        http_server->start();
      }
      catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling http_server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start http server on ports ["sv << port_https << ", "sv << port_https << "]: "sv << err.what();
        rz_state::message_state_t tmpmsg;
        rz_state::SendEventToCortex(rz_state::CortexEvent::Cortex_Event_Change_HTTP_Port, tmpmsg);
        shutdown_event->raise(true);
        return;
      }
    };
    std::thread ssl { accept_and_run, &https_server };
    std::thread tcp { accept_and_run, &http_server };

    // Wait for any event
    shutdown_event->view();

    https_server.stop();
    http_server.stop();

    ssl.join();
    tcp.join();
  }

  /**
   * @brief Remove all paired clients.
   *
   * EXAMPLES:
   * ```cpp
   * nvhttp::erase_all_clients();
   * ```
   */
  void
  erase_all_clients() {
    map_id_client.clear();
    cert_chain.clear();
    save_state();
  }
}  // namespace nvhttp
