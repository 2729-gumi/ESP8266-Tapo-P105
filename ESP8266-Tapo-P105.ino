#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#include "Hash.h"
#include <Arduino_JSON.h>

// Base64 Library by Arturo Guadalupi
// To avoid header name confliction, 
// create "agdl_Base.h" in the Base64 Library directory.
// In "agdl_Base.h", write the following statement.
// #include "Base64.h"
#include "agdl_Base64.h"


// WiFi config
const char WIFI_SSID[] = "XXXXXXXXXXXXX";
const char WIFI_PASS[] = "xxxxxxxxxxxxx";


// Tapo P105 config
const char tapo_p105_email[] = "xxxxxxxxxxxxxxxx@yyyyy.zzz";
const char tapo_p105_password[] = "xxxxxxxxxxxxx";
const char tapo_p105_ip_address[] = "192.168.x.x";
const char tapo_p105_mac_address[] = "XX-XX-XX-XX-XX-XX";


const char rsa_private_key[] = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END RSA PRIVATE KEY-----
)EOF";

const char rsa_public_key[] = R"EOF(
-----BEGIN PUBLIC KEY-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXX
-----END PUBLIC KEY-----
)EOF";


HTTPClient http;

void setup() {
  // put your setup code here, to run once:

  delay(1000);
  
  /*** Serial Initialization ***/
  Serial.begin(115200);
  Serial.println();

  /*** WiFi Initialization ***/
  WiFi.persistent(false); // ! Important !
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("Waiting for WiFi connection.");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.println(" Finished !");

  delay(100);

  
  tapo_p105_init(tapo_p105_ip_address, tapo_p105_mac_address);

  tapo_p105_handshake(rsa_private_key, rsa_public_key);
  Serial.println("Tapo P105 Handshake Finished !");
  
  tapo_p105_login(tapo_p105_email, tapo_p105_password);
  Serial.println("Tapo P105 Login Finished !");

  tapo_p105_switch(true);
  Serial.println("Tapo P105 Trun ON !");

  delay(5000);
  
  tapo_p105_switch(false);
  Serial.println("Tapo P105 Turn OFF !");
 
}


void loop() {
  // put your main code here, to run repeatedly:

}


uint8_t _tplink_cipher_key[16], _tplink_cipher_iv[16];
String _tapo_p105_cookie_sessionid;
String _tapo_p105_token;
String _tapo_p105_ip_address;
String _tapo_p105_terminal_uuid;


void tplink_cipher_init(uint8_t b_arr[], uint8_t b_arr2[]){
  memcpy(_tplink_cipher_key, b_arr, 16);
  memcpy(_tplink_cipher_iv, b_arr2, 16);
}


String tplink_cipher_encrypt(String plain_data){
  int i;
  // PKCS#7 Padding (Encryption), Block Size : 16
  int len = plain_data.length();
  int n_blocks = len / 16 + 1;
  uint8_t n_padding = n_blocks * 16 - len;
  uint8_t data[n_blocks*16];
  memcpy(data, plain_data.c_str(), len);
  for(i = len; i < n_blocks * 16; i++){
    data[i] = n_padding;
  }

  // AES CBC Encryption
  uint8_t key[16], iv[16];
  memcpy(key, _tplink_cipher_key, 16);
  memcpy(iv, _tplink_cipher_iv, 16);

  // encryption context
  br_aes_big_cbcenc_keys encCtx;

  // reset the encryption context and encrypt the data
  br_aes_big_cbcenc_init(&encCtx, key, 16);
  br_aes_big_cbcenc_run( &encCtx, iv, data, n_blocks*16 );

  // Base64 Encode
  len = n_blocks*16;
  char encoded_data[ Base64.encodedLength(len) ];
  Base64.encode(encoded_data, (char *)data, len);
  
  return String(encoded_data);
}


String tplink_cipher_decrypt(String encoded_data_str){
  
  // Base64 Decode
  int input_len = encoded_data_str.length();
  char *encoded_data = const_cast<char*>(encoded_data_str.c_str());
  int len = Base64.decodedLength(encoded_data, input_len);
  uint8_t data[ len ];
  Base64.decode((char *)data, encoded_data, input_len);
  
  // AES CBC Decryption
  uint8_t key[16], iv[16];
  memcpy(key, _tplink_cipher_key, 16);
  memcpy(iv, _tplink_cipher_iv, 16);

  int n_blocks = len / 16;

  br_aes_big_cbcdec_keys decCtx;

  br_aes_big_cbcdec_init(&decCtx, key, 16);
  br_aes_big_cbcdec_run( &decCtx, iv, data, n_blocks*16 );  //Important ! iv mo swap.

  // PKCS#7 Padding (Decryption)
  uint8_t n_padding = data[n_blocks*16-1];
  len = n_blocks*16 - n_padding;
  char plain_data[len + 1];
  memcpy(plain_data, data, len);
  plain_data[len] = '\0';

  return String(plain_data);
}


void tapo_p105_init(String ip_address, String mac_address) {
  _tapo_p105_ip_address = ip_address;
  _tapo_p105_terminal_uuid = mac_address;
}


void tapo_p105_handshake(const char private_key[], const char public_key[]) {
  
  http.begin("http://" + _tapo_p105_ip_address + "/app");
  const char *headers[] = {"Set-Cookie"};
  http.collectHeaders(headers, 1);

  JSONVar params;
  params["key"] = public_key;

  JSONVar payload;
  payload["method"] = "handshake";
  payload["params"] = params;
  payload["requestTimeMils"] = millis();

  String payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println(payload_str);

  payload = JSON.parse(payload_str);
  String key_str = (const char *)payload["result"]["key"];
  // Serial.println(key_str);


  int input_len = key_str.length();
  char *key = const_cast<char*>(key_str.c_str());
  int len = Base64.decodedLength(key, input_len);
  uint8_t data[len];
  Base64.decode((char *)data, key, input_len);

  int i;
  //for(i = 0; i < len; i++) {
  //  Serial.printf("%02x", data[i]);
  //}
  //Serial.println();


  // RSA PKCS#1 V1.5 Padding Encryption
  BearSSL::PrivateKey *private_key_obj = new BearSSL::PrivateKey(private_key);
  
  (*br_rsa_private_get_default())(data, private_key_obj->getRSA());
  for(i = 2; i < len; i++){
    if(data[i] == 0) break;
  }
  i++;
  len -= i;

  uint8_t decoded_data[len];
  memcpy(decoded_data, &data[i], len);
  
  //for(i = 0; i < len; i++) {
  //  Serial.printf("%02x", decoded_data[i]);
  //}
  //Serial.println();

  // Obtain Key & IV

  uint8_t b_arr[16], b_arr2[16];
  memcpy(b_arr, decoded_data, 16);        //key
  memcpy(b_arr2, &decoded_data[16], 16);  //iv

  tplink_cipher_init(b_arr, b_arr2);

  // Obtain Cookie
  
  String set_cookie = http.header("Set-Cookie");
  //Serial.println(set_cookie);

  int idx = set_cookie.indexOf("TP_SESSIONID=");
  String cookie_sessionid = set_cookie.substring(idx);
  idx = cookie_sessionid.indexOf(";");
  _tapo_p105_cookie_sessionid = cookie_sessionid.substring(0, idx);
  //Serial.println(_tapo_p105_cookie_sessionid);
  
}


void tapo_p105_login(String email, String password) {

  int len = password.length();
  char encoded_password[ Base64.encodedLength(len) ];
  Base64.encode(encoded_password, const_cast<char*>(password.c_str()), len);
  //Serial.println(encoded_password);

  String email_digest = sha1(email);
  //Serial.println(email_digest);

  len = email_digest.length();
  char encoded_email[ Base64.encodedLength(len) ];
  Base64.encode(encoded_email, const_cast<char*>(email_digest.c_str()), len);
  //Serial.println(encoded_email);


  http.begin("http://" + _tapo_p105_ip_address + "/app");
  http.addHeader("Cookie", _tapo_p105_cookie_sessionid);

  JSONVar params;
  params["username"] = encoded_email;
  params["password"] = encoded_password;  

  JSONVar payload;
  payload["method"] = "login_device";
  payload["params"] = params;
  payload["requestTimeMils"] = millis();

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = tplink_cipher_encrypt(payload_str);

  params = JSONVar();
  params["request"] = encrypted_payload;
  
  payload = JSONVar();
  payload["method"] = "securePassthrough";
  payload["params"] = params;  
  
  payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println(payload_str);


  payload = JSON.parse(payload_str);
  String response = (const char *)payload["result"]["response"];
  String decrypted_response_str = tplink_cipher_decrypt(response);
  //Serial.println(decrypted_response_str);

  JSONVar decrypted_response = JSON.parse(decrypted_response_str);
  _tapo_p105_token = (const char *)decrypted_response["result"]["token"];
  //Serial.println(_tapo_p105_token);

}


void tapo_p105_switch(bool state) {

  http.begin("http://" + _tapo_p105_ip_address + "/app?token=" + _tapo_p105_token);
  http.addHeader("Cookie", _tapo_p105_cookie_sessionid);

  JSONVar params;
  params["device_on"] = state;

  JSONVar payload;
  payload["method"] = "set_device_info";
  payload["params"] = params;
  payload["requestTimeMils"] = millis();
  payload["terminalUUID"] = _tapo_p105_terminal_uuid;

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = tplink_cipher_encrypt(payload_str);

  params = JSONVar();
  params["request"] = encrypted_payload;
  
  payload = JSONVar();
  payload["method"] = "securePassthrough";
  payload["params"] = params;  
  
  payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println(payload_str);

}
