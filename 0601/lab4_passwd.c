#include <Arduino.h>
#include "mbedtls/sha512.h" // ✨ 變更為 SHA-512 標頭檔
#include <Adafruit_NeoPixel.h>

// =========================================================
// 實驗組別與硬體參數定義
// =========================================================
#define GROUP         "[Group0] " 
#define RGB_LED_PIN   48
#define NUM_PIXELS    1
#define MAX_USERS     30          

Adafruit_NeoPixel pixels(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);

// 狀態機定義
enum SystemState {
  CMD_WAIT,          
  REG_WAIT_USER,     
  REG_WAIT_PASS,     
  AUTH_WAIT_USER,    
  AUTH_WAIT_PASS     
};

SystemState currentState = CMD_WAIT;
String inputBuffer = "";
bool stringComplete = false;

String currentUsername = "";
String currentPassword = "";

// =========================================================
// 模擬 Linux /etc/shadow 記憶體資料庫結構 (升級為 SHA-512)
// =========================================================
struct ShadowEntry {
  String username;
  String salt;
  String hashHex; // ✨ SHA-512 產出的 Hex 字串會長達 128 個字元
  bool active = false;
};

ShadowEntry shadowTable[MAX_USERS];
int userCount = 0;

// =========================================================
// 密碼學核心：mbedTLS SHA-512 運算 (ESP32-S3 採軟體模擬，耗時較長)
// =========================================================
String computeSHA512(String data) {
  // 💡 運算時閃爍藍燈 (學生可以觀察到，因為軟體算 SHA-512 較慢，藍燈閃爍時間會比之前長)
  for(int i=0; i<3; i++) {
    pixels.setPixelColor(0, pixels.Color(0, 0, 80)); pixels.show(); delay(40);
    pixels.setPixelColor(0, pixels.Color(0, 0, 0));  pixels.show(); delay(40);
  }

  mbedtls_sha512_context ctx;
  uint8_t hash[64]; // ✨ SHA-512 產出 64 bytes (512 bits)
  
  mbedtls_sha512_init(&ctx);
  // 0 代表標準 SHA-512 (非 SHA-384)
  mbedtls_sha512_starts(&ctx, 0); 
  mbedtls_sha512_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_sha512_finish(&ctx, hash);
  mbedtls_sha512_free(&ctx);

  // 將 64 bytes 轉換為 128 字元的 Hex 字串
  String hexStr = "";
  for (int i = 0; i < 64; i++) {
    char buf[3];
    sprintf(buf, "%02X", hash[i]);
    hexStr += buf;
  }
  
  pixels.setPixelColor(0, pixels.Color(0, 40, 0)); pixels.show();
  return hexStr;
}

String generateRandomSalt() {
  String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  String salt = "";
  for (int i = 0; i < 8; i++) {
    salt += chars[esp_random() % chars.length()];
  }
  return salt;
}

// =========================================================
// 記憶體資料庫操作
// =========================================================
bool addUser(String user, String pass) {
  if (userCount >= MAX_USERS) {
    Serial.print(GROUP); Serial.println("❌ [錯誤] 系統記憶體資料庫已滿 (上限 30 組)，無法新增帳號！");
    return false;
  }
  
  for(int i=0; i<MAX_USERS; i++) {
    if(shadowTable[i].active && shadowTable[i].username == user) {
      Serial.print(GROUP); Serial.println("❌ [錯誤] 該帳號已存在於系統中！");
      return false;
    }
  }

  String salt = generateRandomSalt();
  String computedHash = computeSHA512(salt + pass);

  shadowTable[userCount].username = user;
  shadowTable[userCount].salt = salt;
  shadowTable[userCount].hashHex = computedHash;
  shadowTable[userCount].active = true;
  userCount++;

  Serial.println();
  Serial.print(GROUP); Serial.println("----------------- [ 新增帳號成功 ] -----------------");
  Serial.print(GROUP); Serial.printf("輸入帳號 : %s\n", user.c_str());
  Serial.print(GROUP); Serial.printf("輸入密碼 : %s\n", pass.c_str());
  Serial.print(GROUP); Serial.printf("隨機鹽值 (Salt): %s\n", salt.c_str());
  Serial.print(GROUP); Serial.printf("硬體計算之安全雜湊 (SHA-512 Hash):\n" GROUP "👉 %s\n", computedHash.c_str());
  // ✨ 標準 Linux $6$ 代表 SHA-512
  Serial.print(GROUP); Serial.printf("Linux 格式 shadow 紀錄:\n" GROUP "👉 $6$%s$%s\n", salt.c_str(), computedHash.c_str()); 
  Serial.print(GROUP); Serial.println("---------------------------------------------------\n");
  return true;
}

void verifyLogin(String user, String pass) {
  Serial.println();
  Serial.print(GROUP); Serial.println("----------------- [ 執行登入驗證 ] -----------------");
  Serial.print(GROUP); Serial.printf("學生輸入帳號: %s\n", user.c_str());
  Serial.print(GROUP); Serial.printf("學生輸入密碼: %s\n", pass.c_str());

  int userIdx = -1;
  for(int i=0; i<MAX_USERS; i++) {
    if(shadowTable[i].active && shadowTable[i].username == user) {
      userIdx = i;
      break;
    }
  }

  if (userIdx == -1) {
    Serial.print(GROUP); Serial.println("🔍 [檢查結果] 帳號不存在！");
    Serial.print(GROUP); Serial.println("❌ [驗證結果] 登入失敗 (Access Denied)");
    Serial.print(GROUP); Serial.println("---------------------------------------------------\n");
    return;
  }

  Serial.print(GROUP); Serial.println("🔍 [檢查結果] 帳號存在！");
  String systemSalt = shadowTable[userIdx].salt;
  String systemKnownHash = shadowTable[userIdx].hashHex;
  
  Serial.print(GROUP); Serial.printf("系統已知該帳號的 Salt: %s\n", systemSalt.c_str());
  Serial.print(GROUP); Serial.printf("系統紀錄的已知雜湊 (Known Hash):\n" GROUP "👉 %s\n", systemKnownHash.c_str());

  String inputComputedHash = computeSHA512(systemSalt + pass);
  Serial.print(GROUP); Serial.printf("本次輸入計算之雜湊 (Input Hash):\n" GROUP "👉 %s\n", inputComputedHash.c_str());

  if (inputComputedHash == systemKnownHash) {
    Serial.print(GROUP); Serial.println("✨ [比對結果] Hash 完全吻合！");
    Serial.print(GROUP); Serial.println("🔓 [驗證結果] 🔴 登入成功 (Login Success)！");
  } else {
    Serial.print(GROUP); Serial.println("⚠️ [比對結果] Hash 不符！密碼錯誤！");
    Serial.print(GROUP); Serial.println("❌ [驗證結果] 登入失敗 (Invalid Password)");
  }
  Serial.print(GROUP); Serial.println("---------------------------------------------------\n");
}

void listUsers() {
  pixels.setPixelColor(0, pixels.Color(0, 0, 80)); pixels.show(); delay(100);
  pixels.setPixelColor(0, pixels.Color(0, 40, 0)); pixels.show();

  Serial.println();
  Serial.print(GROUP); Serial.println("================================== [ Linux /etc/shadow 記憶體傾印 ] ==================================");
  Serial.print(GROUP); Serial.printf(" 當前系統帳號總數: %d / %d 組\n", userCount, MAX_USERS);
  Serial.print(GROUP); Serial.println("-----------------------------------------------------------------------------------------------------");
  Serial.print(GROUP); Serial.printf(" %-4s | %-12s | %-10s | %s\n", "編號", "使用者帳號", "鹽巴 (Salt)", "安全雜湊值 (SHA-512 Hash)");
  Serial.print(GROUP); Serial.println("-----------------------------------------------------------------------------------------------------");
  
  int printedCount = 0;
  for (int i = 0; i < MAX_USERS; i++) {
    if (shadowTable[i].active) {
      Serial.print(GROUP); Serial.printf(" [%02d] | %-12s | %-10s | %s\n", 
                    printedCount + 1,
                    shadowTable[i].username.c_str(), 
                    shadowTable[i].salt.c_str(), 
                    shadowTable[i].hashHex.c_str());
      printedCount++;
    }
  }
  
  if (printedCount == 0) {
    Serial.print(GROUP); Serial.println(" (系統資料庫目前空無一人) ");
  }
  Serial.print(GROUP); Serial.println("=====================================================================================================\n");
}

// =========================================================
// Setup & Loop 主程式
// =========================================================
void setup() {
  Serial.begin(115200);
  while(!Serial);

  pixels.begin();
  pixels.clear();
  pixels.setPixelColor(0, pixels.Color(0, 40, 0)); 
  pixels.show();

  // 預載兩組預設帳號
  addUser("admin", "nust1234"); 
  addUser("student", "nust1234"); 

  Serial.println();
  Serial.print(GROUP); Serial.println("=================================================");
  Serial.print(GROUP); Serial.println("   🐧 ESP32-S3 Linux 內核密碼安全防護實驗室 🐧");
  Serial.print(GROUP); Serial.println("=================================================");
  Serial.print(GROUP); Serial.println("系統已就緒。目前板載 RGB 顯示【綠燈】代表安全待命。");
  Serial.print(GROUP); Serial.println("⚠️  特別說明：Linux $6$ 規範為 SHA-512，在本款晶片上採純軟體模擬。");
  Serial.print(GROUP); Serial.println("👉 請輸入 [login]      開始登入模擬");
  Serial.print(GROUP); Serial.println("👉 請輸入 [add]        開始建立新帳號");
  Serial.print(GROUP); Serial.println("👉 請輸入 [list users] 顯示核心密碼與鹽巴清單");
  Serial.print(GROUP); Handshake: Serial.println("-------------------------------------------------");
}

void loop() {
  while (Serial.available()) {
    char inChar = (char)Serial.read();
    if (inChar == '\n') {
      stringComplete = true;
    } else if (inChar != '\r') {
      inputBuffer += inChar;
    }
  }

  if (stringComplete) {
    inputBuffer.trim();
    
    if (inputBuffer.length() > 0) {
      switch (currentState) {
        case CMD_WAIT:
          if (inputBuffer.equalsIgnoreCase("login")) {
            Serial.println();
            Serial.print(GROUP); Serial.println("[進入登入程序] 請輸入「帳號 (Username)」:");
            currentState = AUTH_WAIT_USER;
          } else if (inputBuffer.equalsIgnoreCase("add")) {
            Serial.println();
            Serial.print(GROUP); Serial.println("[進入註冊程序] 請輸入欲建立的「新帳號 (New Username)」:");
            currentState = REG_WAIT_USER;
          } else if (inputBuffer.equalsIgnoreCase("list users")) {
            listUsers();
            Serial.print(GROUP); Serial.println(">>> 系統回到待命狀態。請輸入 [login], [add] 或 [list users]");
          } else {
            Serial.print(GROUP); Serial.println("❌ 未知指令。請輸入 [login], [add] 或 [list users]");
          }
          break;

        case REG_WAIT_USER:
          currentUsername = inputBuffer;
          Serial.print(GROUP); Serial.printf("帳號設定為: %s\n", currentUsername.c_str());
          Serial.print(GROUP); Serial.println("請輸入該帳號的「密碼 (Password)」:");
          currentState = REG_WAIT_PASS;
          break;

        case REG_WAIT_PASS:
          currentPassword = inputBuffer;
          addUser(currentUsername, currentPassword);
          Serial.print(GROUP); Serial.println(">>> 系統回到待命狀態。請輸入 [login], [add] 或 [list users]");
          currentState = CMD_WAIT;
          break;

        case AUTH_WAIT_USER:
          currentUsername = inputBuffer;
          Serial.print(GROUP); Serial.printf("輸入帳號: %s\n", currentUsername.c_str());
          Serial.print(GROUP); Serial.println("請輸入「密碼 (Password)」:");
          currentState = AUTH_WAIT_PASS;
          break;

        case AUTH_WAIT_PASS:
          currentPassword = inputBuffer;
          verifyLogin(currentUsername, currentPassword);
          Serial.print(GROUP); Serial.println(">>> 系統回到待命狀態。請輸入 [login], [add] 或 [list users]");
          currentState = CMD_WAIT;
          break;
      }
    }
    inputBuffer = "";
    stringComplete = false;
  }
}
