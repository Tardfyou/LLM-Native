/*
 * Buffer Overflow Example
 *
 * This program demonstrates buffer overflow vulnerabilities
 * where data is written beyond the bounds of allocated memory.
 */

#include <iostream>
#include <cstring>
#include <string>

// Simple user profile structure
struct UserProfile {
    char username[64];
    char email[64];
    int userId;

    UserProfile(int id) : userId(id) {
        username[0] = '\0';
        email[0] = '\0';
    }
};

// Function that copies username - VULNERABLE CODE
void setUsername(UserProfile* profile, const char* name) {
    // BUG: No bounds checking - buffer can overflow
    // If name is longer than 63 characters, it will overflow
    strcpy(profile->username, name);
    std::cout << "Username set to: " << profile->username << std::endl;
}

// Function that copies email - VULNERABLE CODE
void setEmail(UserProfile* profile, const char* email) {
    // BUG: No bounds checking - buffer can overflow
    strcpy(profile->email, email);
    std::cout << "Email set to: " << profile->email << std::endl;
}

// Function that processes user data - VULNERABLE CODE
void processUserData(char* buffer, int size, const char* data) {
    // BUG: No size validation - can overflow buffer
    // If data is longer than size, it will overflow
    memcpy(buffer, data, strlen(data));
    std::cout << "Data processed: " << buffer << std::endl;
}

// Function that concatenates paths - VULNERABLE CODE
void buildPath(char* dest, const char* base, const char* filename) {
    // BUG: No bounds checking on destination buffer
    // If combined path exceeds buffer size, overflow occurs
    strcpy(dest, base);
    strcat(dest, "/");
    strcat(dest, filename);
    std::cout << "Path built: " << dest << std::endl;
}

// Function with array indexing - VULNERABLE CODE
void copyArray(int* dest, const int* src, int count, int destSize) {
    // BUG: No validation that count <= destSize
    // Can write beyond dest array bounds
    for (int i = 0; i < count; i++) {
        dest[i] = src[i];  // May overflow if count > destSize
    }
    std::cout << "Array copied" << std::endl;
}

int main() {
    // Test case 1: Username buffer overflow
    std::cout << "=== Test Case 1: Username Overflow ===" << std::endl;
    UserProfile* profile1 = new UserProfile(1);
    char longName[100];
    memset(longName, 'A', 99);
    longName[99] = '\0';
    setUsername(profile1, longName);  // OVERFLOWS username[64]
    delete profile1;

    // Test case 2: Email buffer overflow
    std::cout << "\n=== Test Case 2: Email Overflow ===" << std::endl;
    UserProfile* profile2 = new UserProfile(2);
    char longEmail[100];
    memset(longEmail, 'B', 99);
    longEmail[99] = '\0';
    setEmail(profile2, longEmail);  // OVERFLOWS email[64]
    delete profile2;

    // Test case 3: Data buffer overflow
    std::cout << "\n=== Test Case 3: Data Buffer Overflow ===" << std::endl;
    char buffer[32];
    char largeData[100];
    memset(largeData, 'C', 99);
    largeData[99] = '\0';
    processUserData(buffer, 32, largeData);  // OVERFLOWS buffer[32]

    // Test case 4: Path concatenation overflow
    std::cout << "\n=== Test Case 4: Path Building Overflow ===" << std::endl;
    char path[64];
    char longBase[50];
    char longFile[50];
    memset(longBase, 'D', 49);
    longBase[49] = '\0';
    memset(longFile, 'E', 49);
    longFile[49] = '\0';
    buildPath(path, longBase, longFile);  // OVERFLOWS path[64]

    // Test case 5: Array bounds overflow
    std::cout << "\n=== Test Case 5: Array Index Overflow ===" << std::endl;
    int destArray[10];
    int srcArray[20];
    for (int i = 0; i < 20; i++) srcArray[i] = i;
    copyArray(destArray, srcArray, 20, 10);  // OVERFLOWS destArray[10]

    return 0;
}
