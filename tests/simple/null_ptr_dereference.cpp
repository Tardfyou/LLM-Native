/*
 * Null Pointer Dereference Example
 *
 * This program demonstrates a null pointer dereference vulnerability
 * where a pointer is used without proper null checking.
 */

#include <iostream>
#include <string>

// Simple user structure
struct User {
    int id;
    std::string name;
    int age;

    User(int i, const std::string& n, int a) : id(i), name(n), age(a) {}

    void display() const {
        std::cout << "User ID: " << id << ", Name: " << name << ", Age: " << age << std::endl;
    }
};

// Function that creates a user
User* createUser(int id, const std::string& name, int age) {
    // VULNERABILITY: Returns nullptr for invalid id
    if (id <= 0) {
        return nullptr;
    }
    return new User(id, name, age);
}

// Function that processes user - VULNERABLE CODE
void processUser(User* user) {
    // BUG: No null check before dereferencing
    // This will crash if user is nullptr
    std::cout << "Processing user: " << user->name << std::endl;
    user->display();
}

// Function that finds user by ID - VULNERABLE CODE
User* findUserById(int userId, User* users[], int size) {
    for (int i = 0; i < size; i++) {
        if (users[i] && users[i]->id == userId) {
            return users[i];
        }
    }
    // Returns nullptr if not found
    return nullptr;
}

// Function that updates user - VULNERABLE CODE
void updateUserAge(User* user, int newAge) {
    // BUG: No null check before dereferencing
    user->age = newAge;
    std::cout << "User age updated to: " << user->age << std::endl;
}

int main() {
    // Test case 1: Null pointer from createUser
    std::cout << "=== Test Case 1: Invalid User ID ===" << std::endl;
    User* user1 = createUser(-1, "Alice", 25);
    processUser(user1);  // CRASH: dereferences nullptr

    // Test case 2: Null pointer from findUserById
    std::cout << "\n=== Test Case 2: User Not Found ===" << std::endl;
    User* users[] = {
        new User(1, "Bob", 30),
        new User(2, "Charlie", 35)
    };
    User* user2 = findUserById(999, users, 2);
    processUser(user2);  // CRASH: dereferences nullptr

    // Test case 3: Null pointer passed directly
    std::cout << "\n=== Test Case 3: Direct Null Pointer ===" << std::endl;
    User* user3 = nullptr;
    updateUserAge(user3, 40);  // CRASH: dereferences nullptr

    // Clean up (won't reach here due to crashes)
    for (int i = 0; i < 2; i++) {
        delete users[i];
    }

    return 0;
}
