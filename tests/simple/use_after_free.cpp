/*
 * Use After Free Example
 *
 * This program demonstrates use-after-free vulnerabilities
 * where memory is accessed after being deallocated.
 */

#include <iostream>
#include <cstring>

// Simple data structure
struct DataBlock {
    int id;
    char content[128];
    int* refCount;

    DataBlock(int i) : id(i), refCount(new int(1)) {
        std::cout << "DataBlock " << id << " created" << std::endl;
    }

    ~DataBlock() {
        (*refCount)--;
        if (*refCount == 0) {
            delete refCount;
        }
        std::cout << "DataBlock " << id << " destroyed" << std::endl;
    }

    void setContent(const char* data) {
        strncpy(content, data, sizeof(content) - 1);
        content[sizeof(content) - 1] = '\0';
    }

    void display() const {
        std::cout << "DataBlock " << id << ": " << content << std::endl;
    }
};

// Function that frees data - VULNERABLE CODE
void processDataAndFree(DataBlock* data) {
    data->display();

    // Free the memory
    delete data;

    // BUG: data pointer is now dangling but still accessible
    // Any use of 'data' here is a use-after-free vulnerability
}

// Function with conditional use after free - VULNERABLE CODE
void conditionalUseAfterFree(bool shouldFree) {
    DataBlock* block = new DataBlock(100);
    block->setContent("Important data");

    if (shouldFree) {
        delete block;
        // BUG: block is freed but still used below
    }

    // This line will use-after-free if shouldFree is true
    std::cout << "Block content: ";
    block->display();  // CRASH if shouldFree was true
}

// Function with use after free in error path - VULNERABLE CODE
void processWithErrorHandling(int value) {
    DataBlock* data = new DataBlock(200);
    data->setContent("Error handling data");

    if (value < 0) {
        delete data;
        std::cerr << "Invalid value, data freed" << std::endl;
        return;
        // BUG: Early return after delete, but data might still be referenced
    }

    data->display();
    delete data;
}

// Function with double free scenario - VULNERABLE CODE
void doubleFreeScenario() {
    DataBlock* data = new DataBlock(300);
    data->setContent("Double free test");

    // First free
    delete data;

    // BUG: data is freed but still stored
    // If code tries to free again, it's double-free (related to use-after-free)
    if (data != nullptr) {  // This check doesn't help!
        delete data;  // DOUBLE FREE
    }
}

// Function with use after free via copy - VULNERABLE CODE
void useAfterFreeViaCopy() {
    DataBlock* original = new DataBlock(400);
    original->setContent("Original data");

    DataBlock* copy = original;
    delete original;

    // BUG: copy points to same memory, now freed
    copy->display();  // CRASH: use-after-free
}

// Function with C-style memory - VULNERABLE CODE
void cStyleUseAfterFree() {
    int* numbers = new int[10];
    for (int i = 0; i < 10; i++) {
        numbers[i] = i * 10;
    }

    // Display numbers
    std::cout << "Numbers: ";
    for (int i = 0; i < 10; i++) {
        std::cout << numbers[i] << " ";
    }
    std::cout << std::endl;

    // Free the memory
    delete[] numbers;

    // BUG: Try to access freed memory
    std::cout << "First number: " << numbers[0] << std::endl;  // UNDEFINED BEHAVIOR

    // BUG: Try to write to freed memory
    numbers[0] = 999;  // UNDEFINED BEHAVIOR
}

// Function with dangling reference - VULNERABLE CODE
DataBlock* createDanglingReference() {
    DataBlock* temp = new DataBlock(500);
    temp->setContent("Temporary data");

    // Process and delete
    temp->display();
    delete temp;

    // BUG: Returning pointer to freed memory
    return temp;  // DANGLING POINTER
}

int main() {
    // Test case 1: Simple use after free
    std::cout << "=== Test Case 1: Simple Use After Free ===" << std::endl;
    DataBlock* data1 = new DataBlock(1);
    data1->setContent("Test data 1");
    delete data1;
    data1->display();  // CRASH: use-after-free

    // Test case 2: Conditional use after free
    std::cout << "\n=== Test Case 2: Conditional Use After Free ===" << std::endl;
    conditionalUseAfterFree(true);  // Will crash

    // Test case 3: Use after free via copy
    std::cout << "\n=== Test Case 3: Use After Free Via Copy ===" << std::endl;
    useAfterFreeViaCopy();  // Will crash

    // Test case 4: C-style use after free
    std::cout << "\n=== Test Case 4: C-Style Use After Free ===" << std::endl;
    cStyleUseAfterFree();  // Undefined behavior

    // Test case 5: Dangling reference
    std::cout << "\n=== Test Case 5: Dangling Reference ===" << std::endl;
    DataBlock* dangling = createDanglingReference();
    dangling->display();  // CRASH: dangling pointer
    delete dangling;  // Double free!

    return 0;
}
