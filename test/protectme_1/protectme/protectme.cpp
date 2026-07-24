#include <iostream>
#include <Windows.h>

#include "Aegis64SDK.h"

__declspec(noinline) int UltimateVMTest(int seed) {

    Aegis64_Begin();

    int result = 0;
    int data_array[5] = { 15, 30, 45, 60, 75 };

    for (int i = 0; i < 5; i++) {
        result += data_array[i] ^ (i * 3);
    }

    int a = 1000;
    int b = -3;
    int div_res = a / b;    
    result += div_res;     

    volatile char small_val = (char)seed;
    small_val ^= 0xAA;
    small_val += 15;

    result += small_val;  

    if (result < 0) {
        result = ~result;  
        result <<= 2;       
    }
    else {
        result = (result & 0xFFFF) >> 1;
    }

    Aegis64_End();

    printf("[+] VM block exited. Intermediate internal state: %d\n", result);

    return result;
}

int main() {
    printf(" - Aegis64 Engine Test - \n");

    int final_result = UltimateVMTest(0x55);

    printf("[+] VM Execution Completed Safely.\n");
    printf("Final Decrypted State: 0x%X\n", final_result);

    system("pause");
    return 0;
}