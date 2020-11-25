#include <iostream>
#include <random>

// Test vector generator for MT19937 (32- and 64-bit)
int main() {
    std::mt19937 rng(5489);
    std::mt19937_64 rng_64(5489);

    std::cout << "MT19937 (32-bit) values: " << std::endl << std::endl;

    for (int i=0; i < 16; i++) {
        std::cout << rng() << ", ";
	if (i % 8 == 7) {
            std::cout << std::endl;
	}
    }

    std::cout << std::endl << "MT19937 (64-bit) values: " << std::endl << std::endl;

    for (int i=0; i < 16; i++) {
        std::cout << rng_64() << ", ";
	if (i % 8 == 7) {
            std::cout << std::endl;
	}
    }

    std::cout << std::endl;

    return 0;
}
