#include "DES.h"

bitset<32> feistel(bitset<32> rightPart, bitset<48> subK) {
    // expand substitution
    bitset<48> expandR;
    for(int i = 0; i < 48; i++) {
        expandR[47-i] = rightPart[32-E[i]];
    }
    // nor
    expandR ^= subK;
    // s-box transform
    bitset<32> s_result;
    int x = 0;
	for(int i = 0; i < 48; i = i + 6) {
        int row = expandR[47-i]*2+expandR[47-i-5];
        int col = expandR[47-i-1]*8 + expandR[47-i-2]*4 + expandR[47-i-3]*2 + expandR[47-i-4];
        int num = S_BOX[i/6][row][col];

        bitset<4> binary(num);
        s_result[31-x]  = binary[3];
        s_result[31-x-1] = binary[2];
        s_result[31-x-2] = binary[1];
        s_result[31-x-3] = binary[0];

        x += 4;
    }
    // permutation
    bitset<32> output;
    for(int i = 0; i < 32; i++) {
        output[31-i] = s_result[32-feistelPermutation[i]];
    }

    return output;
}

bitset<28> leftShift(bitset<28> subK, int bits) {
    bitset<28> temp = subK;
    for(int i = 27; i >=0; i--) {
        if(i-bits >= 0)
            subK[i] = temp[i-bits];
        else    
            subK[i] = temp[i-bits+28];
    }
    return subK;
}

void generateKey() {
    bitset<56> realKey;
    bitset<28> C, D;
    bitset<48> key48;

    // Permutation
    for(int i = 0; i < 56; i++) {
        realKey[55-i] = secretKey[64-PC_1[i]];
    }

    // generate 16 subKey
    for(int round = 0; round < 16; round++) {
        // C and D
        for(int i = 0; i < 56; i++) {
            if(i < 28) D[i] = realKey[i];
            else       C[i-28] = realKey[i];
        }
        // leftShift
        C = leftShift(C, LSBits[round]);
        D = leftShift(D, LSBits[round]);
        // merge
        for(int i = 0; i < 56; i++) {
            if(i < 28) realKey[i] = D[i];
            else       realKey[i] = C[i-28];
        }
        // compress
        for(int i = 0; i < 48; i++) {
            key48[47-i] = realKey[56-PC_2[i]];
        }

        subKey[round] = key48;
    }
}

bitset<64> encrypt(bitset<64> plaintext) {
    bitset<64> currentBits;
    bitset<32> L, R;

    // Initial Permutation
    for(int i = 0; i < 64; i++) {
        currentBits[63-i] = plaintext[64-IP[i]];
    }

    // get L0 and R0
    for(int i = 0; i < 64; i++) {
        if (i < 32) 
            R[i] = currentBits[i];
        else
            L[i-32] = currentBits[i];
    }

    // T iteration
    for(int round = 0; round < 16; round++) {
        bitset<32> tempR = R;
        R = L ^ feistel(R, subKey[round]);
        L = tempR;
    }

    // merge to R-L (not L-R!)
    for(int i = 0; i < 64; i++) {
        if(i < 32)
            currentBits[i] = L[i];
        else
            currentBits[i] = R[i-32];
    }

    // IP-1 Permutation
    bitset<64> result;
    for(int i = 0; i < 64; i++) {
        result[63-i] = currentBits[64-IP_1[i]];
    }

    return result;
}

bitset<64> decrypt(bitset<64> cipher) {
    bitset<64> currentBits;
    bitset<32> L, R;

    // Initial Permutation
    for(int i = 0; i < 64; i++) {
        currentBits[63-i] = cipher[64-IP[i]];
    }

    // get L0 and R0
    for(int i = 0; i < 64; i++) {
        if (i < 32) 
            R[i] = currentBits[i];
        else
            L[i-32] = currentBits[i];
    }

    // T iteration
    for(int round = 0; round < 16; round++) {
        bitset<32> tempR = R;
        R = L ^ feistel(R, subKey[15-round]);
        L = tempR;
    }

    // merge to R-L (not L-R!)
    for(int i = 0; i < 64; i++) {
        if(i < 32)
            currentBits[i] = L[i];
        else
            currentBits[i] = R[i-32];
    }

    // IP-1 Permutation
    bitset<64> result;
    for(int i = 0; i < 64; i++) {
        result[63-i] = currentBits[64-IP_1[i]];
    }

    return result;
}

// convert char[8] to binary
bitset<64> charToBitset(const char s[8])
{
	bitset<64> bits;
	for(int i=0; i<8; ++i)
		for(int j=0; j<8; ++j)
			bits[i*8+j] = ((s[i]>>j) & 1);
	return bits;
}

int main() {
    string s = "romantic";
    string k = "12345678";
    bitset<64> plain = charToBitset(s.c_str());
    secretKey        = charToBitset(k.c_str());

    generateKey();

    bitset<64> cipher = encrypt(plain);
    bitset<64> plain_ = decrypt(cipher);

	return 0;
}

