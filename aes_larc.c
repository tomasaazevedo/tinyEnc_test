/**
 * Curupira2.c
 *
 * The Curupira-2 block cipher
 * designed by Marcos A. Simplicio Jr. and Paulo S. L. M. Barreto
 * This version is restricted (and optimized) to 96-bit keys.
 *
 * @author Marcos A. Simplicio Jr
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*********************************************************************************
*                                  CONFIGURATION                                 *
**********************************************************************************/

//#include <avr/eeprom.h>
#define __CURUPIRA_CIPHER__

#include <xc.h>
#define _XTAL_FREQ        8192000UL
//============== CONFIGURATION WORD ===============
// Watchdog Timer
#pragma config WDTE = OFF

/***************************************************************************
*					             DEFINES   							       *
****************************************************************************/

//------------------------ PLATFORM ------------------------------------

#ifndef u8
#define u8 unsigned char
#endif

//Used to indicate that data is stored as program-memory (not RAM)
//You may need to edit this. The following defines can be used when
//there is EEPROM available or when an AVR device is used
#ifndef PROGMEM
	#define PROGMEM
	//#define PROGMEM EEMEM
	#ifndef rb
		#define rb(value) *(value)
		//#define rb(value) eeprom_read_byte((u8*)value)
	#endif
#endif

//Used to print data when debugging/testing
// #ifndef dbsp
// 	#define dbsp printf
// #endif
// #ifndef dbch
// 	#define dbch(value) printf("%2x", value)
// #endif

//------------- OPTIMIZATIONS: pre-computed tables -------------//

//#define USE_TABS		//table for S-Box
//#define USE_TABX		//table for xtimes operation
//#define USE_TAB0		//table for T0 operation
//#define USE_TAB1		//table for T1 operation


//--------------- FUNCTIONALITIES ----------------//

//Enables the square-complete transform interface
//#define REQUIRE_SCT

//Indicates that 'Table 0' is present (used by Marvin and LetterSoup)
#define HAS_T0
#define HAS_T1


//---------------------------------- CONSTANTS ---------------------------------------

#define N_ROUNDS				10		//The number of rounds used by the Curupira-2 cipher
#define BLOCK_SIZE              12
#define KEY_SIZE				BLOCK_SIZE
#define BLOCK_SIZE_BITS         96

//------------------------ TESTS ------------------------------------

#define ENABLE_TESTS_CIPHER    //Enable tests

#ifdef ENABLE_TESTS_CIPHER
	//#define ENABLE_DEBUG_CIPHER    //Enables debugging
	void printMatrix(u8 matrix[]);
	void printvector(u8 vector[], u8 size);
#endif


/***********************************************************************************/


/***********************************************************************************
*			                  GLOBAL VARIABLES                                     *
************************************************************************************/

//--------------------------- COMPLETE S-BOX ---------------------------

#ifdef USE_TABS
//The 256-byte S-Box table
static const u8 PROGMEM tabS[256] = {
    0xba, 0x54, 0x2f, 0x74, 0x53, 0xd3, 0xd2, 0x4d,
    0x50, 0xac, 0x8d, 0xbf, 0x70, 0x52, 0x9a, 0x4c,
    0xea, 0xd5, 0x97, 0xd1, 0x33, 0x51, 0x5b, 0xa6,
    0xde, 0x48, 0xa8, 0x99, 0xdb, 0x32, 0xb7, 0xfc,
    0xe3, 0x9e, 0x91, 0x9b, 0xe2, 0xbb, 0x41, 0x6e,
    0xa5, 0xcb, 0x6b, 0x95, 0xa1, 0xf3, 0xb1, 0x02,
    0xcc, 0xc4, 0x1d, 0x14, 0xc3, 0x63, 0xda, 0x5d,
    0x5f, 0xdc, 0x7d, 0xcd, 0x7f, 0x5a, 0x6c, 0x5c,
    0xf7, 0x26, 0xff, 0xed, 0xe8, 0x9d, 0x6f, 0x8e,
    0x19, 0xa0, 0xf0, 0x89, 0x0f, 0x07, 0xaf, 0xfb,
    0x08, 0x15, 0x0d, 0x04, 0x01, 0x64, 0xdf, 0x76,
    0x79, 0xdd, 0x3d, 0x16, 0x3f, 0x37, 0x6d, 0x38,
    0xb9, 0x73, 0xe9, 0x35, 0x55, 0x71, 0x7b, 0x8c,
    0x72, 0x88, 0xf6, 0x2a, 0x3e, 0x5e, 0x27, 0x46,
    0x0c, 0x65, 0x68, 0x61, 0x03, 0xc1, 0x57, 0xd6,
    0xd9, 0x58, 0xd8, 0x66, 0xd7, 0x3a, 0xc8, 0x3c,
    0xfa, 0x96, 0xa7, 0x98, 0xec, 0xb8, 0xc7, 0xae,
    0x69, 0x4b, 0xab, 0xa9, 0x67, 0x0a, 0x47, 0xf2,
    0xb5, 0x22, 0xe5, 0xee, 0xbe, 0x2b, 0x81, 0x12,
    0x83, 0x1b, 0x0e, 0x23, 0xf5, 0x45, 0x21, 0xce,
    0x49, 0x2c, 0xf9, 0xe6, 0xb6, 0x28, 0x17, 0x82,
    0x1a, 0x8b, 0xfe, 0x8a, 0x09, 0xc9, 0x87, 0x4e,
    0xe1, 0x2e, 0xe4, 0xe0, 0xeb, 0x90, 0xa4, 0x1e,
    0x85, 0x60, 0x00, 0x25, 0xf4, 0xf1, 0x94, 0x0b,
    0xe7, 0x75, 0xef, 0x34, 0x31, 0xd4, 0xd0, 0x86,
    0x7e, 0xad, 0xfd, 0x29, 0x30, 0x3b, 0x9f, 0xf8,
    0xc6, 0x13, 0x06, 0x05, 0xc5, 0x11, 0x77, 0x7c,
    0x7a, 0x78, 0x36, 0x1c, 0x39, 0x59, 0x18, 0x56,
    0xb3, 0xb0, 0x24, 0x20, 0xb2, 0x92, 0xa3, 0xc0,
    0x44, 0x62, 0x10, 0xb4, 0x84, 0x43, 0x93, 0xc2,
    0x4a, 0xbd, 0x8f, 0x2d, 0xbc, 0x9c, 0x6a, 0x40,
    0xcf, 0xa2, 0x80, 0x4f, 0x1f, 0xca, 0xaa, 0x42,
};

//The S-Box function uses the complete table
#define sBox(value) (rb(tabS+(value)))

//--------------------------- MINI S-BOXES ---------------------------
#else

static const u8 P[16] = {
    0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC, 0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1
};

static const u8 Q[16] = {
    0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC, 0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8
};

static u8 sBox(const u8 u){	// The S-Box calculation
	u8 uHigh, uLow, tempU;

	//First pass
	uHigh = P[u >> 4];
	uLow  = Q[u & 0xF];

	//Second Pass
	tempU	= Q[(uHigh & 0xC) ^ (uLow >> 2)];
	uLow    = P[((uHigh << 2) & 0xC) ^ (uLow & 0x3)];

	//Third pass
	uHigh = P[(tempU & 0xC) ^ (uLow >> 2)];
	uLow  = Q[((tempU << 2) & 0xC) ^ (uLow & 0x3)];

	//Concatenation
	return (uHigh << 4) ^ uLow;
}

#endif

//-------------- X-TIMES OPPERATION --------------
#ifdef USE_TABX
static const u8 PROGMEM tabX[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
    0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE,
    0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
    0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
    0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
    0x4D, 0x4F, 0x49, 0x4B, 0x45, 0x47, 0x41, 0x43,
    0x5D, 0x5F, 0x59, 0x5B, 0x55, 0x57, 0x51, 0x53,
    0x6D, 0x6F, 0x69, 0x6B, 0x65, 0x67, 0x61, 0x63,
    0x7D, 0x7F, 0x79, 0x7B, 0x75, 0x77, 0x71, 0x73,
    0x0D, 0x0F, 0x09, 0x0B, 0x05, 0x07, 0x01, 0x03,
    0x1D, 0x1F, 0x19, 0x1B, 0x15, 0x17, 0x11, 0x13,
    0x2D, 0x2F, 0x29, 0x2B, 0x25, 0x27, 0x21, 0x23,
    0x3D, 0x3F, 0x39, 0x3B, 0x35, 0x37, 0x31, 0x33,
    0xCD, 0xCF, 0xC9, 0xCB, 0xC5, 0xC7, 0xC1, 0xC3,
    0xDD, 0xDF, 0xD9, 0xDB, 0xD5, 0xD7, 0xD1, 0xD3,
    0xED, 0xEF, 0xE9, 0xEB, 0xE5, 0xE7, 0xE1, 0xE3,
    0xFD, 0xFF, 0xF9, 0xFB, 0xF5, 0xF7, 0xF1, 0xF3,
    0x8D, 0x8F, 0x89, 0x8B, 0x85, 0x87, 0x81, 0x83,
    0x9D, 0x9F, 0x99, 0x9B, 0x95, 0x97, 0x91, 0x93,
    0xAD, 0xAF, 0xA9, 0xAB, 0xA5, 0xA7, 0xA1, 0xA3,
    0xBD, 0xBF, 0xB9, 0xBB, 0xB5, 0xB7, 0xB1, 0xB3,
};
#define xTimes(value) (rb(tabX+(value)))

#else
//#define xTimes(value) (((value) & 0x80) ? ((value) << 1) ^ 0x4D : ((value) << 1))
static u8 xTimes(const u8 value){
    if (value & 0x80)
        return ((value << 1) ^ 0x4D);
    else
        return (value << 1);
}

#endif

#ifdef USE_TAB0
//tab0[v]: (v << 5)^(v << 3);

static const u8 PROGMEM tab0b[32] = {
0x00, 0x28, 0x50, 0x78, 0xa0, 0x88, 0xf0, 0xd8,
0x40, 0x68, 0x10, 0x38, 0xe0, 0xc8, 0xb0, 0x98,
0x80, 0xa8, 0xd0, 0xf8, 0x20, 0x08, 0x70, 0x58,
0xc0, 0xe8, 0x90, 0xb8, 0x60, 0x48, 0x30, 0x18
};

static u8 T0(const u8 v){
    return rb(tab0b+(v & 0x1F)); // V2
}

#else

static inline u8 T0(const u8 v){
    return (v << 5)^(v << 3);
}

#endif //USE_TAB0

#ifdef USE_TAB1
//tab1[v]: v ^ (v >> 3)^(v >> 5);
static const u8 PROGMEM tab1[256] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x09, 0x08, 0x0b, 0x0a, 0x0d, 0x0c, 0x0f, 0x0e,
0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15,
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c,
0x25, 0x24, 0x27, 0x26, 0x21, 0x20, 0x23, 0x22,
0x2c, 0x2d, 0x2e, 0x2f, 0x28, 0x29, 0x2a, 0x2b,
0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
0x3e, 0x3f, 0x3c, 0x3d, 0x3a, 0x3b, 0x38, 0x39,
0x4a, 0x4b, 0x48, 0x49, 0x4e, 0x4f, 0x4c, 0x4d,
0x43, 0x42, 0x41, 0x40, 0x47, 0x46, 0x45, 0x44,
0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
0x51, 0x50, 0x53, 0x52, 0x55, 0x54, 0x57, 0x56,
0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68,
0x66, 0x67, 0x64, 0x65, 0x62, 0x63, 0x60, 0x61,
0x7d, 0x7c, 0x7f, 0x7e, 0x79, 0x78, 0x7b, 0x7a,
0x74, 0x75, 0x76, 0x77, 0x70, 0x71, 0x72, 0x73,
0x94, 0x95, 0x96, 0x97, 0x90, 0x91, 0x92, 0x93,
0x9d, 0x9c, 0x9f, 0x9e, 0x99, 0x98, 0x9b, 0x9a,
0x86, 0x87, 0x84, 0x85, 0x82, 0x83, 0x80, 0x81,
0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88,
0xb1, 0xb0, 0xb3, 0xb2, 0xb5, 0xb4, 0xb7, 0xb6,
0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
0xa3, 0xa2, 0xa1, 0xa0, 0xa7, 0xa6, 0xa5, 0xa4,
0xaa, 0xab, 0xa8, 0xa9, 0xae, 0xaf, 0xac, 0xad,
0xde, 0xdf, 0xdc, 0xdd, 0xda, 0xdb, 0xd8, 0xd9,
0xd7, 0xd6, 0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0,
0xcc, 0xcd, 0xce, 0xcf, 0xc8, 0xc9, 0xca, 0xcb,
0xc5, 0xc4, 0xc7, 0xc6, 0xc1, 0xc0, 0xc3, 0xc2,
0xfb, 0xfa, 0xf9, 0xf8, 0xff, 0xfe, 0xfd, 0xfc,
0xf2, 0xf3, 0xf0, 0xf1, 0xf6, 0xf7, 0xf4, 0xf5,
0xe9, 0xe8, 0xeb, 0xea, 0xed, 0xec, 0xef, 0xee,
0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7
};

#define T1(value) (rb(tab1+(value)))

#else

static inline u8 T1(const u8 v){
    return v ^ (v >> 3)^(v >> 5);
}

#endif //USE_TAB1


//-------------- "CURUPIRA ATRIBUTES"  --------------
//holds the round keys
static u8 k[BLOCK_SIZE];


/***********************************************************************************
*                                 CRYPT FUNCTIONS                                  *
************************************************************************************/

//-------------- " KEY SCHEDULE "  --------------

/** Evolutes the key.
  *
  *        (k[0], k[1], ... , k[10], k[11])
  *         ^                        ^
  * most significant            least significant
  *
  */
static void createNextKey(u8 constantOffSet){

	u8 aux1 = k[0] ^ sBox(constantOffSet++); //applies the constant

	//Multiplies by x^8
	for(u8 i = 0 ; i < BLOCK_SIZE-1 ; i++){
		k[i] = k[i+1];
	}
	k[BLOCK_SIZE-3] ^= T1(aux1);
    k[BLOCK_SIZE-2] ^= T0(aux1);
	k[BLOCK_SIZE-1] = aux1;
}

//------- " CURUPIRA-2 ROUND FUNCTION  "  ---------


#ifdef REQUIRE_SCT

//-------------- " (UNKEYED) ROUND FUNCTION  "  --------------

/**Computes a unkeyed round over the 'bl' array.
 *
 * @param doMatrixMultiplication If '0', the multiplication
 * by matrix D is not performed; it will be performed otherwise.
 */
static void unkeyedRound(u8* bl, u8 doMatrixMultiplication){
	u8 aux1;

	//Swap
	aux1 = bl[1]; bl[1] = bl[4]; bl[4] = aux1;
	aux1 = bl[2]; bl[2] = bl[8]; bl[8] = aux1;
	aux1 = bl[7]; bl[7] = bl[10]; bl[10] = aux1;
	aux1 = bl[5]; bl[5] = bl[11]; bl[11] = aux1;

	//SBox
	for(u8 i = 0; i < BLOCK_SIZE ; i++){
		bl[i] = sBox(bl[i]);
	}

    //If the multiplication by D is needed
    if(doMatrixMultiplication){
		//Multiplication by matrix D
		for(u8 i = 0;  i < BLOCK_SIZE ; )
		{
			//Computes the multiplication by x and x^2
			aux1 = xTimes(bl[i] ^ bl[i+1] ^ bl[i+2]);
			u8 aux2 = xTimes(aux1);
			//Then, computes the result of the multiplication by D
			bl[i++] ^= aux1;
			bl[i++] ^= aux2;
			bl[i++] ^= aux1 ^ aux2;
		}
	}
}


//-------------- " CURUPIRA-2 ENCRYPTION "  --------------

/**
 * Encrypts a single data block.
 * @param src Pointer to the source block
 * @param dst Pointer to the destination block
 */
void cipherCryptB(u8* key, u8* src, u8* dst){

	//Loads the key into the 'k' buffer (so it is not replaced
	//by the key evolution process) and applies the first key
	for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
		k[i] = key[i];
	}

   	//Applies the first key
	for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
		dst[i] = src[i] ^ sBox(k[i]); i++;
		dst[i] = src[i] ^ k[i]; i++;
		dst[i] = src[i] ^ k[i];
	}

    //round function applied 10 times
    for(u8 round = 0; round != N_ROUNDS ; ){

        //Creates the key for this round
        createNextKey(round++);

        //Computes a single unkeyed round.
		//The last round does not include the multiplication by matrix D
        unkeyedRound(dst, round < N_ROUNDS);

        //Applies the key for this round
		for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
			dst[i] ^= sBox(k[i]); i++;
			dst[i] ^= k[i]; i++;
			dst[i] ^= k[i];
		}

#ifdef ENABLE_DEBUG_CIPHER
dbsp("\nDEBUG. Round ");
dbch(round);
dbsp("\nKey:");
printMatrix(k);
dbsp("\nBLock:");
printMatrix(dst);
#endif

    }//end of all rounds

    return;
}

#else
/**
 * Encrypts a single data block.
 * @param src Pointer to the source block
 * @param dst Pointer to the destination block
 */
void cipherCryptB(u8* key, u8* src, u8* dst){

	//Restores original keys (possibly replaced due to the key evolution)
	for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
		k[i] = key[i];
	}

    //Applies the first key
	for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
		dst[i] = src[i] ^ sBox(k[i]); i++;
		dst[i] = src[i] ^ k[i]; i++;
		dst[i] = src[i] ^ k[i];
	}

	//round function
	for(u8 round = 0;  ; ){
		u8 aux1;

		//Swap
		aux1 = dst[1]; dst[1] = dst[4]; dst[4] = aux1;
		aux1 = dst[2]; dst[2] = dst[8]; dst[8] = aux1;
		aux1 = dst[7]; dst[7] = dst[10]; dst[10] = aux1;
		aux1 = dst[5]; dst[5] = dst[11]; dst[11] = aux1;

		//SBox
		for(u8 i = 0; i < BLOCK_SIZE ; i++){
			dst[i] = sBox(dst[i]);
		}

		//Create the key for this round
		createNextKey(round);

        //Checks if the final round is achieved
		if(++round == N_ROUNDS){
			for(u8 i = 0 ; i < BLOCK_SIZE ; ){
				dst[i] ^= sBox(k[i]);	i++;
				dst[i] ^= k[i];			i++;
				dst[i] ^= k[i];			i++;
			}
			break;
        }

		//Multiplication by matrix D
		for(u8 i = 0;  i <= 9 ; )
		{
			aux1 = xTimes(dst[i] ^ dst[i+1] ^ dst[i+2]);
			u8 aux2 = xTimes(aux1);
			dst[i] ^= aux1 ^ sBox(k[i]);	i++;
			dst[i] ^= aux2 ^ k[i];			i++;
			dst[i] ^= aux1 ^ aux2 ^ k[i];	i++;
		}

		//Key addition
		//applyKey();

#ifdef ENABLE_DEBUG_CIPHER
dbsp("\nDEBUG. Round ");
dbch(round);
dbsp("\nKey:");
printMatrix(k);
dbsp("\nBLock:");
printMatrix(dst);
#endif

	}//end of for (all rounds)

	return;
}

#endif


/************************************************************************************/
/*********************************** TESTS ******************************************/
/************************************************************************************/

#ifdef ENABLE_TESTS_CIPHER

void printMatrix(u8 matrix[]) {
    u8 nCol = 4;
    u8 nRow = BLOCK_SIZE/4;
    int row, a;

    dbsp("\n");
    for (row = 0; row < nRow; row++) {
        dbsp("| ");
        for (a = 0; a < nCol; a++) {
            dbsp(" ");
            dbch(matrix[row + nRow * a]);
            dbsp(" ");
        }
        dbsp(" |\n");
    }
}

//Prints a vector
void printvector(u8 vector[], u8 size) {
    int a;

	dbsp("\n");
    for (a = 0; a < size; a++) {
        dbsp("| ");
        dbch(vector[a]);
        dbsp(" ");
    }
    dbsp("|\n");
}

int main(void){

	TRISA0 = 0;

	LATA0 = 1;

//---------------------- INPUTS ---------------------------//

	u8 plaintext[BLOCK_SIZE];
	u8 ciphertext[BLOCK_SIZE];
    u8 keyUsed[BLOCK_SIZE];
	for(u8 i = 0 ; i < BLOCK_SIZE; i++){
		plaintext[i] = 0;
		keyUsed[i] = 0;
	}

	u8 ok1;

//---------------------- EXPECETD OUTPUTS ---------------------------//


	u8 res[BLOCK_SIZE];
	res[0] = 0xe8; res[1] = 0x82; res[2]  = 0xf1; res[3] = 0x9c;
	res[4] = 0x4a; res[5] = 0xf9; res[6]  = 0xf2; res[7] = 0x80;
	res[8] = 0xd8; res[9] = 0x98; res[10] = 0xea; res[11] = 0x94;


	//-------------------- TESTS Curupira ---------------------------//

	// dbsp("Plaintext: ");
	// printMatrix(plaintext);
	// dbsp("Key: ");
	// printMatrix(keyUsed);
	cipherCryptB(keyUsed, plaintext, ciphertext);
	// dbsp("Result: ");
	// printMatrix(ciphertext);



	//check if results are OK
	ok1 = 1;
	for(u8 i = 0 ; i < BLOCK_SIZE ; i++){
		if(ciphertext[i] != res[i]){
			ok1 = 0;
			break;
		}
	}

	if(ok1){
        LATA0 = 0;
        __delay_ms(2000);
        LATA0 = 1;
        __delay_ms(2000);
        LATA0 = 0;
    }

	//getch();

	while(1) {}

    return 1;
}

#endif
