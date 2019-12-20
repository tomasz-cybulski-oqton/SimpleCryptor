/*
 *  SimpleQtCryptor is an encryption library for Qt.
 *
 *  Copyright (C) 2010 Gunnar Thorburn
 *
 *  SimpleQtRC5 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ParrotShare is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "simpleqtcryptor.h"

#include <boost/uuid/sha1.hpp>

#ifdef WITH_SERPENT_INCLUDE_FAST_SBOX
#include "serpent_sbox.h"
#endif

#define ROUNDS 32
#define KEYSIZE_RC5 20
#define KEYSIZE_SERPENT 32
#define SSIZE_RC5 66
#define SSIZE_SERPENT 132

#define P32 0xb7e17163
#define Q32 0x9e3779b9
#define P64 0xb7e151628aed2a6b;
#define Q64 0x9e3779b97f4a7c15;

#define ROTL32(x,y) (((x)<<(y)) | ((x)>>(32-(y))))
#define ROTR32(x,y) (((x)>>(y)) | ((x)<<(32-(y))))
#define ROTL64(x,y) (((x)<<(y)) | ((x)>>(64-(y))))
#define ROTR64(x,y) (((x)>>(y)) | ((x)<<(64-(y))))

#if __BIG_ENDIAN__
# define fromLittleEndian32(x) __bswap_32(x)
# define fromLittleEndian64(x) __bswap_64(x)
#else if __LITTLE_ENDIAN__
# define fromLittleEndian32(x) (x)
# define fromLittleEndian64(x) (x)
#endif

namespace SimpleQtCryptor {

#ifdef WITHRC5
std::vector<uint8_t> header_RC5_32_32_20  = {'R','C','5','/','3','2','/','3','2','/','2','0',':'};
std::vector<uint8_t> header_RC5_64_32_20  = {'R','C','5','/','6','4','/','3','2','/','2','0',':'};
#endif
std::vector<uint8_t> header_SERPENT_32  = {'S','E','R','P','E','N','T','/','3','2',':'};

std::vector<uint8_t> header_CBC  = {'C','B','C',':','P','A','D','N',':',':'};
std::vector<uint8_t> header_CFB  = {'C','F','B',':',':'};


#ifdef WITH_SERPENT_FAST_SBOX
inline uint32_t serpent_sbox_fast(int sbox, uint32_t X);
#else
void serpent_sbox_it(int sbox, uint32_t &X1, uint32_t &X2,
                               uint32_t &X3, uint32_t &X4);
#endif

#ifdef WITHRC5
Algorithm Info::fastRC5() {
    #if (QT_POINTER_SIZE==4)
        return RC5_32_32_20;
    #else
        return RC5_64_32_20;
    #endif
}
#endif

std::string Info::errorText(Error e) {
    switch (e) {
    case NoError:
        return std::string("NoError");
    case ErrorNoAlgorithm:
        return std::string("ErrorNoAlgorithm");
    case ErrorNoMode:
        return std::string("ErrorNoMode");
    case ErrorInvalidKey:
        return std::string("ErrorInvalidKey");
    case ErrorNotEnoughData:
        return std::string("ErrorNotEnoughData");
    case ErrorModeNotImplemented:
        return std::string("ErrorModeNotImplemented");
    case ErrorAlgorithmNotImplemented:
        return std::string("ErrorAlgorithmNotImplemented");
    case ErrorChecksumNotImplemented:
        return std::string("ErrorChecksumNotImplemented");
    case ErrorAlreadyError:
        return std::string("ErrorAlreadyError");
    default:
        return std::string("UnknownError");
    }
    return std::string();
}


Key::Key() {
#ifdef WITHRC5
    s32 = 0;
    s64 = 0;
#endif
    serpent = 0;
}

Key::Key(const std::vector<uint8_t> &k) {
    key = k;
#ifdef WITHRC5
    s32 = 0;
    s64 = 0;
#endif
    serpent = 0;
}

Key::Key(const std::string &k) {
    boost::uuids::detail::sha1 qch;
    qch.process_bytes(k.c_str(), k.size());
    key.resize(20);
    unsigned digest[5] = {0};
    qch.get_digest(digest);
    for (int i = 0; i < 5; ++i) {
        key[4 * i + 0] = digest[i] & 0xFF000000 >> 24;
        key[4 * i + 1] = digest[i] & 0x00FF0000 >> 16;
        key[4 * i + 2] = digest[i] & 0x0000FF00 >>  8;
        key[4 * i + 2] = digest[i] & 0x000000FF >>  0;
    }
#ifdef WITHRC5
    s32 = 0;
    s64 = 0;
#endif
    serpent = 0;
}

Key::~Key() {
#ifdef WITHRC5
    delete[] s32;
    delete[] s64;
#endif
    delete serpent;
}


std::vector<uint8_t> Key::resizeKey(int ks) {
    std::vector<uint8_t> newKey(ks, 0);
    unsigned char *ok = (unsigned char *)(key.data());
    unsigned char *nk = (unsigned char *)(newKey.data());
    for ( int i = 0 ; i < key.size() ; i++ ) {
        nk[i%ks] ^= ok[i];
    }
    return newKey;
}

#ifdef WITHRC5
void Key::expandKeyRc532() {
    if (s32) return;
    if ( KEYSIZE_RC5 != keyRc5.size() ) {
        keyRc5 = resizeKey(KEYSIZE_RC5);
    } 
    s32 = new uint32_t[SSIZE_RC5];
    uint32_t *s = s32;

    uint32_t *k = (uint32_t *)(keyRc5.data());
    uint32_t L[5];
    L[0] = fromLittleEndian32(*(k+0));
    L[1] = fromLittleEndian32(*(k+1));
    L[2] = fromLittleEndian32(*(k+2));
    L[3] = fromLittleEndian32(*(k+3));
    L[4] = fromLittleEndian32(*(k+4));

    s[0] = P32;
    for ( int i = 1 ; i < SSIZE_RC5 ; i++ ) {
        s[i] = s[i-1] + Q32;
    }

    int i=0 , j=0;
    uint32_t A=0 , B=0;

    for ( int x = 0 ; x < ROUNDS ; x++ ) {
        A = s[i] = ROTL32(s[i] + (A+B), 3);
        B = L[j] = ROTL32(L[j] + (A+B), (A+B) & 31 );
        i = (i + 1) % SSIZE_RC5;
        j = (j + 1) % 5;
    }
}
#endif

#ifdef WITHRC5
//TODO
void Key::expandKeyRc564() {
    if (s64) return;
    if ( KEYSIZE_RC5 != keyRc5.size() ) {
        keyRc5 = resizeKey(KEYSIZE_RC5);
    } 
    s64 = new uint64_t[SSIZE_RC5];
    uint64_t *s = s64;

    uint64_t *k = (uint64_t *)(keyRc5.data());
    uint64_t L[3];
    L[0] = fromLittleEndian64(*(k));
    L[1] = fromLittleEndian64(*(k+8));
    L[2] = fromLittleEndian64(*(k+16));

    s[0] = P64;
    for ( int i = 1 ; i < SSIZE_RC5 ; i++ ) {
        s[i] = s[i-1] + Q64;
    }

    int i=0 , j=0;
    uint64_t A=0 , B=0;

    for ( int x = 0 ; x < ROUNDS ; x++ ) {
        A = s[i] = ROTL64(s[i] + (A+B), 3);
        B = L[j] = ROTL64(L[j] + (A+B), (A+B) & 63 );
        i = (i + 1) % SSIZE_RC5;
        j = (j + 1) % 3;
    }
}
#endif


void Key::expandKeySerpent() {
    uint32_t i;
    uint32_t tmp;
    uint32_t *s;
    if (serpent) return;
    if ( KEYSIZE_SERPENT != keySerpent.size() ) {
        keySerpent = resizeKey(KEYSIZE_SERPENT);
    } 
    serpent = new uint32_t[SSIZE_SERPENT];
    s = new uint32_t[SSIZE_SERPENT + 8];

    uint32_t *k = (uint32_t *)(keySerpent.data());
    for ( i=0 ; i<8 ; i++ ) {
        s[i] = fromLittleEndian32(*(k + 4*i));
    }

    for(i=8 ; i < SSIZE_SERPENT + 8 ; i++) {
        tmp = ( s[i-8] ^ s[i-5] ^ s[i-3] ^ s[i-1] ^ Q32 ^ (i-8) );
        serpent[i-8] = s[i] = ROTL32(tmp, 11);
    }
    for(i=0;i<33;i++) {
#ifdef WITH_SERPENT_FAST_SBOX
        tmp = (35-i) % 8;
        for (int j=0;j<4;j++) {
            serpent[4*i+j] = serpent_sbox_fast(tmp,serpent[4*i+j]);
        }
#else
        serpent_sbox_it( (35-i)%8 , serpent[4*i  ], serpent[4*i+1],
                                    serpent[4*i+2], serpent[4*i+3] );
#endif
    }

    delete s;
}


/* *** ENCRYPTOR *** */

Encryptor::Encryptor(std::shared_ptr<Key> k, Algorithm a, Mode m, Checksum c) {
    key = k;
    algorithm = a;
    mode = m;
    checksum = c;
#ifdef WITHRC5
    if ( algorithm == RC5_FAST_32_20 ) {
        algorithm = Info::fastRC5();
    }
#endif
    state = StateReset;
    modex = 0;
}

Encryptor::~Encryptor() {
    delete modex;
}

Error Encryptor::encrypt(const std::vector<uint8_t> &plain, std::vector<uint8_t> &cipher, bool end) {
    std::vector<uint8_t> tmpIn;
    switch ( state ) {
    case StateReset:

        switch ( algorithm ) {
#ifdef WITHRC5
        case RC5_32_32_20:
            tmpIn.insert(std::end(tmpIn), std::begin(header_RC5_32_32_20), std::end(header_RC5_32_32_20));
            break;
        case RC5_64_32_20:
            tmpIn.insert(std::end(tmpIn), std::begin(header_RC5_64_32_20), std::end(header_RC5_64_32_20));
            break;
#endif
        case SERPENT_32:
            tmpIn.insert(std::end(tmpIn), std::begin(header_SERPENT_32), std::end(header_SERPENT_32));
            break;
        case NoAlgorithm:
        case DetectAlgorithm:
#ifdef WITHRC5
        case RC5_FAST_32_20:
#endif
            state = StateError;
            return ErrorNoAlgorithm;
        }

        switch ( mode ) {
        case ModeCBC:
            tmpIn.insert(std::end(tmpIn), std::begin(header_CBC), std::end(header_CBC));
            if ( 0 == modex) modex = new CBC(key,algorithm);
            break;
        case ModeCFB:
            tmpIn.insert(std::end(tmpIn), std::begin(header_CFB), std::end(header_CFB));
            if ( 0 == modex) modex = new CFB(key, algorithm);
            break;
        case NoMode:
        case DetectMode:
        default:
            state = StateError;
            return ErrorNoMode;
        }

        if ( checksum != NoChecksum ) {
            state = StateError;
            return ErrorChecksumNotImplemented;
        }
        // switch (checksum) HERE

        state = StateOn;
    case StateOn:
        tmpIn.insert(std::end(tmpIn), std::begin(plain), std::end(plain));
        cipher = modex->encrypt(tmpIn, end);
        break;
    case StateError:
    default:
        return ErrorAlreadyError;
    }
    if (end) {
        state = StateReset;
    }

    return NoError;
}


/* *** DECRYPTOR *** */

Decryptor::Decryptor(std::shared_ptr<Key> k, Algorithm a, Mode m) {
    key = k;
    algorithm = a;
    mode = m;
    state = StateReset;
    checksum = NoChecksum;
    modex = 0;
}

Decryptor::~Decryptor() {
    delete modex;
}

Checksum Decryptor::getChecksumType() {
    return checksum;
}

Error Decryptor::decrypt(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain, bool end) {
    std::vector<uint8_t> expectHeader;
    std::vector<uint8_t> remainingFromHeader;
    std::vector<uint8_t> tmpIn;
    std::vector<uint8_t> tmpOut;
    int neededForHeader = -1;
    int neededForIv = -1;

    switch ( state ) {
    case StateReset:
        switch ( algorithm ) {
#ifdef WITHRC5
        case RC5_32_32_20:
            expectHeader.insert(std::end(expectHeader), std::begin(header_RC5_32_32_20), std::end(header_RC5_32_32_20));
            neededForIv = 8;
            break;
        case RC5_64_32_20:
            expectHeader.insert(std::end(expectHeader), std::begin(header_RC5_64_32_20), std::end(header_RC5_64_32_20));
            neededForIv = 16;
            break;
#endif
        case SERPENT_32:
            expectHeader.insert(std::end(expectHeader), std::begin(header_SERPENT_32), std::end(header_SERPENT_32));
            neededForIv = 16;
            break;
        case NoAlgorithm:
        case DetectAlgorithm:
#ifdef WITHRC5
        case RC5_FAST_32_20:
#endif
            state = StateError;
            return ErrorNoAlgorithm;
        }

        switch ( mode ) {
        case ModeCBC:
            expectHeader.insert(std::end(expectHeader), std::begin(header_CBC), std::end(header_CBC));
            neededForHeader = (((neededForIv + expectHeader.size() - 1) / neededForIv) + 1) * neededForIv;
            if ( 0 == modex) modex = new CBC(key, algorithm);
            break;
        case ModeCFB:
            expectHeader.insert(std::end(expectHeader), std::begin(header_CFB), std::end(header_CFB));
            neededForHeader = neededForIv + expectHeader.size();
            if ( 0 == modex) modex = new CFB(key, algorithm);
            break;
        case NoMode:
        case DetectMode:
        default:
            state = StateError;
            return ErrorNoMode;
        }


        if ( cipher.size() < neededForHeader ) {
            state = StateError;
            return ErrorNotEnoughData;
        }

        tmpOut = modex->decrypt(std::vector<uint8_t>(cipher.begin(), cipher.begin() + neededForHeader), false);

        if ( std::equal(tmpOut.begin(), tmpOut.begin() + expectHeader.size(), expectHeader.begin()) ) {
            remainingFromHeader = std::vector<uint8_t>(tmpOut.begin() + expectHeader.size(), tmpOut.end());
            tmpOut.clear();
            tmpIn = std::vector<uint8_t>(cipher.begin() + neededForHeader, cipher.end());
            state = StateOn;
        } else {
            state = StateError;
            tmpOut.clear();
            return ErrorInvalidKey;
        }

    case StateOn:
        if ( tmpIn.empty() ) {
            tmpIn = cipher;
        }
        tmpOut = modex->decrypt(tmpIn, end);
        break;
    case StateError:
    default:
        return ErrorAlreadyError;
    }
    if ( ! remainingFromHeader.empty() ) {
        tmpOut.insert(std::end(tmpOut), std::begin(remainingFromHeader), std::end(remainingFromHeader));
    }
    if (end) {
        state = StateReset;
    }
    plain = tmpOut;
    return NoError;
}


/* *** DECRYPTOR WIZARD ENTRY *** */

class DecryptorWizardEntry {
public:
    std::shared_ptr<Key> key;
    Algorithm alg;
    Mode mode;
    Checksum csum;
};


/* *** DECRYPTOR WIZARD *** */

DecryptorWizard::DecryptorWizard() {
}

DecryptorWizard::DecryptorWizard(std::shared_ptr<Key> k, Algorithm a, Mode m) {
    addParameters(k, a, m);
}

DecryptorWizard::~DecryptorWizard() {
    for (auto entry : entries) {
        delete entry;
    }
}

void DecryptorWizard::addParameters(std::shared_ptr<Key> k, Algorithm a, Mode m) {
    DecryptorWizardEntry *dwe = new DecryptorWizardEntry();
    dwe->key = k;
    dwe->alg = a;
    dwe->mode = m;
    entries.push_back(dwe);
}

Error DecryptorWizard::decrypt(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain, std::shared_ptr<Decryptor> &decryptor, bool end) {
#ifdef WITHRC5
    Algorithm aList[3] = { RC5_32_32_20, RC5_64_32_20, SERPENT_32 };
    int aL = 3;
#else
    Algorithm aList[1] = { SERPENT_32 };
    int aL = 1;
#endif
    Mode mList[2] = { ModeCBC, ModeCFB };
    int mL = 2;
    int eL = entries.size();
    int eI, aI, mI;
    Decryptor *dx;
    Error dxError;
    Error retError = ErrorInvalidKey;

    for (eI=0 ; eI<eL ; eI++) for (aI=0 ; aI<aL ; aI++) for (mI=0 ; mI<mL ; mI++) {
        if ( (entries.at(eI)->alg != aList[aI]) && (entries.at(eI)->alg != DetectAlgorithm) ) continue;
        if ( (entries.at(eI)->mode != mList[mI]) && (entries.at(eI)->mode != DetectMode) ) continue;
        dx = new Decryptor(entries.at(eI)->key, aList[aI], mList[mI]);
        dxError = dx->decrypt(cipher, plain, end);
        switch (dxError) {
        case NoError:
            decryptor = std::shared_ptr<Decryptor>(dx);
            return NoError;
        case ErrorNotEnoughData:
            retError = ErrorNotEnoughData;
            break;
        case ErrorInvalidKey:
            if ( ErrorNotEnoughData != retError ) {
                retError = ErrorInvalidKey;
            }
            break;
        default:
            delete dx;
            return dxError;
        }
        delete dx;
    }
    return retError;
}

Error DecryptorWizard::decryptToEnd(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain) {
    std::shared_ptr<Decryptor> qspd;
    Error er = decrypt(cipher, plain, qspd, true);
    return er;
}


/* *** INITIALIZATION VECTOR *** */

std::vector<uint8_t> InitializationVector::getVector8() {
    std::vector<uint8_t> ret(8, 0);
    uint32_t A = ((uint32_t)(std::rand())) ^ ((uint32_t)(QTime::currentTime().msecsTo(QTime(23,59,59,999))));
    uint32_t B = ((uint32_t)(std::rand())) ^ ((uint32_t)(QDate::currentDate().daysTo(QDate(2999,12,31))));
    qToLittleEndian(A, (uint8_t *)(ret.data()));
    qToLittleEndian(B, (uint8_t *)(ret.data() + 4));
    ret[0] = ( (uint8_t)(ret[0]) | 128 );
    return ret;
}

std::vector<uint8_t> InitializationVector::getVector16() {
    std::vector<uint8_t> ret(16, 0);
    uint32_t A = ((uint32_t)(std::rand())) ^ ((uint32_t)(QTime::currentTime().msecsTo(QTime(23,59,59,999))));
    uint32_t B = ((uint32_t)(std::rand())) ^ ((uint32_t)(QDate::currentDate().daysTo(QDate(2999,12,31))));
    uint32_t C = (uint32_t)(std::rand());
    uint32_t D = (uint32_t)(std::rand());
    qToLittleEndian(A, (uint8_t *)(ret.data()));
    qToLittleEndian(B, (uint8_t *)(ret.data() + 4));
    qToLittleEndian(C, (uint8_t *)(ret.data() + 8));
    qToLittleEndian(D, (uint8_t *)(ret.data() + 12));
    ret[0] = ( (uint8_t)(ret[0]) | 128 );
    return ret;
}

void InitializationVector::initiate() {
    std::srand((uint32_t)(QTime::currentTime().msecsTo(QTime(23,59,59,999))));
}

/* *** CBC *** */

CBC::CBC(std::shared_ptr<Key> k, Algorithm a) {
    algorithm = a;
    key = k;
    reset();
}

CBC::~CBC() {
}

void CBC::reset() {
    worksize = -1;
    buffer.clear();
    cbcBuffer.clear();
    padHostageBuffer.clear();
}

/*
 *
 * PSEUDO
 *
 * documentation missing
 *
 */
std::vector<uint8_t> CBC::encrypt(const std::vector<uint8_t> plain, bool end) {
    int cipherpos = 0;
    int padsize = -1;
    bool iv = false;

    // set initialization vector if first data
    if ( -1 == worksize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            cbcBuffer = InitializationVector::getVector8();
            worksize = 8;
            iv = true;
            key->expandKeyRc532();
            break;
        case RC5_64_32_20:
            cbcBuffer = InitializationVector::getVector16();
            worksize = 16;
            iv = true;
            key->expandKeyRc564();
            break;
#endif
        case SERPENT_32:
            cbcBuffer = InitializationVector::getVector16();
            worksize = 16;
            iv = true;
            key->expandKeySerpent();
            break;
        default:
            buffer.clear();
            return std::vector<uint8_t>();
        }
    }
    buffer.append(plain);

    int cipherlen = ( buffer.size() / worksize ) * worksize;
    padsize = worksize - (buffer.size() - cipherlen);
    if (iv) cipherlen += cbcBuffer.size();
    if (end) cipherlen += worksize;

    std::vector<uint8_t> cipher = std::vector<uint8_t>(cipherlen, 0);

    if (end) {
        buffer.append(std::vector<uint8_t>(padsize, (char)padsize));
    }

    if ( iv ) while (cipherpos < worksize) {
        cipher[cipherpos] = cbcBuffer[cipherpos];
        cipherpos++;
    }

    uint8_t *bufdat = (uint8_t *)buffer.data();
    uint8_t *cipdat = (uint8_t *)cipher.data();
    uint8_t *cbcdat = (uint8_t *)cbcBuffer.data();
    int bufpos = 0;

    switch (algorithm) {
#ifdef WITHRC5
    case RC5_32_32_20:
        {
            uint32_t cbc1 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat));
            uint32_t cbc2 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat + 4));
            uint32_t buf1;
            uint32_t buf2;

            while ( cipherpos < cipherlen ) {
                buf1 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos));
                buf2 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos + 4));
                cbc1 ^= buf1;
                cbc2 ^= buf2;
                rc5_32_encrypt_2w(cbc1, cbc2, key->s32);
                qToLittleEndian(cbc1, cipdat + cipherpos);
                qToLittleEndian(cbc2, cipdat + cipherpos + 4);

                cipherpos += worksize;
                bufpos += worksize;
            }

            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 4);
        }
        break;
    case RC5_64_32_20:
        {
            uint64_t cbc1 = fromLittleEndian64(*reinterpret_cast<uint64_t*>(cbcdat));
            uint64_t cbc2 = fromLittleEndian64(*reinterpret_cast<uint64_t*>(cbcdat + 8));
            uint64_t buf1;
            uint64_t buf2;

            while ( cipherpos < cipherlen ) {
                buf1 = fromLittleEndian64(*reinterpret_cast<uint64_t*>(bufdat + bufpos));
                buf2 = fromLittleEndian64(*reinterpret_cast<uint64_t*>(bufdat + bufpos + 8));
                cbc1 ^= buf1;
                cbc2 ^= buf2;
                rc5_64_encrypt_2w(cbc1, cbc2, key->s64);
                qToLittleEndian(cbc1, cipdat + cipherpos);
                qToLittleEndian(cbc2, cipdat + cipherpos + 8);

                cipherpos += worksize;
                bufpos += worksize;
            }

            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 8);
        }
        break;
#endif
    case SERPENT_32:
        {
            uint32_t cbc1 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat));
            uint32_t cbc2 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat + 4));
            uint32_t cbc3 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat + 8));
            uint32_t cbc4 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(cbcdat + 12));
            uint32_t buf1;
            uint32_t buf2;
            uint32_t buf3;
            uint32_t buf4;

            while ( cipherpos < cipherlen ) {
                buf1 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos));
                buf2 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos + 4));
                buf3 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos + 8));
                buf4 = fromLittleEndian32(*reinterpret_cast<uint32_t*>(bufdat + bufpos + 12));
                cbc1 ^= buf1;
                cbc2 ^= buf2;
                cbc3 ^= buf3;
                cbc4 ^= buf4;
                serpent_encrypt_4w(cbc1, cbc2, cbc3, cbc4, key->serpent);
                qToLittleEndian(cbc1, cipdat + cipherpos);
                qToLittleEndian(cbc2, cipdat + cipherpos + 4);
                qToLittleEndian(cbc3, cipdat + cipherpos + 8);
                qToLittleEndian(cbc4, cipdat + cipherpos + 12);

                cipherpos += worksize;
                bufpos += worksize;
            }

            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 4);
            qToLittleEndian(cbc3, cbcdat + 8);
            qToLittleEndian(cbc4, cbcdat + 12);
        }
	break;
    default:
        cipher.clear();
        return cipher;
    }

    if (end) {
        reset();
    } else {
        buffer = buffer.right( buffer.size() - bufpos );
    }
    return cipher;
}

std::vector<uint8_t> CBC::decrypt(const std::vector<uint8_t> cipher, bool end) {
    int bufferpos = 0;
    int plainpos = 0;

    buffer.append(cipher);
    if ( -1 == worksize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            if ( buffer.size() < 8 ) return std::vector<uint8_t>();
            cbcBuffer = buffer.left(8);
            worksize = 8;
            bufferpos = 8;
            key->expandKeyRc532();
            break;
        case RC5_64_32_20:
            if ( buffer.size() < 16 ) return std::vector<uint8_t>();
            cbcBuffer = buffer.left(16);
            worksize = 16;
            bufferpos = 16;
            key->expandKeyRc564();
            break;
#endif
        case SERPENT_32:
            if ( buffer.size() < 16 ) return std::vector<uint8_t>();
            cbcBuffer = buffer.left(16);
            worksize = 16;
            bufferpos = 16;
            key->expandKeySerpent();
            break;
        default:
            buffer.clear();
            return std::vector<uint8_t>();
        }
    }

    int plainlen = ( (buffer.size() - bufferpos) / worksize ) * worksize + padHostageBuffer.size();
    std::vector<uint8_t> plain(plainlen, 0);
    while (plainpos < padHostageBuffer.size()) {
        plain[plainpos] = padHostageBuffer[plainpos];
        plainpos++;
    }
    padHostageBuffer.clear();

    uint8_t *bufdat = (uint8_t *)buffer.data();
    uint8_t *plndat = (uint8_t *)plain.data();
    uint8_t *cbcdat = (uint8_t *)cbcBuffer.data();

    switch (algorithm) {
#ifdef WITHRC5
    case RC5_32_32_20:
        {
            uint32_t cbc1 = qFromLittleEndian<uint32_t>(cbcdat);
            uint32_t cbc2 = qFromLittleEndian<uint32_t>(cbcdat + 4);
            uint32_t buf1;
            uint32_t buf2;
            uint32_t pln1;
            uint32_t pln2;
            while ( plainpos < plainlen ) {
                pln1 = buf1 = qFromLittleEndian<uint32_t>(bufdat + bufferpos);
                pln2 = buf2 = qFromLittleEndian<uint32_t>(bufdat + bufferpos + 4);
                rc5_32_decrypt_2w(pln1,pln2,key->s32);
                qToLittleEndian( (pln1 ^ cbc1) , plndat + plainpos);
                qToLittleEndian( (pln2 ^ cbc2) , plndat + plainpos + 4);
                cbc1 = buf1;
                cbc2 = buf2;

                plainpos += worksize;
                bufferpos += worksize;
            }
            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 4);
        }
        break;
    case RC5_64_32_20:
        {
            uint64_t cbc1 = qFromLittleEndian<uint64_t>(cbcdat);
            uint64_t cbc2 = qFromLittleEndian<uint64_t>(cbcdat + 8);
            uint64_t buf1;
            uint64_t buf2;
            uint64_t pln1;
            uint64_t pln2;
            while ( plainpos < plainlen ) {
                pln1 = buf1 = qFromLittleEndian<uint64_t>(bufdat + bufferpos);
                pln2 = buf2 = qFromLittleEndian<uint64_t>(bufdat + bufferpos + 8);
                rc5_64_decrypt_2w(pln1,pln2,key->s64);
                qToLittleEndian( (pln1 ^ cbc1) , plndat + plainpos);
                qToLittleEndian( (pln2 ^ cbc2) , plndat + plainpos + 8);
                cbc1 = buf1;
                cbc2 = buf2;

                plainpos += worksize;
                bufferpos += worksize;
            }
            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 8);
        }
        break;
#endif
    case SERPENT_32:
        {
            uint32_t cbc1 = qFromLittleEndian<uint32_t>(cbcdat);
            uint32_t cbc2 = qFromLittleEndian<uint32_t>(cbcdat + 4);
            uint32_t cbc3 = qFromLittleEndian<uint32_t>(cbcdat + 8);
            uint32_t cbc4 = qFromLittleEndian<uint32_t>(cbcdat + 12);
            uint32_t buf1;
            uint32_t buf2;
            uint32_t buf3;
            uint32_t buf4;
            uint32_t pln1;
            uint32_t pln2;
            uint32_t pln3;
            uint32_t pln4;
            while ( plainpos < plainlen ) {
                pln1 = buf1 = qFromLittleEndian<uint32_t>(bufdat+bufferpos);
                pln2 = buf2 = qFromLittleEndian<uint32_t>(bufdat+bufferpos + 4);
                pln3 = buf3 = qFromLittleEndian<uint32_t>(bufdat+bufferpos + 8);
                pln4 = buf4 = qFromLittleEndian<uint32_t>(bufdat+bufferpos + 12);
                serpent_decrypt_4w(pln1,pln2,pln3,pln4,key->serpent);
                qToLittleEndian( (pln1 ^ cbc1) , plndat + plainpos);
                qToLittleEndian( (pln2 ^ cbc2) , plndat + plainpos + 4);
                qToLittleEndian( (pln3 ^ cbc3) , plndat + plainpos + 8);
                qToLittleEndian( (pln4 ^ cbc4) , plndat + plainpos + 12);
                cbc1 = buf1;
                cbc2 = buf2;
                cbc3 = buf3;
                cbc4 = buf4;

                plainpos += worksize;
                bufferpos += worksize;
            }
            qToLittleEndian(cbc1, cbcdat);
            qToLittleEndian(cbc2, cbcdat + 4);
            qToLittleEndian(cbc3, cbcdat + 8);
            qToLittleEndian(cbc4, cbcdat + 12);
        }
        break;
    default:
        plain.clear();
        return plain;
    }

    if (end) {
        // in case we dont have any valid padding, the only explanation
        // is a transmission error, or someone modified the file
        // however, this is not the layer where to discover such problems
        // and I have nowhere to report a problem, so I just need
        // to avoid crashing
        int padc = 0;
        if ( ! plain.isEmpty() ) {
            padc = (int)plain[plainlen - 1];
            if ( padc > plain.size() ) {
                padc = 0;
            }
        }
        if ( 0 < padc && padc <= 16 ) {
            plain = plain.left(plainlen - padc);
        }
        reset();
    } else {
        buffer = buffer.right(buffer.size() - bufferpos);

        // there is a chance, that we will not get more data,
        // but end=false anyways. in this case, we must not
        // return possible pad data as plain text
        if ( buffer.size() == 0 && plainlen > 0 ) {
            uint8_t lastByte = plain[plainlen - 1];
            if ( 0 < lastByte && lastByte <= 16 ) {
                std::vector<uint8_t> padPattern((int)lastByte,(char)lastByte);
                if (plain.endsWith(padPattern)) {
                    padHostageBuffer = plain.right(worksize);
                    plain = plain.left(plainlen - worksize);
                    plainlen -= worksize;
                }
            }
        }
    }

    return plain;
}


/* *** CFB *** */

CFB::CFB(std::shared_ptr<Key> k, Algorithm a) {
    algorithm = a;
    key = k;
    reset();
}

CFB::~CFB() {
}

void CFB::reset() {
    bufferpos = -1;
    buffer.clear();
}


/*
 * PSEUDO:
 *
 * if first: make IV, put in buffer
 *
 * if unused bytes in buffer
 *   cipher = buffer XOR plain
 *   buffer = cipher
 *
 * while ( more to encrypt )
 *   encrypt buffer
 *   cipher = buffer XOR plain
 *   buffer = cipher
 *
 *
 */
std::vector<uint8_t> CFB::encrypt(const std::vector<uint8_t> plain, bool end) {
    int plainpos = 0;
    int plainlen = plain.size();
    int cipherpos = 0;
    int bufferlen = buffer.size();
    int copysize = 0;
    std::vector<uint8_t> cipher(plainlen, 0);
    uint8_t *bufdat = 0;

    // set initialization vector if first data
    if ( -1 == bufferpos ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            buffer = InitializationVector::getVector8();
            key->expandKeyRc532();
            bufferlen = 8;
            break;
        case RC5_64_32_20:
            buffer = InitializationVector::getVector16();
            key->expandKeyRc564();
            bufferlen = 16;
            break;
#endif
        case SERPENT_32:
            buffer = InitializationVector::getVector16();
            key->expandKeySerpent();
            bufferlen = 16;
            break;
        default:
            buffer.clear();
            return std::vector<uint8_t>();
        }
        cipher.prepend(buffer);
        bufferpos = bufferlen;
        cipherpos += bufferlen;
    }

    bufdat = (uint8_t *)(buffer.data());

    uint8_t *cphdat = (uint8_t *)cipher.data();
    uint8_t *plndat = (uint8_t *)plain.data();

    copysize = qMin( bufferlen - bufferpos , plainlen - plainpos );
    // in case the buffer contains unused data from last encrypt,
    // use those bytes first
    while ( 0 < copysize ) {
        bufdat[bufferpos] = plndat[plainpos] ^ bufdat[bufferpos];
        cphdat[cipherpos] = bufdat[bufferpos];
        cipherpos++;
        plainpos++;
        bufferpos++;
        copysize--;
    }

    copysize = qMin( bufferlen , plainlen - plainpos );

    if ( bufferlen == copysize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            {
            uint32_t B1 = qFromLittleEndian<uint32_t>(bufdat);
            uint32_t B2 = qFromLittleEndian<uint32_t>(bufdat + 4);
            uint32_t P1 = 0;
            uint32_t P2 = 0;

            do {
                rc5_32_encrypt_2w(B1,B2,key->s32);
                P1 = qFromLittleEndian<uint32_t>(plndat + plainpos);
                P2 = qFromLittleEndian<uint32_t>(plndat + plainpos + 4);
                B1 ^= P1;
                B2 ^= P2;
                qToLittleEndian(B1, cphdat + cipherpos);
                qToLittleEndian(B2, cphdat + cipherpos + 4);
                cipherpos += copysize;
                plainpos += copysize;
                copysize = qMin( bufferlen , plainlen - plainpos );
            } while ( bufferlen == copysize );
            qToLittleEndian(B1, bufdat);
            qToLittleEndian(B2, bufdat + 4);
            }
            break;
        case RC5_64_32_20:
            {
            uint64_t B1 = qFromLittleEndian<uint64_t>(bufdat);
            uint64_t B2 = qFromLittleEndian<uint64_t>(bufdat + 8);
            uint64_t P1 = 0;
            uint64_t P2 = 0;

            do {
                rc5_64_encrypt_2w(B1,B2,key->s64);
                P1 = qFromLittleEndian<uint64_t>(plndat + plainpos);
                P2 = qFromLittleEndian<uint64_t>(plndat + plainpos + 8);
                B1 ^= P1;
                B2 ^= P2;
                qToLittleEndian(B1, cphdat + cipherpos);
                qToLittleEndian(B2, cphdat + cipherpos + 8);
                cipherpos += copysize;
                plainpos += copysize;
                copysize = qMin( bufferlen , plainlen - plainpos );
            } while ( bufferlen == copysize );
            qToLittleEndian(B1, bufdat);
            qToLittleEndian(B2, bufdat + 8);
            }
            break;
#endif
        case SERPENT_32:
            {
            uint32_t B1 = qFromLittleEndian<uint64_t>(bufdat);
            uint32_t B2 = qFromLittleEndian<uint64_t>(bufdat + 4);
            uint32_t B3 = qFromLittleEndian<uint64_t>(bufdat + 8);
            uint32_t B4 = qFromLittleEndian<uint64_t>(bufdat + 12);
            uint32_t P1 = 0;
            uint32_t P2 = 0;
            uint32_t P3 = 0;
            uint32_t P4 = 0;

            do {
                serpent_encrypt_4w(B1,B2,B3,B4,key->serpent);
                P1 = qFromLittleEndian<uint32_t>(plndat + plainpos);
                P2 = qFromLittleEndian<uint32_t>(plndat + plainpos + 4);
                P3 = qFromLittleEndian<uint32_t>(plndat + plainpos + 8);
                P4 = qFromLittleEndian<uint32_t>(plndat + plainpos + 12);
                B1 ^= P1;
                B2 ^= P2;
                B3 ^= P3;
                B4 ^= P4;
                qToLittleEndian(B1, cphdat + cipherpos);
                qToLittleEndian(B2, cphdat + cipherpos + 4);
                qToLittleEndian(B3, cphdat + cipherpos + 8);
                qToLittleEndian(B4, cphdat + cipherpos + 12);
                cipherpos += copysize;
                plainpos += copysize;
                copysize = qMin( bufferlen , plainlen - plainpos );
            } while ( bufferlen == copysize );
            qToLittleEndian(B1, bufdat);
            qToLittleEndian(B2, bufdat + 4);
            qToLittleEndian(B3, bufdat + 8);
            qToLittleEndian(B4, bufdat + 12);
            }
            break;
        default:
            cipher.clear();
            return cipher;
        }
        bufferpos = bufferlen;
    }

    while ( 0 < copysize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            {
            uint32_t X32_1 = qFromLittleEndian<uint32_t>(bufdat);
            uint32_t X32_2 = qFromLittleEndian<uint32_t>(bufdat + 4);
            rc5_32_encrypt_2w(X32_1,X32_2,key->s32);
            qToLittleEndian(X32_1, bufdat);
            qToLittleEndian(X32_2, bufdat + 4);
            }
            break;
        case RC5_64_32_20:
            {
            uint64_t X64_1 = qFromLittleEndian<uint64_t>(bufdat);
            uint64_t X64_2 = qFromLittleEndian<uint64_t>(bufdat + 8);
            rc5_64_encrypt_2w(X64_1,X64_2,key->s64);
            qToLittleEndian(X64_1, bufdat);
            qToLittleEndian(X64_2, bufdat + 8);
            }
            break;
#endif
        case SERPENT_32:
            {
            uint32_t X32_1 = qFromLittleEndian<uint32_t>(bufdat);
            uint32_t X32_2 = qFromLittleEndian<uint32_t>(bufdat + 4);
            uint32_t X32_3 = qFromLittleEndian<uint32_t>(bufdat + 8);
            uint32_t X32_4 = qFromLittleEndian<uint32_t>(bufdat + 12);
            serpent_encrypt_4w(X32_1,X32_2,X32_3,X32_4,key->serpent);
            qToLittleEndian(X32_1, bufdat);
            qToLittleEndian(X32_2, bufdat + 4);
            qToLittleEndian(X32_3, bufdat + 8);
            qToLittleEndian(X32_4, bufdat + 12);
            }
            break;
        default:
            cipher.clear();
            return cipher;
        }
        bufferpos = 0;

        while ( 0 < copysize ) {
            bufdat[bufferpos] = plndat[plainpos] ^ bufdat[bufferpos];
            cphdat[cipherpos] = bufdat[bufferpos];
            cipherpos++;
            plainpos++;
            bufferpos++;
            copysize--;
        }
        copysize = qMin( bufferlen , plainlen - plainpos );
    }    
    if (end) {
        reset();
    }
    return cipher;
}



/*
 * PSEUDO
 *
 * if buffer not full-size
 *   copy cipher (IV) into buffer
 *
 * if unused buffer available
 *   plain = cipher XOR buffer
 *   buffer = cipher
 *
 * while ( more to decrypt )
 *   encrypt buffer
 *   plain = cipher XOR buffer
 *   buffer = cipher
 *
 */
std::vector<uint8_t> CFB::decrypt(const std::vector<uint8_t> cipher, bool end) {
    int cipherpos = 0;
    int cipherlen = cipher.size();
    int bufferlen = -1;
    int copysize = 0;
    int plainpos = 0;
    uint8_t *bufdat = 0;
    uint8_t *cphdat = 0;
    uint8_t *plndat = 0;

    // as long as bufferpos == -1, the initialization vector
    // has not yet been loaded
    if ( -1 == bufferpos ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            key->expandKeyRc532();
            bufferlen = 8;
            break;
        case RC5_64_32_20:
            key->expandKeyRc564();
            bufferlen = 16;
            break;
#endif
        case SERPENT_32:
            key->expandKeySerpent();
            bufferlen = 16;
            break;
        default:
            return std::vector<uint8_t>();
        }
        copysize = qMin ( bufferlen - buffer.size() , cipherlen );
        buffer.append(cipher.left(copysize));
        cipherpos = copysize;
        if ( bufferlen == buffer.size() ) {
            bufferpos = bufferlen;
        } else {
            return std::vector<uint8_t>();
        }
    } else {
        bufferlen = buffer.size();
    }

    std::vector<uint8_t> plain(cipherlen - cipherpos, 0);

    bufdat = (uint8_t *)(buffer.data());
    cphdat = (uint8_t *)(cipher.data());
    plndat = (uint8_t *)(plain.data());

    copysize = qMin( bufferlen - bufferpos , cipherlen - cipherpos );
    while ( 0 < copysize ) {
        plndat[plainpos] = buffer[bufferpos] ^ cphdat[cipherpos];
        buffer[bufferpos] = cphdat[cipherpos];
        plainpos++;
        cipherpos++;
        bufferpos++;
        copysize--;
    }

    copysize = qMin( bufferlen , cipherlen - cipherpos );

    if ( bufferlen == copysize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            {
                uint32_t B1 = qFromLittleEndian<uint32_t>(bufdat);
                uint32_t B2 = qFromLittleEndian<uint32_t>(bufdat + 4);
                uint32_t C1 = 0;
                uint32_t C2 = 0;

                do {
                    rc5_32_encrypt_2w(B1,B2,key->s32);
                    C1 = qFromLittleEndian<uint32_t>(cphdat + cipherpos);
                    C2 = qFromLittleEndian<uint32_t>(cphdat + cipherpos + 4);
                    B1 ^= C1;
                    B2 ^= C2;
                    qToLittleEndian(B1, plndat + plainpos);
                    qToLittleEndian(B2, plndat + plainpos + 4);
                    B1 = C1;
                    B2 = C2;
                    cipherpos += copysize;
                    plainpos += copysize;
                    copysize = qMin( bufferlen , cipherlen - cipherpos );
                } while ( bufferlen == copysize );
                qToLittleEndian(B1, bufdat);
                qToLittleEndian(B2, bufdat + 4);
            }
            break;
        case RC5_64_32_20:
            {
                uint64_t B1 = qFromLittleEndian<uint64_t>(bufdat);
                uint64_t B2 = qFromLittleEndian<uint64_t>(bufdat + 8);
                uint64_t C1 = 0;
                uint64_t C2 = 0;

                do {
                    rc5_64_encrypt_2w(B1,B2,key->s64);
                    C1 = qFromLittleEndian<uint64_t>(cphdat + cipherpos);
                    C2 = qFromLittleEndian<uint64_t>(cphdat + cipherpos + 8);
                    B1 ^= C1;
                    B2 ^= C2;
                    qToLittleEndian(B1, plndat + plainpos);
                    qToLittleEndian(B2, plndat + plainpos + 8);
                    B1 = C1;
                    B2 = C2;
                    cipherpos += copysize;
                    plainpos += copysize;
                    copysize = qMin( bufferlen , cipherlen - cipherpos );
                } while ( bufferlen == copysize );
                qToLittleEndian(B1, bufdat);
                qToLittleEndian(B2, bufdat + 8);
            }
            break;
#endif
        case SERPENT_32:
            {
                uint32_t B1 = qFromLittleEndian<uint32_t>(bufdat);
                uint32_t B2 = qFromLittleEndian<uint32_t>(bufdat + 4);
                uint32_t B3 = qFromLittleEndian<uint32_t>(bufdat + 8);
                uint32_t B4 = qFromLittleEndian<uint32_t>(bufdat + 12);
                uint32_t C1 = 0;
                uint32_t C2 = 0;
                uint32_t C3 = 0;
                uint32_t C4 = 0;

                do {
                    serpent_encrypt_4w(B1,B2,B3,B4,key->serpent);
                    C1 = qFromLittleEndian<uint32_t>(cphdat + cipherpos);
                    C2 = qFromLittleEndian<uint32_t>(cphdat + cipherpos + 4);
                    C3 = qFromLittleEndian<uint32_t>(cphdat + cipherpos + 8);
                    C4 = qFromLittleEndian<uint32_t>(cphdat + cipherpos + 12);
                    B1 ^= C1;
                    B2 ^= C2;
                    B3 ^= C3;
                    B4 ^= C4;
                    qToLittleEndian(B1, plndat + plainpos);
                    qToLittleEndian(B2, plndat + plainpos + 4);
                    qToLittleEndian(B3, plndat + plainpos + 8);
                    qToLittleEndian(B4, plndat + plainpos + 12);
                    B1 = C1;
                    B2 = C2;
                    B3 = C3;
                    B4 = C4;
                    cipherpos += copysize;
                    plainpos += copysize;
                    copysize = qMin( bufferlen , cipherlen - cipherpos );
                } while ( bufferlen == copysize );
                qToLittleEndian(B1, bufdat);
                qToLittleEndian(B2, bufdat + 4);
                qToLittleEndian(B3, bufdat + 8);
                qToLittleEndian(B4, bufdat + 12);
            }
            break;
        default:
            plain.clear();
            return plain;
        }
        bufferpos = bufferlen;
    }

    while ( 0 < copysize ) {
        switch (algorithm) {
#ifdef WITHRC5
        case RC5_32_32_20:
            {
            uint32_t X32_1 = qFromLittleEndian<uint32_t>(bufdat);
            uint32_t X32_2 = qFromLittleEndian<uint32_t>(bufdat + 4);
            rc5_32_encrypt_2w(X32_1,X32_2,key->s32);
            qToLittleEndian(X32_1, bufdat);
            qToLittleEndian(X32_2, bufdat + 4);
            }
            break;
        case RC5_64_32_20:
            {
            uint64_t X64_1 = qFromLittleEndian<uint64_t>(bufdat);
            uint64_t X64_2 = qFromLittleEndian<uint64_t>(bufdat + 8);
            rc5_64_encrypt_2w(X64_1,X64_2,key->s64);
            qToLittleEndian(X64_1, bufdat);
            qToLittleEndian(X64_2, bufdat + 8);
            }
            break;
#endif
        case SERPENT_32:
            {
            uint32_t X32_1 = qFromLittleEndian<uint32_t>(bufdat);
            uint32_t X32_2 = qFromLittleEndian<uint32_t>(bufdat + 4);
            uint32_t X32_3 = qFromLittleEndian<uint32_t>(bufdat + 8);
            uint32_t X32_4 = qFromLittleEndian<uint32_t>(bufdat + 12);
            serpent_encrypt_4w(X32_1,X32_2,X32_3,X32_4,key->serpent);
            qToLittleEndian(X32_1, bufdat);
            qToLittleEndian(X32_2, bufdat + 4);
            qToLittleEndian(X32_3, bufdat + 8);
            qToLittleEndian(X32_4, bufdat + 12);
            }
            break;
        default:
            plain.clear();
            return plain;
        }
        bufferpos = 0;

        while ( 0 < copysize ) {
            plndat[plainpos] = buffer[bufferpos] ^ cphdat[cipherpos];
            buffer[bufferpos] = cphdat[cipherpos];
            plainpos++;
            cipherpos++;
            bufferpos++;
            copysize--;
        }

        copysize = qMin( bufferlen , cipherlen - cipherpos );
    }
    if (end) {
        reset();
    }
    return plain;
}


#ifdef WITHRC5
void rc5_32_encrypt_2w(uint32_t &X1, uint32_t &X2, const uint32_t *s) {
    uint32_t x1 = X1 + s[0];
    uint32_t x2 = X2 + s[1];
    int r;
    for ( int i = 1 ; i <= ROUNDS ; i++ ) {
        r = x2 & 31;
        x1 ^= x2;
        x1 = ROTL32(x1,r);
        x1 += s[2*i];

        r = x1 & 31;
        x2 ^= x1;
        x2 = ROTL32(x2,r);
        x2 += s[2*i + 1];
    }
    X1 = x1;
    X2 = x2;
}

void rc5_64_encrypt_2w(uint64_t &X1, uint64_t &X2, const uint64_t *s) {
    uint64_t x1 = X1 + s[0];
    uint64_t x2 = X2 + s[1];
    int r;
    for ( int i = 1 ; i <= ROUNDS ; i++ ) {
        r = x2 & 63;
        x1 ^= x2;
        x1 = ROTL64(x1,r) + s[2*i];

        r = x1 & 63;
        x2 ^= x1;
        x2 = ROTL64(x2,r) + s[2*i + 1];
    }
    X1 = x1;
    X2 = x2;
}

void rc5_32_decrypt_2w(uint32_t &X1, uint32_t &X2, const uint32_t *s) {
    uint32_t x1 = X1;
    uint32_t x2 = X2;
    int r;
    for ( int i = ROUNDS ; i > 0 ; i-- ) {
        r = x1 & 31;
        x2 -= s[2*i+1];
        x2 = ROTR32(x2,r);
        x2 ^= x1;

        r = x2 & 31;
        x1 -= s[2*i];
        x1 = ROTR32(x1,r);
        x1 ^= x2;
    }
    x2 -= s[1];
    x1 -= s[0];
    X2 = x2;
    X1 = x1;
}

void rc5_64_decrypt_2w(uint64_t &X1, uint64_t &X2, const uint64_t *s) {
    uint64_t x1 = X1;
    uint64_t x2 = X2;
    int r;
    for ( int i = ROUNDS ; i > 0 ; i-- ) {
        r = x1 & 63;
        x2 -= s[2*i+1];
        x2 = ROTR64(x2,r) ^ x1;

        r = x2 & 63;
        x1 -= s[2*i];
        x1 = ROTR64(x1,r) ^ x2;
    }
    x2 -= s[1];
    x1 -= s[0];
    X2 = x2;
    X1 = x1;
}



void rc5_32_encrypt_8b(const uint8_t *plain8, uint8_t *cipher8, const uint32_t *s) {
    uint32_t X1 = qFromLittleEndian<uint32_t>(plain8);
    uint32_t X2 = qFromLittleEndian<uint32_t>(plain8 + 4);
    rc5_32_encrypt_2w(X1, X2, s);
    qToLittleEndian(X1, cipher8);
    qToLittleEndian(X2, cipher8 + 4);
}

void rc5_64_encrypt_16b(const uint8_t *plain16, uint8_t *cipher16, const uint64_t *s) {
    uint64_t X1 = qFromLittleEndian<uint64_t>(plain16);
    uint64_t X2 = qFromLittleEndian<uint64_t>(plain16 + 8);
    rc5_64_encrypt_2w(X1, X2, s);
    qToLittleEndian(X1, cipher16);
    qToLittleEndian(X2, cipher16 + 8);
}

void rc5_32_decrypt_8b(const uint8_t *cipher8, uint8_t *plain8, const uint32_t *s) {
    uint32_t X1 = qFromLittleEndian<uint32_t>(cipher8);
    uint32_t X2 = qFromLittleEndian<uint32_t>(cipher8 + 4);
    rc5_32_decrypt_2w(X1, X2, s);
    qToLittleEndian(X1, plain8);
    qToLittleEndian(X2, plain8 + 4);
}

void rc5_64_decrypt_16b(const uint8_t *cipher16, uint8_t *plain16, const uint64_t *s) {
    uint64_t X1 = qFromLittleEndian<uint64_t>(cipher16);
    uint64_t X2 = qFromLittleEndian<uint64_t>(cipher16 + 8);
    rc5_64_decrypt_2w(X1, X2, s);
    qToLittleEndian(X1, plain16);
    qToLittleEndian(X2, plain16 + 8);
}

#endif // WITHRC5


/* SERPENT BELOW */


#ifdef WITH_SERPENT_FAST_SBOX

uint32_t serpent_sbox_fast(int sbox, uint32_t X) {
    int sbox512 = sbox * 512;
    quint16 Y = 0;
    uint32_t R = 0;

    Y  = serpent_sbox_fast_data[ sbox512 + ( 0xff & X ) + 256 ];
    X >>= 8;
    Y += serpent_sbox_fast_data[ sbox512 + ( 0xff & X ) ];
    X >>= 8;

    R = Y;
    Y  = serpent_sbox_fast_data[ sbox512 + ( 0xff & X ) + 256 ];
    X >>= 8;
    Y += serpent_sbox_fast_data[ sbox512 + ( 0xff & X ) ];

    R += ( Y << 16 );

    return R;
}

#else

const quint8 serpent_sboxes[256] = {
  //sbox [0-7]
  //      0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
	0x3,0x8,0xf,0x1,0xa,0x6,0x5,0xb,0xe,0xd,0x4,0x2,0x7,0x0,0x9,0xc,
	0xf,0xc,0x2,0x7,0x9,0x0,0x5,0xa,0x1,0xb,0xe,0x8,0x6,0xd,0x3,0x4,
	0x8,0x6,0x7,0x9,0x3,0xc,0xa,0xf,0xd,0x1,0xe,0x4,0x0,0xb,0x5,0x2,
	0x0,0xf,0xb,0x8,0xc,0x9,0x6,0x3,0xd,0x1,0x2,0x4,0xa,0x7,0x5,0xe,
	0x1,0xf,0x8,0x3,0xc,0x0,0xb,0x6,0x2,0x5,0x4,0xa,0x9,0xe,0x7,0xd,
	0xf,0x5,0x2,0xb,0x4,0xa,0x9,0xc,0x0,0x3,0xe,0x8,0xd,0x6,0x7,0x1,
	0x7,0x2,0xc,0x5,0x8,0x4,0x6,0xb,0xe,0x9,0x1,0xf,0xd,0x3,0xa,0x0,
	0x1,0xd,0xf,0x0,0xe,0x8,0x2,0xb,0x7,0x4,0xc,0xa,0x9,0x3,0x5,0x6,
  //inverse sbox[8-15]
  //      0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
	0xd,0x3,0xb,0x0,0xa,0x6,0x5,0xc,0x1,0xe,0x4,0x7,0xf,0x9,0x8,0x2,
	0x5,0x8,0x2,0xe,0xf,0x6,0xc,0x3,0xb,0x4,0x7,0x9,0x1,0xd,0xa,0x0,
	0xc,0x9,0xf,0x4,0xb,0xe,0x1,0x2,0x0,0x3,0x6,0xd,0x5,0x8,0xa,0x7,
	0x0,0x9,0xa,0x7,0xb,0xe,0x6,0xd,0x3,0x5,0xc,0x2,0x4,0x8,0xf,0x1,
	0x5,0x0,0x8,0x3,0xa,0x9,0x7,0xe,0x2,0xc,0xb,0x6,0x4,0xf,0xd,0x1,
	0x8,0xf,0x2,0x9,0x4,0x1,0xd,0xe,0xb,0x6,0x5,0x3,0x7,0xc,0xa,0x0,
	0xf,0xa,0x1,0xd,0x5,0x3,0x6,0x0,0x4,0x9,0xe,0x7,0x2,0xc,0x8,0xb,
	0x3,0x0,0x6,0xd,0x9,0xe,0xf,0x8,0x5,0xc,0xb,0x7,0xa,0x1,0x4,0x2
};



/*
 * This function is used both for S-boxes and reverse S-boxes
 * since the same thing is done
 * Argument "sbox" > 8 means reverse sbox
 */
void serpent_sbox_it(int sbox, uint32_t &X1, uint32_t &X2,
                               uint32_t &X3, uint32_t &X4) {
    uint32_t i,j,tmp;
    uint32_t newword, mask, X;

    X = X1;
    /* Data block is 128 bits, integer is 32 bits => 4 loops */	
    for(i=0;i<4;i++) {
        newword = 0x0;
        switch(i) {
        case 1:
	    X1 = X;
	    X = X2;
            break;
        case 2:
            X2 = X;
            X = X3;
            break;
        case 3:
            X3 = X;
            X = X4;
            break;
        default:
            break;
        }
	
        /* Copying on bit per loop round to its new position
           working on 2x16 bits */
        for(j=0;j<0x10;j++) {
            tmp = *(serpent_sboxes + 0x10*sbox + j);
            mask = 0x80008000;
            mask >>= tmp;
            mask &= X;
            mask <<= tmp;
            mask >>= j;
            newword |= mask;
        }
        X = newword;
    }
    X4 = X;
}

#endif


void serpent_encrypt_4w(uint32_t &X1a, uint32_t &X2a,
                        uint32_t &X3a, uint32_t &X4a, const uint32_t *s) {
    int round, rm8;
    uint32_t X1, X2, X3, X4;
    /* LOOP THROUGH THE 32 ROUNDS */

    X1 = X1a;
    X2 = X2a;
    X3 = X3a;
    X4 = X4a;

    // for(round=0 ; round<ROUNDS ; round++) {
    round = 0;
    while ( 1 ) {
    
        /* KEY MIXING */
        X1 = s[4*round    ] ^ X1;
        X2 = s[4*round + 1] ^ X2;
        X3 = s[4*round + 2] ^ X3;
        X4 = s[4*round + 3] ^ X4;

        /* APPLY S-BOX */
        rm8 = round & 0x7;
#ifdef WITH_SERPENT_FAST_SBOX
	X1 = serpent_sbox_fast(rm8, X1);
	X2 = serpent_sbox_fast(rm8, X2);
	X3 = serpent_sbox_fast(rm8, X3);
	X4 = serpent_sbox_fast(rm8, X4);
#else
        serpent_sbox_it(rm8 , X1, X2, X3, X4);
#endif
        if ( round == ROUNDS-1 ) break;

        /* DO LINEAR TRANSFORMATION (not in last round) */
        X1 = ROTL32(X1, 13);
        X3 = ROTL32(X3, 3);
        X2 = X2 ^ X1 ^ X3;
        X4 = X4 ^ X3 ^ ( X1 << 3 );
        X2 = ROTL32(X2, 1);
        X4 = ROTL32(X4, 7);
        X1 = X1 ^ X2 ^ X4;
        X3 = X3 ^ X4 ^ ( X2 << 7 );
        X1 = ROTL32(X1, 5);
        X3 = ROTL32(X3, 22);

        round++;
    }

    /* FINAL KEY MIX */
    X1a = X1 ^ s[128];
    X2a = X2 ^ s[129];
    X3a = X3 ^ s[130];
    X4a = X4 ^ s[131];
}


void serpent_decrypt_4w(uint32_t &X1a, uint32_t &X2a,
                        uint32_t &X3a, uint32_t &X4a, const uint32_t *s) {
    int round, rm8;
    uint32_t X1, X2, X3, X4;

    X1 = X1a ^ s[128];
    X2 = X2a ^ s[129];
    X3 = X3a ^ s[130];
    X4 = X4a ^ s[131];

    round = ROUNDS - 1;
    while ( 1 ) {
        rm8 = (round & 0x7) + 8;
#ifdef WITH_SERPENT_FAST_SBOX
	X1 = serpent_sbox_fast(rm8, X1);
	X2 = serpent_sbox_fast(rm8, X2);
	X3 = serpent_sbox_fast(rm8, X3);
	X4 = serpent_sbox_fast(rm8, X4);
#else
        serpent_sbox_it(rm8 , X1, X2, X3, X4);
#endif

        X1 = s[4*round    ] ^ X1;
        X2 = s[4*round + 1] ^ X2;
        X3 = s[4*round + 2] ^ X3;
        X4 = s[4*round + 3] ^ X4;

        round--;
        if ( -1 == round ) break;

        X3 = ROTR32(X3, 22);
        X1 = ROTR32(X1, 5);
        X3 = X3 ^ X4 ^ (X2 << 7);
        X1 = X1 ^ X2 ^ X4;
        X4 = ROTR32(X4, 7);
        X2 = ROTR32(X2, 1);
        X4 = X4 ^ X3 ^ (X1 << 3);
        X2 = X2 ^ X1 ^ X3;
        X3 = ROTR32(X3, 3);
        X1 = ROTR32(X1, 13);
    }

    X1a = X1;
    X2a = X2;
    X3a = X3;
    X4a = X4;
}

void serpent_encrypt_16b(const uint8_t *plain16, uint8_t *cipher16, const uint32_t *s) {
    uint32_t X1 = qFromLittleEndian<uint32_t>(plain16);
    uint32_t X2 = qFromLittleEndian<uint32_t>(plain16 + 4);
    uint32_t X3 = qFromLittleEndian<uint32_t>(plain16 + 8);
    uint32_t X4 = qFromLittleEndian<uint32_t>(plain16 + 12);
    serpent_encrypt_4w(X1, X2, X3, X4, s);
    qToLittleEndian(X1, cipher16);
    qToLittleEndian(X2, cipher16 + 4);
    qToLittleEndian(X3, cipher16 + 8);
    qToLittleEndian(X4, cipher16 + 12);
}

void serpent_decrypt_16b(const uint8_t *cipher16, uint8_t *plain16, const uint32_t *s) {
    uint32_t X1 = qFromLittleEndian<uint32_t>(cipher16);
    uint32_t X2 = qFromLittleEndian<uint32_t>(cipher16 + 4);
    uint32_t X3 = qFromLittleEndian<uint32_t>(cipher16 + 8);
    uint32_t X4 = qFromLittleEndian<uint32_t>(cipher16 + 12);
    serpent_decrypt_4w(X1, X2, X3, X4, s);
    qToLittleEndian(X1, plain16);
    qToLittleEndian(X2, plain16 + 4);
    qToLittleEndian(X3, plain16 + 8);
    qToLittleEndian(X4, plain16 + 12);
}


#ifdef WITH_SERPENT_PRINT_SBOX_H
void serpent_print_sbox_h() {
    int sbox;
    int i;
    uint32_t X1, X2, X3, X4;

    i = X2 = X3 = X4 = 0;

    printf("/* THIS IS serpent_sbox.h\n");
    printf(" * #include it in simpleqtcryptor.c for faster serpent\n");
    printf(" */\n\n");

    printf("#define WITH_SERPENT_FAST_SBOX\n\n");
    
    printf("const quint16 serpent_sbox_fast_data[] = {\n");

    for ( sbox = 0 ; sbox < 16 ; sbox++ ) {

        printf("\n// SBOX: %d , 0000-FF00", sbox);
        for ( i = 0 ; i < 256 ; i++ ) {
            if ( 0 == (i % 64) ) {
                printf("\n  /* *** %d - %d *** */\n", i, i+63);
            } else if ( 0 == ( i % 8 ) ) {
                printf("\n");
            }
            X1 = i * 256;

#ifdef WITH_SERPENT_FAST_SBOX
            X1 = serpent_sbox_fast(sbox, X1);
#else
            serpent_sbox_it(sbox, X1, X2, X3, X4);
#endif
            printf("0x%04x,", X1);
        }

        printf("\n// SBOX: %d , 0000-00FF", sbox);
        for ( i = 0 ; i < 256 ; i++ ) {
            if ( 0 == (i % 64) ) {
                printf("\n  /* *** %d - %d *** */\n", i, i+63);
            } else if ( 0 == ( i % 8 ) ) {
                printf("\n");
            }
            X1 = i;

#ifdef WITH_SERPENT_FAST_SBOX
            X1 = serpent_sbox_fast(sbox, X1);
#else
            serpent_sbox_it(sbox, X1, X2, X3, X4);
#endif
            printf("0x%04x,", X1);
        }
    }
    printf("0x0};\n");
}

#endif // WITH_SERPENT_PRINT_SBOX_H


}; //namespace
