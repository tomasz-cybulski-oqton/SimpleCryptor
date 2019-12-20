/*
 *  SimpleQtCryptor is an encryption library for Qt.
 *
 *  Copyright (C) 2010,2011 Gunnar Thorburn
 *
 *  SimpleQtCrypto is free software: you can redistribute it and/or modify
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

#include <list>
#include <memory>
#include <vector>

// remove this line if you do not want RC5
#define WITHRC5

// this line enables the print serpent_sbox.h functionality
// #define WITH_SERPENT_PRINT_SBOX_H

// remove this line if you want a slightly smaller and much slower
// binary (serpent only)
#define WITH_SERPENT_INCLUDE_FAST_SBOX

#ifndef SIMPLEQTCRYPTOR_H
#define SIMPLEQTCRYPTOR_H

namespace SimpleQtCryptor {

class Encryptor;
class Decryptor;
class LayerMode;
class CFB;
class CBC;

enum Algorithm {
    NoAlgorithm = 0,
    DetectAlgorithm,
#ifdef WITHRC5
    RC5_FAST_32_20,
    RC5_32_32_20,
    RC5_64_32_20,
#endif
    SERPENT_32
};

enum Mode {
    NoMode = 0,
    DetectMode,
    ModeCBC,
    ModeCFB
};

enum Checksum {
    NoChecksum = 0,
    DetectChecksum,
    ChecksumSoft,
    ChecksumHard
};

enum Error {
    NoError = 0,
    // ErrorNoKey,
    ErrorNoAlgorithm,
    ErrorNoMode,
    ErrorInvalidKey,
    ErrorNotEnoughData,
    ErrorModeNotImplemented,
    ErrorAlgorithmNotImplemented,
    ErrorChecksumNotImplemented,
    ErrorAlreadyError
};


enum State {
    StateReset = 0,
    StateOn,
    StateError
};


class Info {
public:
    static Algorithm fastRC5();
    static std::string errorText(Error e);
};



class Key {
public:
    Key();
    Key(const std::vector<uint8_t> &key);
    Key(const std::string &key);
    ~Key();

    // not for use by end application
#ifdef WITHRC5
    void expandKeyRc532();
    void expandKeyRc564();
#endif
    void expandKeySerpent();

    // variables
    std::vector<uint8_t> key;
#ifdef WITHRC5
    std::vector<uint8_t> keyRc5;
    uint32_t *s32;
    uint64_t *s64;
#endif
    std::vector<uint8_t> keySerpent;
    uint32_t *serpent;
private:
    std::vector<uint8_t> resizeKey(int ks);
};


/*
 * About end and reset()
 *  - If you encrypt/decrypt a piece of data (ie a file) in one chunk
 *    make sure end=true. After this, you can use the same LayerMode
 *    object to encrypt/decrypt something else
 *  - If you encrypt/decrypt i piece of data (ie a file or a network
 *    conversation) in more than one chunk, make sure the last chunk
 *    only has end=true.
 *  - Call reset() only if you want to start over after an error
 *    (typically ErrorInvalidKey or ErrorNotEnoughData);
 *    as long as you use end=true, you never need to reset().
 */
class Encryptor {
public:
    Encryptor(std::shared_ptr<Key> k, Algorithm a, Mode m, Checksum c);
    ~Encryptor();   
    Error encrypt(const std::vector<uint8_t> &plain, std::vector<uint8_t> &cipher, bool end);
    void reset();
private:
    std::shared_ptr<Key> key;
    Algorithm algorithm;
    Mode mode;
    Checksum checksum;
    State state;
    LayerMode *modex;
};


// will attempt all different combinations, and give you a
// Decryptor back to decrypt rest of data or more messages
// from the same source
class DecryptorWizardEntry;
class DecryptorWizard {
public:
    DecryptorWizard();
    DecryptorWizard(std::shared_ptr<Key> k, Algorithm a = DetectAlgorithm, Mode m = DetectMode);
    ~DecryptorWizard();

    void addParameters(std::shared_ptr<Key> k, Algorithm a = DetectAlgorithm, Mode m = DetectMode);

    Error decrypt(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain, std::shared_ptr<Decryptor> &decryptor, bool end = false);
    Error decryptToEnd(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain);
private:
    std::list<DecryptorWizardEntry*> entries;
};



class Decryptor {
public:
    Decryptor(std::shared_ptr<Key> k, Algorithm a, Mode m);
    ~Decryptor();
    Error decrypt(const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain, bool end);
    void reset();
    Checksum getChecksumType();
private:
    std::shared_ptr<Key> key;
    Algorithm algorithm;
    Mode mode;
    State state;
    Checksum checksum;
    LayerMode *modex;
};



class InitializationVector {
public:
    static std::vector<uint8_t> getVector8();
    static std::vector<uint8_t> getVector16();
    static void initiate();
};



/* *** Layer 2 : mode layer *** */

/*
 * A single LayerMode object can handle only one encrypt OR decrypt
 * at a time
 */
class LayerMode {
public:
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> plain, bool end) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> cipher, bool end) = 0;
    virtual void reset() = 0;
    virtual ~LayerMode() {};
};

class CFB : public LayerMode {
public:
    CFB(std::shared_ptr<Key> k, Algorithm a);
    ~CFB();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> plain, bool end = false);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> cipher, bool end = false);
    void reset();
private:
    std::vector<uint8_t> buffer;
    int bufferpos;
    Algorithm algorithm;
    std::shared_ptr<Key> key;
};

class CBC : public LayerMode {
public:
    CBC(std::shared_ptr<Key> k, Algorithm a);
    ~CBC();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> plain, bool end);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> cipher, bool end);
    void reset();
private:
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> cbcBuffer;
    std::vector<uint8_t> padHostageBuffer;
    int worksize;
    Algorithm algorithm;
    std::shared_ptr<Key> key;
};


/* *** Layer 1 : block layer - experts only *** */

#ifdef WITHRC5
// input replaced by output
void rc5_32_encrypt_2w(uint32_t &X1, uint32_t &X2, const uint32_t *s);
void rc5_64_encrypt_2w(uint64_t &X1, uint64_t &X2, const uint64_t *s);
void rc5_32_decrypt_2w(uint32_t &X1, uint32_t &X2, const uint32_t *s);
void rc5_64_decrypt_2w(uint64_t &X1, uint64_t &X2, const uint64_t *s);

void rc5_32_encrypt_8b(const uint8_t *plain8, uint8_t *cipher8, const uint32_t *s);
void rc5_64_encrypt_16b(const uint8_t *plain16, uint8_t *cipher16, const uint64_t *s);
void rc5_32_decrypt_8b(const uint8_t *cipher8, uint8_t *plain8, const uint32_t *s);
void rc5_64_decrypt_16b(const uint8_t *cipher16, uint8_t *plain16, const uint64_t *s);
#endif

void serpent_encrypt_4w(uint32_t &X1, uint32_t &X2,
                        uint32_t &X3, uint32_t &X4, const uint32_t *s);

void serpent_decrypt_4w(uint32_t &X1, uint32_t &X2,
                        uint32_t &X3, uint32_t &X4, const uint32_t *s);

void serpent_encrypt_16b(const uint8_t *plain16, uint8_t *cipher16, const uint32_t *s);
void serpent_decrypt_16b(const uint8_t *cipher16, uint8_t *plain16, const uint32_t *s);

#ifdef WITH_SERPENT_PRINT_SBOX_H
void serpent_print_sbox_h();
#endif

} // namespace


#endif // SIMPLEQTCRYPTOR_H
