/*
 *  SimpleQtCryptor is an RC5 encryption library for Qt.
 *
 *  Copyright (C) 2010 Gunnar Thorburn
 *
 *  SimpleQtCryptor is free software: you can redistribute it and/or modify
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
#include "simpleqtcryptor_test.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

// Global variables
std::istream *myIn;
std::ostream *myOut;
std::ostream *myStderr;

char cmdCommand;
bool benchEncrypt;
int  benchMegabytes;
char *cmdPassword;
char *cmdSecretFile;
char *cmdSecret;
char *cmdInfile;
char *cmdOutfile;
SimpleQtCryptor::Algorithm cmdAlgorithm;
SimpleQtCryptor::Mode cmdMode;
bool cmdHeader;
bool cmdVerbose;

std::shared_ptr<SimpleQtCryptor::Key> gKey;


// Function declarations
bool encrypt();
bool decrypt();
bool test();
bool benchmark();
bool prepare();

void printVersion() {
        *myStderr << ("SimpleQtCryptor (v1.0.0)\n(C) 2000,2010,2011 Gunnar Thorburn\n    2000 Erik Hemberg\n");
}

void printUsage() {
    if ( !cmdVerbose ) printVersion();
    *myStderr << ("USAGE:\n");
    *myStderr << ("  SimpleQtCryptor -t testfile\n");
    *myStderr << ("  SimpleQtCryptor -b e|d rc532|rc564|spt Mb (benchmark Mb)\n");
    *myStderr << ("  SimpleQtCryptor -e OPTIONS\n");
    *myStderr << ("  SimpleQtCryptor -d OPTIONS\n");
    *myStderr << ("  SimpleQtCryptor -h\n");
    *myStderr << ("OPTIONS:\n");
    *myStderr << ("  -k SecretFile (preferred to -p)\n");
    *myStderr << ("  -p Secret (default = <empty>)\n");
    *myStderr << ("  -i IndataFile\n");
    *myStderr << ("  -o OutdataFile\n");
    *myStderr << ("  -rc5    : use native RC5 algorithm (default)\n");
    *myStderr << ("  -rc532  : use 32-bit RC5\n");
    *myStderr << ("  -rc564  : use 64-bit RC5\n");
    *myStderr << ("  -spt    : use Serpent algorithm\n");
    *myStderr << ("  -cbc    : CBC\n");
    *myStderr << ("  -cfb    : CFB (default)\n");
    *myStderr << ("  -n      : no header\n");
    *myStderr << ("  -v      : verbose\n");
}


int main(int argc, char *argv[]) {
    myStderr = &std::cerr;
    myIn = nullptr;
    myOut = nullptr;

    cmdCommand = 'x';
    cmdSecret = 0;
    cmdSecretFile = 0;
    cmdInfile = 0;
    cmdOutfile = 0;
    cmdAlgorithm = SimpleQtCryptor::NoAlgorithm;
    cmdMode = SimpleQtCryptor::NoMode;
    cmdHeader = true;
    cmdVerbose = false;
    bool ok = false;
    int aCtr = 2;

    if ( 1 == argc ) {
        goto failandprint;
    }
    if ( !qstrcmp("-e", argv[1]) ) {
        cmdCommand = 'e';
    } else if ( !qstrcmp("-d", argv[1]) ) {
        cmdCommand = 'd';
    } else if ( !qstrcmp("-t", argv[1]) ) {
        cmdCommand = 't';
        if ( 3 != argc ) {
            goto failandprint;
        } else {
            cmdInfile = argv[2];
            aCtr++;
        }
    } else if ( !qstrcmp("-b", argv[1]) ) {
        cmdCommand = 'b';
        if ( 5 != argc ) {
            goto failandprint;
        }
        if ( !qstrcmp("e", argv[2]) ) {
            benchEncrypt = true;
        } else if ( !qstrcmp("d", argv[2]) ) {
            benchEncrypt = false;
        } else {
            goto failandprint;
        }
        if ( !qstrcmp("rc532", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::RC5_32_32_20;
        } else if ( !qstrcmp("rc564", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::RC5_64_32_20;
        } else if ( !qstrcmp("spt", argv[3]) ) {
            cmdAlgorithm = SimpleQtCryptor::SERPENT_32;
        } else {
            goto failandprint;
        }
        benchMegabytes = QString(argv[4]).toInt();
        if ( ! ( 0 < benchMegabytes && benchMegabytes < 1000 ) ) {
            goto failandprint;
        }
        aCtr = 5;
    } else if ( !qstrcmp("-h", argv[1]) ) {
        printUsage();
        goto success;
#ifdef WITH_SERPENT_PRINT_SBOX_H
    } else if ( !qstrcmp("-serpent-sbox-h", argv[1]) ) {
        SimpleQtCryptor::serpent_print_sbox_h();
        return 0;
#endif
    } else {
        goto failandprint;
    }

    while (aCtr < argc) {
        if ( !qstrcmp("-k", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdSecretFile = argv[aCtr];
        } else if ( !qstrcmp("-p", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdSecret = argv[aCtr];
        } else if ( !qstrcmp("-i", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdInfile = argv[aCtr];
        } else if ( !qstrcmp("-o", argv[aCtr]) ) {
            aCtr++;
            if (aCtr >= argc) {
                goto failandprint;
            }
            cmdOutfile = argv[aCtr];
        } else if ( !qstrcmp("-spt", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::SERPENT_32;
        } else if ( !qstrcmp("-rc532", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::RC5_32_32_20;
        } else if ( !qstrcmp("-rc564", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::RC5_64_32_20;
        } else if ( !qstrcmp("-rc5", argv[aCtr]) ) {
            if ( cmdAlgorithm != SimpleQtCryptor::NoAlgorithm )
                goto failandprint;
            cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
        } else if ( !qstrcmp("-cbc", argv[aCtr]) ) {
            cmdMode = SimpleQtCryptor::ModeCBC;
        } else if ( !qstrcmp("-cfb", argv[aCtr]) ) {
            cmdMode = SimpleQtCryptor::ModeCFB;
        } else if ( !qstrcmp("-n", argv[aCtr]) ) {
            cmdHeader = false;
        } else if ( !qstrcmp("-v", argv[aCtr]) ) {
            cmdVerbose = true;
            printVersion();
        } else {
            myStderr->write("Unrecognised argument: ");
            myStderr->write(argv[aCtr]);
            myStderr->write("\n");
            goto failandprint;
        }
        aCtr++;
    }   

    switch (cmdCommand) {
    case 't':
        ok = test();
        break;
    case 'b':
        ok = benchmark();
        break;
    case 'e':
        ok = prepare();
        if (ok) ok = encrypt();
        break;
    case 'd':
        ok = prepare();
        if (ok) ok = decrypt();
        break;
    default:
        goto failandprint;
    }

    if (!ok) goto failure;

success:
    if (myIn) myIn->close();
    if (myOut) myOut->close();
    myStderr->close();
    return 0;
failandprint:
    printUsage();
failure:
    if (myIn) myIn->close();
    if (myOut) myOut->close();
    myStderr->close();
    return 1;
}

bool prepare() {
    if ( 0 == cmdSecret && 0 == cmdSecretFile ) {
        if (cmdVerbose) myStderr->write("Using empty Secret\n");
        gKey = std::make_shared<SimpleQtCryptor::Key>(std::string(""));
    } else if ( 0 != cmdSecret && 0 != cmdSecretFile ) {
        *myStderr << ("Error: use either -k or -p\n");
    } else if ( 0 != cmdSecret ) {
        gKey = std::make_shared<SimpleQtCryptor::Key>(std::string(cmdSecret));
    } else {
        std::ifstream kfile(cmdSecretFile);
        if (!kfile.is_open()) {
            *myStderr << ("failed to open secret file ");
            *myStderr << (cmdSecretFile);
            *myStderr << ("\n");
            return false;
        }
        
        std::vector<uint8_t> k;
        if (!kfile.eof()) {
            kfile.seekg(0, std::ios_base::end);
            std::streampos fileSize = file.tellg();
            k.resize(fileSize);

            file.seekg(0, std::ios_base::beg);
            file.read(&k[0], fileSize);
        }
        gKey = std::make_shared<SimpleQtCryptor::Key>(k);
        if (cmdVerbose) {
            myStderr->write("using contents of  ");
            myStderr->write(cmdSecretFile);
            myStderr->write(" as encryption key\n");
        }
    }

    if ( 0 == cmdInfile ) {
        myIn = &std::cin;
    } else {
        myIn = new QFile(QString::fromAscii(cmdInfile));
        if ( ! myIn->open(QIODevice::ReadOnly) ) {
            delete myIn;
            myIn = 0;
            myStderr->write("Failed to open Input File ");
            myStderr->write(cmdInfile);
            myStderr->write("\n");
            return false;
        }
    }

    if ( 0 == cmdOutfile ) {
        myOut = new QFile(0);
        myOut->open(1, QIODevice::WriteOnly);
    } else {
        myOut = new QFile(QString::fromAscii(cmdOutfile));
        if ( ! myOut->open(QIODevice::WriteOnly) ) {
            delete myOut;
            myOut = 0;
            myStderr->write("Failed to open Output File ");
            myStderr->write(cmdOutfile);
            myStderr->write("\n");
            return false;
        }
    }

    return true;
}

bool test() {
    QString testfilename(cmdInfile);
    QFile testfile(testfilename);
    if ( ! testfile.open(QIODevice::ReadOnly) ) {
         myStderr->write("Can not open testfile ");
         myStderr->write(testfilename.toAscii());
         myStderr->write("\n");
        return false;
    }

    QByteArray testdata = testfile.readAll();
    testfile.close();

    SimpleQtCryptor::SelfTest st;
    return st.test(testdata, myStderr);
}

bool benchmark() {
    myStderr->write("Benchmarking...");
    int i;
    SimpleQtCryptor::Key *k = new SimpleQtCryptor::Key();
    if ( cmdAlgorithm == SimpleQtCryptor::RC5_32_32_20 ) {
        quint32 X1 = 0;
        quint32 X2 = 0;
        k->expandKeyRc532();
        i = benchMegabytes * 128000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::rc5_32_encrypt_2w(X1, X2, k->s32);
        } else while ( i-- ) {
            SimpleQtCryptor::rc5_32_decrypt_2w(X1, X2, k->s32);
        }
    } else if ( cmdAlgorithm == SimpleQtCryptor::RC5_64_32_20 ) {
        quint64 X1 = 0;
        quint64 X2 = 0;
        k->expandKeyRc564();
        i = benchMegabytes * 64000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::rc5_64_encrypt_2w(X1, X2, k->s64);
        } else while ( i-- ) {
            SimpleQtCryptor::rc5_64_decrypt_2w(X1, X2, k->s64);
        }
    } else if ( cmdAlgorithm == SimpleQtCryptor::SERPENT_32 ) {
        quint32 X1 = 0;
        quint32 X2 = 0;
        quint32 X3 = 0;
        quint32 X4 = 0;
        k->expandKeySerpent();
        i = benchMegabytes * 64000;
        if ( benchEncrypt ) while ( i-- ) {
            SimpleQtCryptor::serpent_encrypt_4w(X1, X2, X3, X4, k->serpent);
        } else while ( i-- ) {
            SimpleQtCryptor::serpent_decrypt_4w(X1, X2, X3, X4, k->serpent);
        }
    }
    myStderr->write("...done");
    delete k;
    return true;
}

bool encrypt() {
    SimpleQtCryptor::Encryptor *enc = 0;
    SimpleQtCryptor::LayerMode *mox = 0;

    if ( cmdAlgorithm == SimpleQtCryptor::NoAlgorithm ) {
        cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
        if (cmdVerbose) {
            myStderr->write("Defaulting to fastest algorithm for this machine\n");
        }
    }
    if ( cmdMode == SimpleQtCryptor::NoMode ) {
        cmdMode = SimpleQtCryptor::ModeCFB;
        if (cmdVerbose) {
            myStderr->write("Defaulting to CFB mode\n");
        }
    }

    if ( cmdHeader ) {
        if (cmdVerbose) {
            myStderr->write("A little (encrypted) header is written to the file making\n");
            myStderr->write("  it possible to decrypt it without parameters\n");
        }
        enc = new SimpleQtCryptor::Encryptor(gKey, cmdAlgorithm, cmdMode, SimpleQtCryptor::NoChecksum);
    } else {
        if (cmdVerbose) {
            myStderr->write("No header is written to this file. Remember your parameters!\n");
        }
        if ( SimpleQtCryptor::ModeCBC == cmdMode ) {
            mox = new SimpleQtCryptor::CBC(gKey, cmdAlgorithm);
        } else {
            mox = new SimpleQtCryptor::CFB(gKey, cmdAlgorithm);
        }
    }

    myStderr->flush();

    QByteArray indata;
    QByteArray cipher;
    SimpleQtCryptor::Error er = SimpleQtCryptor::NoError;
    do {
        indata = myIn->read(512000);
        if ( cmdHeader ) {
            er = enc->encrypt(indata, cipher, indata.isEmpty());
        } else {
            cipher = mox->encrypt(indata, indata.isEmpty());
        }
        if (SimpleQtCryptor::NoError != er) {
            myStderr->write("Encryption error (very unexpected)\n");
            return false;
        }
        myOut->write(cipher);
        myOut->flush();
        cipher.clear();
    } while ( !indata.isEmpty() );
    delete mox;
    delete enc;
    if (QFile::NoError != myIn->error()) {
        myStderr->write("ERROR reading indata\n");
        return false;
    }
    return true;
}

bool decrypt() {
    QSharedPointer<SimpleQtCryptor::Decryptor> dec;
    SimpleQtCryptor::DecryptorWizard *dew = 0;
    SimpleQtCryptor::LayerMode *mox = 0;

    if ( cmdAlgorithm == SimpleQtCryptor::NoAlgorithm ) {
        if (cmdHeader) {
            cmdAlgorithm = SimpleQtCryptor::DetectAlgorithm;
            if (cmdVerbose) {
                myStderr->write("Defaulting to automatically detect algorithm\n");
            }
        } else {
            cmdAlgorithm = SimpleQtCryptor::Info::fastRC5();
            if (cmdVerbose) {
                myStderr->write("Defaulting to fastest algorithm for this machine\n");
            }
        }
    }
    if ( cmdMode == SimpleQtCryptor::NoMode ) {
        if (!cmdHeader) {
            cmdMode = SimpleQtCryptor::ModeCFB;
            myStderr->write("Defaulting to CFB mode\n");
        } else {
            cmdMode = SimpleQtCryptor::DetectMode;
            if (cmdVerbose) {
                myStderr->write("Defaulting to automatically detect mode\n");
            }
        }
    }

    if ( cmdHeader ) {
        dew = new SimpleQtCryptor::DecryptorWizard(gKey, cmdAlgorithm, cmdMode);
    } else {
        if ( SimpleQtCryptor::ModeCBC == cmdMode ) {
            mox = new SimpleQtCryptor::CBC(gKey, cmdAlgorithm);
        } else {
            mox = new SimpleQtCryptor::CFB(gKey, cmdAlgorithm);
        }
    }

    myStderr->flush();

    QByteArray indata;
    QByteArray plain;
    SimpleQtCryptor::Error er = SimpleQtCryptor::NoError;
    do {
        indata = myIn->read(512000);
        if ( cmdHeader ) {
            if (dec.isNull()) {
                er = dew->decrypt(indata, plain, dec, indata.isEmpty());
            } else {
                er = dec->decrypt(indata, plain, indata.isEmpty());
            }
        } else {
            plain = mox->decrypt(indata, myIn->atEnd());
        }
        if (SimpleQtCryptor::NoError != er) {
            myStderr->write("Decryption error: ");
            myStderr->write(SimpleQtCryptor::Info::errorText(er).toAscii().data());
            myStderr->write("\n");
            return false;
        }
        myOut->write(plain);
        myOut->flush();
        plain.clear();
    } while ( ! indata.isEmpty() );
    if (QFile::NoError != myIn->error()) {
        myStderr->write("ERROR reading indata\n");
        return false;
    }
    return true;
}





