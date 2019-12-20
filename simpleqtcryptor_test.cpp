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

#include <QString>
#include <QByteArray>
#include <QtGlobal>
#include <QSharedPointer>
#include <QFile>


#include <QDebug>

#include "simpleqtcryptor_test.h"

namespace SimpleQtCryptor {

SelfTest::SelfTest() {
}

SelfTest::~SelfTest() {
}

QString getRandomString() {
    QByteArray tmp(2 + qrand() % 18 , 0);
    return tmp.toBase64();
}

void SelfTest::print(QString line) {
    if ( 0 == outString) {
        outFile->write(line.toAscii());
        outFile->flush();
    } else {
        outString->append(line);
    }
}


// Function implementations

bool SelfTest::test_key_zero_expand(QSharedPointer<SimpleQtCryptor::Key> k) {
    int expect = 58000;
    k->expandKeyRc532();
    int value = qChecksum(k->keyRc5.data(), k->keyRc5.size());
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of RC5 key was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_key_zero_expand_spt(QSharedPointer<SimpleQtCryptor::Key> k) {
    int expect = 52592;
    k->expandKeySerpent();
    int value = qChecksum(k->keySerpent.data(), k->keySerpent.size());
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of RC5 key was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_key_zero_s32(QSharedPointer<SimpleQtCryptor::Key> k) {
    quint32 expect = 3283408660UL;
    k->expandKeyRc532();
    quint32 value = 0;
    for (int i=0 ; i<66 ; i++) {
        value ^= k->s32[i];
    }
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of key was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_key_zero_s64(QSharedPointer<SimpleQtCryptor::Key> k) {
    quint64 expect = Q_UINT64_C(13974939462919509502);
    k->expandKeyRc564();
    quint64 value = 0;
    for (int i=0 ; i<66 ; i++) {
        value ^= k->s64[i];
    }
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of key was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_key_zero_spt(QSharedPointer<SimpleQtCryptor::Key> k) {
    quint32 expect = 2347418874UL;
    k->expandKeySerpent();
    quint32 value = 0;
    for (int i=0 ; i<132 ; i++) {
        value ^= k->serpent[i];
    }
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of key was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}


bool SelfTest::test_rc5_32_encrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar cph[8];
    SimpleQtCryptor::rc5_32_encrypt_8b(data, cph, k->s32);
    int value = qChecksum((char*)cph, 8);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of ciphertext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_rc5_64_encrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar cph[16];
    SimpleQtCryptor::rc5_64_encrypt_16b(data, cph, k->s64);
    int value = qChecksum((char*)cph, 16);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of ciphertext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_rc5_32_decrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar pln[8];
    SimpleQtCryptor::rc5_32_decrypt_8b(data, pln, k->s32);
    int value = qChecksum((char*)pln, 8);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of plaintext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_rc5_64_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar pln[16];
    SimpleQtCryptor::rc5_64_decrypt_16b(data, pln, k->s64);
    int value = qChecksum((char*)pln, 16);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of plaintext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_serpent_encrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar cph[16];
    SimpleQtCryptor::serpent_encrypt_16b(data, cph, k->serpent);
    int value = qChecksum((char*)cph, 16);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of ciphertext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_serpent_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect) {
    uchar pln[16];
    SimpleQtCryptor::serpent_decrypt_16b(data, pln, k->serpent);
    int value = qChecksum((char*)pln, 16);
    if ( expect != value ) {
        print(QString("\n  FAILED: checksum of plaintext was %1, expected %2\n").arg(value).arg(expect));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_rc5_32_encrypt_decrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data) {
    uchar cip[8];
    uchar pln[8];
    SimpleQtCryptor::rc5_32_encrypt_8b(data, cip, k->s32);
    SimpleQtCryptor::rc5_32_decrypt_8b(cip,  pln, k->s32);
    if ( qChecksum((char*)data, 8) != qChecksum((char*)pln, 8) ) {
        print(QString("\n  FAILED: decryption did not recover plaintext\n"));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_rc5_64_encrypt_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data) {
    uchar cip[16];
    uchar pln[16];
    SimpleQtCryptor::rc5_64_encrypt_16b(data, cip, k->s64);
    SimpleQtCryptor::rc5_64_decrypt_16b(cip,  pln, k->s64);
    if ( qChecksum((char*)data, 16) != qChecksum((char*)pln, 16) ) {
        print(QString("\n  FAILED: decryption did not recover plaintext\n"));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test_serpent_encrypt_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data) {
    uchar cip[16];
    uchar pln[16];
    SimpleQtCryptor::serpent_encrypt_16b(data, cip, k->serpent);
    SimpleQtCryptor::serpent_decrypt_16b(cip,  pln, k->serpent);
    if ( qChecksum((char*)data, 16) != qChecksum((char*)pln, 16) ) {
        print(QString("\n  FAILED: decryption did not recover plaintext\n"));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test2_CBC_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a) {
    SimpleQtCryptor::CBC cbc(k, a);
    QByteArray cipher = cbc.encrypt(data, true);
    QByteArray plain  = cbc.decrypt(cipher, true);
    if ( data.size() != plain.size() ) {
        print(QString("\n  FAILED: recovered plaintext not same size as original (%1, not %2)\n").arg(plain.size()).arg(data.size()));
        return false;
    }
    if ( qChecksum(data.data(), data.size()) != qChecksum(plain.data(), plain.size()) ) {
        print(QString("\n  FAILED: recovered plaintext not identical to original\n"));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test2_CFB_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a) {
    SimpleQtCryptor::CFB cfb(k, a);
    QByteArray cipher = cfb.encrypt(data);
    cfb.reset();
    QByteArray plain  = cfb.decrypt(cipher);
    cfb.reset();
    if ( data.size() != plain.size() ) {
        print(QString("\n  FAILED: recovered plaintext not same size as original (%1, not %2)\n").arg(plain.size()).arg(data.size()));
        return false;
    }
    if ( qChecksum(data.data(), data.size()) != qChecksum(plain.data(), plain.size()) ) {
        print(QString("\n  FAILED: recovered plaintext not identical to original\n"));
        return false;
    } else {
        print(QString(" passed\n"));
    }
    return true;
}

bool SelfTest::test2_encrypt_decrypt_pieceByPiece(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m) {
    SimpleQtCryptor::LayerMode *modex;
    qint64 tmpl = 0;
    qint64 tmpx = 0;
    int ps = -1;
    int cs = -1;
    int half = -1;
    QByteArray cipher;
    QByteArray cipherNN;
    QByteArray cipher0X0;
    QByteArray cipherR;
    QByteArray cipherC;
    QByteArray plain;

    QString descList[4] = { QString("ALL-IN-ONE") , QString("SPLIT-IN-TWO") ,
                            QString("EMPTY-HEAD-AND-TAIL") , QString("SPLIT-RANDOMLY") };

    int decOrderList[8][4] = { { 1 , 2 , 3 , 0 } , { 1 , 3 , 0 , 2 } , { 2 , 0 , 3 , 1 } , { 2 , 3 , 0 , 1 } ,
                               { 2 , 3 , 1 , 0 } , { 3 , 0 , 1 , 2 } , { 3 , 2 , 0 , 1 } , { 3 , 2 , 1 , 0 } };
    int *decOrder = decOrderList[qrand() % 8];

    // int decOrder[4] = { 0,0,0,0 };
    if (m == SimpleQtCryptor::ModeCBC) {
        modex = new SimpleQtCryptor::CBC(k, a);
    } else if (m == SimpleQtCryptor::ModeCFB) {
        modex = new SimpleQtCryptor::CFB(k, a);
    } else {
        return false;
    }

    ps = qChecksum((char*)data.data(), data.size());

    // 1. Encrypt everything at once
    cipher = modex->encrypt(data, true);
    cs = qChecksum((char*)cipher.data(), cipher.size());

    // 2. Encrypt in two pices
    half = data.size() / 2;
    cipherNN = modex->encrypt(data.left(half), false);
    cipherNN.append(modex->encrypt(data.right(data.size() - half), true));
    if ( cipher.size() != cipherNN.size() ) {
        print(QString("\n  FAILED: encrypting (%1) gave wrong cipher size (%2 not %3\n").arg(descList[1]).arg(cipherNN.size()).arg(cipher.size()));
        goto failure;
    }

    // 3. Encrypt first block of 0 size, then everything, and then finally another block of 0
    cipher0X0 = modex->encrypt(QByteArray(), false);
    cipher0X0.append(modex->encrypt(data, false));
    cipher0X0.append(modex->encrypt(QByteArray(), true));
    if ( cipher.size() != cipher0X0.size() ) {
        print(QString("\n  FAILED: encrypting (%1) gave wrong cipher size (%2 not %3\n").arg(descList[2]).arg(cipher0X0.size()).arg(cipher.size()));
        goto failure;
    }

    // 4. Encrypt in random block of size 0-47 bytes
    cipherR = QByteArray();
    do {
        tmpx = qMin((qint64)(qrand() % 48 ), data.size() - tmpl);
        cipherR.append(modex->encrypt(data.mid(tmpl, tmpx), tmpx + tmpl == data.size()));
        tmpl += tmpx;
    } while (tmpl < data.size());
    if ( cipher.size() != cipherR.size() ) {
        print(QString("\n  FAILED: encrypting (%1) gave wrong cipher size (%2 not %3)\n").arg(descList[3]).arg(cipherR.size()).arg(cipher.size()));
        goto failure;
    }

    for ( int i = 0 ; i < 4 ; i++ ) {
        switch (i) {
        case 0:
            cipherC = cipher;
            break;
        case 1:
            cipherC = cipherNN;
            break;
        case 2:
            cipherC = cipher0X0;
            break;
        case 3:
        default:
            cipherC = cipherR;
        }

        switch(decOrder[i]) {
        case 0:
            // 1. Encrypt everything at once
            plain = modex->decrypt(cipherC, true);
            break;
        case 1:
            // 2. Decrypt half and half
            half = cipherC.size() / 2;
            plain = modex->decrypt(cipherC.left(half), false);
            plain.append(modex->decrypt(cipherC.right(cipherC.size() - half), true));
            break;
        case 2:
            // 3. Encrypt first block of 0 size, then everything, and then finally another block of 0
            plain = modex->decrypt(QByteArray(), false);
            plain.append(modex->decrypt(cipherC, false));
            plain.append(modex->decrypt(QByteArray(), true));
            break;
        case 3:
        default:
            tmpl = tmpx = 0;
            while (tmpl < cipherC.size()) {
                tmpx = qMin((qint64)(qrand() % 48 ), cipherC.size() - tmpl);
                plain.append(modex->decrypt(cipherC.mid(tmpl, tmpx), tmpx + tmpl == cipherC.size()));
                tmpl += tmpx;
            }
            break;
        }
        if ( plain.size() != data.size() ) {
            print(QString("\n  FAILED: encrypting (%1) and decrypting (%2)\n").arg(descList[i]).arg(descList[decOrder[i]]));
            print(QString("          gave wrong plain size (%1 not %2)\n").arg(plain.size()).arg(data.size()));
            goto failure;
        }
        if ( ps != qChecksum((char*)plain.data(), plain.size()) ) {
            print(QString("\n  FAILED: encrypting (%1) and decrypting (%2)\n").arg(descList[i]).arg(descList[decOrder[i]]));
            print(QString("          gave wrong plain text data\n"));
            goto failure;
        }
        plain.clear();
    }
    cs = cs; // to avoid warnings
    delete modex;
    print(QString(" passed\n"));
    return true;
failure:
    delete modex;
    return false;
}

bool SelfTest::test3_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m) {
    SimpleQtCryptor::Encryptor ex(k, a, m, SimpleQtCryptor::NoChecksum);
    SimpleQtCryptor::Decryptor dx(k, a, m);
    QByteArray ct;
    QByteArray pt;
    SimpleQtCryptor::Error er;
    er = ex.encrypt(data, ct, true);
    if ( SimpleQtCryptor::NoError != er ) {
        print(QString("\n  FAILED: on encryption: %1\n").arg(SimpleQtCryptor::Info::errorText(er)));
        return false;
    }
    er = dx.decrypt(ct, pt, true);
    if ( SimpleQtCryptor::NoError != er ) {
        print(QString("\n  FAILED: on decryption: %1\n").arg(SimpleQtCryptor::Info::errorText(er)));
        return false;
    }

    if ( data.size() != pt.size() ) {
        print(QString("\n  FAILED: wrong size of decrypted data (%1 not %2)\n").arg(pt.size()).arg(data.size()));
        return false;
    }

    if ( qChecksum((char*)data.data(), data.size()) != qChecksum((char*)pt.data(), pt.size()) ) {
        print(QString("\n  FAILED: decryption did not recover original data\n"));
        return false;
    }

    print(QString(" passed\n"));
    return true;
}

bool SelfTest::test3_decryptorwiz(QSharedPointer<SimpleQtCryptor::Key> *kl, int kc, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m) {
    SimpleQtCryptor::Encryptor ex(kl[qrand() % kc], a, m, SimpleQtCryptor::NoChecksum);
    QByteArray ct;
    QByteArray cttmp;
    QByteArray pt;
    QByteArray pttmp;
    SimpleQtCryptor::Error er;
    QSharedPointer<SimpleQtCryptor::Decryptor> dx;

    // qDebug() << "SIZE OF DATA=" << (data.size());
    // qDebug() << "---encrypt---";
    int tmpl = data.size();
    int tmpp = 0;
    int tmpx = 0;
    do {
        tmpx = qMin( tmpl - tmpp , qrand() % 80 );
        er = ex.encrypt(data.mid(tmpp, tmpx), cttmp, (tmpl == tmpp + tmpx));
        if ( SimpleQtCryptor::NoError != er ) {
            print(QString("\n  FAILED: on encryption bytes %1-%2: %3\n").arg(tmpp).arg(tmpp+tmpx-1).arg(SimpleQtCryptor::Info::errorText(er)));
            return false;
        }
        tmpp += tmpx;
        ct.append(cttmp);
        cttmp.clear();
    } while (tmpp < tmpl);

    SimpleQtCryptor::DecryptorWizard dw(kl[0], SimpleQtCryptor::DetectAlgorithm, SimpleQtCryptor::DetectMode);
    for ( int i=1 ; i<kc ; i++ ) {
        dw.addParameters(kl[i], a, m);
    }

    // qDebug() << "SIZE OF CT=" << (ct.size());
    // qDebug() << "---decrypt---";
    tmpl = ct.size();
    tmpp = 0;
    tmpx = 0;
    er = dw.decrypt(ct.left(16), pttmp, dx, false);
    if ( SimpleQtCryptor::ErrorNotEnoughData != er ) {
        print(QString("\n  FAILED: not handling too little data correctly, got %1\n").arg(SimpleQtCryptor::Info::errorText(er)));
        return false;
    }
    pttmp.clear();
    tmpx = qMin( 80 + qrand() % 80 , tmpl );
    er = dw.decrypt(ct.left( tmpx ) , pt , dx, false);
    if ( SimpleQtCryptor::NoError != er ) {
        print(QString("\n  FAILED: on decrypting data, got %1\n").arg(SimpleQtCryptor::Info::errorText(er)));
        return false;
    }
    tmpp += tmpx;
    // qDebug() << "---decrypt (2)---";
    do {
        tmpx = qMin( tmpl - tmpp , qrand() % 80 );
        er = dx->decrypt(ct.mid(tmpp, tmpx), pttmp, (tmpl == tmpx + tmpp));
        if ( SimpleQtCryptor::NoError != er ) {
            print(QString("\n  FAILED: on decrypting bytes %1-%2: %3\n").arg(tmpp).arg(tmpp+tmpx-1).arg(SimpleQtCryptor::Info::errorText(er)));
            return false;
        }
        tmpp += tmpx;
        pt.append(pttmp);
        pttmp.clear();
    } while (tmpp < tmpl);

    if ( data.size() != pt.size() ) {
        print(QString("\n  FAILED: wrong size of decrypted data (%1 not %2)\n").arg(pt.size()).arg(data.size()));
        return false;
    }

    if ( qChecksum((char*)data.data(), data.size()) != qChecksum((char*)pt.data(), pt.size()) ) {
        print(QString("\n  FAILED: decryption did not recover original data\n"));
        return false;
    }

    print(QString(" passed\n"));
    return true;
}


bool SelfTest::test(QByteArray &testdata, QString *outmsg) {
    outString = outmsg;
    outFile = 0;
    return test(testdata);
}

bool SelfTest::test(QByteArray &testdata, QFile *outmsg) {
    outString = 0;
    outFile = outmsg;
    return test(testdata);
}

bool SelfTest::test(QByteArray &testdata) {
    if (testdata.isEmpty()) {
        print(QString("Warning, testdata was empty\n"));
    }

    QByteArray testdata16 = testdata.left(qMin(16,testdata.size()));
    if (testdata16.size() < 16) {
        testdata16.append(QByteArray(16 - testdata.size(), 0));
    }

    {
        int rv = qChecksum(testdata.data(), qMin(4096, testdata.size()));
        qsrand(rv);
        print(QString("Random seed for this input file: %1\n").arg(rv));
    }

    print(QString("Setting up keys...\n"));
    print(QString("  - zero key\n"));
    QSharedPointer<SimpleQtCryptor::Key> keyZero(new SimpleQtCryptor::Key());
    print(QString("  - based on String (randomized)\n"));
    QSharedPointer<SimpleQtCryptor::Key> keyStr(new SimpleQtCryptor::Key(getRandomString()));
    print(QString("  - based on Contents of testfile\n"));
    QSharedPointer<SimpleQtCryptor::Key> keyBuf(new SimpleQtCryptor::Key(testdata.left(qMin(testdata.size(), qrand() % 64))));
    print(QString("done\n"));

    QSharedPointer<SimpleQtCryptor::Key> keyAll[3];
    keyAll[0] = keyZero;
    keyAll[1] = keyStr;
    keyAll[2] = keyBuf;

    bool ok = true;
    bool done = false;
    int testn = 1;
    while ( ok && !done ) {
        switch ( testn ) {
        case (0):
            done = true;
            break;
        case (1):
            print(QString("=== KEYS ===\n"));
            print(QString("%1 Expand RC5 Key:").arg(testn));
            ok = test_key_zero_expand(keyZero);
            testn = 2;
            break;
        case (2):
            print(QString("%1 Expand Serpent Key:").arg(testn));
            ok = test_key_zero_expand_spt(keyZero);
            testn = 3;
            break;
        case (3):
            keyStr->expandKeyRc532();
            keyStr->expandKeyRc564();
            keyBuf->expandKeyRc532();
            keyBuf->expandKeyRc564();
            keyStr->expandKeySerpent();
            keyBuf->expandKeySerpent();
            testn = 5;
            break;
        case (5):
            print(QString("%1 S-Field (RC5 32bit):").arg(testn));
            ok = test_key_zero_s32(keyZero);
            testn = 6;
            break;
        case (6):
            print(QString("%1 S-Field (RC5 64bit):").arg(testn));
            ok = test_key_zero_s64(keyZero);
            testn = 7;
            break;
        case (7):
            print(QString("%1 S-Field (Serpent):").arg(testn));
            ok = test_key_zero_spt(keyZero);
            testn = 11;
            break;
        case (11):
            print(QString("=== LEVEL 1 ===\n"));
            print(QString("%1 RC5 Encrypt Zero (32bit):").arg(testn));
            ok = test_rc5_32_encrypt_8b(keyZero, (uchar*)(QByteArray(8,0).data()) , 33590);
            testn = 12;
            break;
        case (12):
            print(QString("%1 RC5 Encrypt Zero (64bit):").arg(testn));
            ok = test_rc5_64_encrypt_16b(keyZero, (uchar*)(QByteArray(16,0).data()) , 25205);
            testn = 13;
            break;
        case (13):
            print(QString("%1 RC5 Decrypt Zero (32bit):").arg(testn));
            ok = test_rc5_32_decrypt_8b(keyZero, (uchar*)(QByteArray(8,0).data()) , 16263);
            testn = 14;
            break;
        case (14):
            print(QString("%1 RC5 Decrypt Zero (64bit):").arg(testn));
            ok = test_rc5_64_decrypt_16b(keyZero, (uchar*)(QByteArray(16,0).data()) , 27423);
            testn = 15;
            break;
        case (15):
            print(QString("%1 Serpent Encrypt Zero:").arg(testn));
            ok = test_serpent_encrypt_16b(keyZero, (uchar*)(QByteArray(16,0).data()) , 12239);
            testn = 16;
            break;
        case (16):
            print(QString("%1 Serpent Decrypt Zero:").arg(testn));
            ok = test_serpent_decrypt_16b(keyZero, (uchar*)(QByteArray(16,0).data()) , 49930);
            testn = 21;
            break;
        case (21):
            print(QString("%1 RC5 Encrypt & Decrypt first block of file (32bit):").arg(testn));
            ok = test_rc5_32_encrypt_decrypt_8b(keyZero, (uchar*)(testdata16.data()));
            testn = 22;
            break;
        case (22):
            print(QString("%1 RC5 Encrypt & Decrypt first block of file (64bit):").arg(testn));
            ok = test_rc5_64_encrypt_decrypt_16b(keyZero, (uchar*)(testdata16.data()));
            testn = 23;
            break;
        case (23):
            print(QString("%1 Serpent Encrypt & Decrypt first block of file:").arg(testn));
            ok = test_serpent_encrypt_decrypt_16b(keyZero, (uchar*)(testdata16.data()));
            testn = 31;
            break;
        case (31):
            print(QString("=== LEVEL 2 ===\n"));
            print(QString("%1 RC5 CBC Encrypt & Decrypt entire file (32bit):").arg(testn));
            ok = test2_CBC_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20);
            testn = 32;
            break;
        case (32):
            print(QString("%1 RC5 CBC Encrypt & Decrypt entire file (64bit):").arg(testn));
            ok = test2_CBC_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20);
            testn = 33;
            break;
        case (33):
            print(QString("%1 RC5 CFB Encrypt & Decrypt entire file (32bit):").arg(testn));
            ok = test2_CFB_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20);
            testn = 34;
            break;
        case (34):
            print(QString("%1 RC5 CFB Encrypt & Decrypt entire file (64bit):").arg(testn));
            ok = test2_CFB_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20);
            testn = 35;
            break;
        case (35):
            print(QString("%1 Serpent CBC Encrypt & Decrypt entire file:").arg(testn));
            ok = test2_CBC_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32);
            testn = 36;
            break;
        case (36):
            print(QString("%1 Serpent CFB Encrypt & Decrypt entire file:").arg(testn));
            ok = test2_CFB_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32);
            testn = 41;
            break;
        case (41):
            print(QString("%1 RC5 CBC Encrypt in pieces (32bit):").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCBC);
            testn = 42;
            break;
        case (42):
            print(QString("%1 RC5 CBC Encrypt in pieces (64bit):").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20, SimpleQtCryptor::ModeCBC);
            testn = 43;
            break;
        case (43):
            print(QString("%1 RC5 CFB Encrypt in pieces (32bit):").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCFB);
            testn = 44;
            break;
        case (44):
            print(QString("%1 RC5 CFB Encrypt in pieces (64bit):").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20, SimpleQtCryptor::ModeCFB);
            testn = 45;
            break;
        case (45):
            print(QString("%1 Serpent CBC Encrypt in pieces:").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCBC);
            testn = 46;
            break;
        case (46):
            print(QString("%1 Serpent CFB Encrypt in pieces:").arg(testn));
            ok =  test2_encrypt_decrypt_pieceByPiece(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCFB);
            testn = 51;
            break;
        case (51):
            print(QString("=== LEVEL 3 ===\n"));
            print(QString("%1 RC5 CBC Encrypt & Decrypt entire file (32bit):").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCBC);
            testn = 52;
            break;
        case (52):
            print(QString("%1 RC5 CBC Encrypt & Decrypt entire file (64bit):").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20, SimpleQtCryptor::ModeCBC);
            testn = 53;
            break;
        case (53):
            print(QString("%1 RC5 CFB Encrypt & Decrypt entire file (32bit):").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCFB);
            testn = 54;
            break;
        case (54):
            print(QString("%1 RC5 CFB Encrypt & Decrypt entire file (64bit):").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::RC5_64_32_20, SimpleQtCryptor::ModeCFB);
            testn = 55;
            break;
        case (55):
            print(QString("%1 Serpent CBC Encrypt & Decrypt entire file:").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCBC);
            testn = 56;
            break;
        case (56):
            print(QString("%1 Serpent CFB Encrypt & Decrypt entire file:").arg(testn));
            ok = test3_encrypt_decrypt(keyAll[qrand() % 3], testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCFB);
            testn = 61;
            break;
        case (61):
            print(QString("%1 RC5 CBC Encrypt (32bit) - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCBC);
            testn = 62;
            break;
        case (62):
            print(QString("%1 RC5 CBC Encrypt (64bit) - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::RC5_64_32_20, SimpleQtCryptor::ModeCBC);
            testn = 63;
            break;
        case (63):
            print(QString("%1 RC5 CFB Encrypt (32bit) - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCFB);
            testn = 64;
            break;
       case (64):
            print(QString("%1 RC5 CFB Encrypt (64bit) - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::RC5_32_32_20, SimpleQtCryptor::ModeCFB);
            testn = 65;
            break;
        case (65):
            print(QString("%1 Serpent CBC Encrypt - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCBC);
            testn = 66;
            break;
        case (66):
            print(QString("%1 Serpent CFB Encrypt - try DecryptorWizard:").arg(testn));
            ok = test3_decryptorwiz(keyAll, 3, testdata, SimpleQtCryptor::SERPENT_32, SimpleQtCryptor::ModeCFB);
            testn = 0;
            break;
        default:
            print(QString("Unexpected error while testing (1)\n"));
            ok = false;
        }
    }

    if ( ok ) {
        print(QString("PASSED - you may try another testfile\n"));
    } else {
        print(QString("FAILED - something is wrong - dont use SimpleQtCryptor!\n"));
    }
    return ok;
}

// SERPENT TESTS


} //namespace



