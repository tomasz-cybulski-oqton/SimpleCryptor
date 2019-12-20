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


/*
 */

#ifndef SIMPLEQTCRYPTOR_TEST_H
#define SIMPLEQTCRYPTOR_TEST_H


#include "simpleqtcryptor.h"

class QString;
class QFile;
class QByteArray;
#include <QSharedPointer>


namespace SimpleQtCryptor {


class SelfTest {
public:
    SelfTest();
    ~SelfTest();

    bool test(QByteArray &testdata, QString *outmsg);
    bool test(QByteArray &testdata, QFile *outmsg);

private:
    QString *outString;
    QFile *outFile;

    void print(QString line);

    bool test(QByteArray &testdata);

// RC5 tests
    bool test_key_zero_expand(QSharedPointer<SimpleQtCryptor::Key> k);
    bool test_key_zero_s32(QSharedPointer<SimpleQtCryptor::Key> k);
    bool test_key_zero_s64(QSharedPointer<SimpleQtCryptor::Key> k);
    bool test_rc5_32_encrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_rc5_64_encrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_rc5_32_decrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_rc5_64_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_rc5_32_encrypt_decrypt_8b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data);
    bool test_rc5_64_encrypt_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data);
    bool test2_CBC_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a);
    bool test2_CFB_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a);
    bool test2_encrypt_decrypt_pieceByPiece(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);
    bool test3_encrypt_decrypt(QSharedPointer<SimpleQtCryptor::Key> k, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);
    bool test3_decryptorwiz(QSharedPointer<SimpleQtCryptor::Key> *kl, int kc, const QByteArray &data, SimpleQtCryptor::Algorithm a, SimpleQtCryptor::Mode m);

// SERPENT TESTS
    bool test_key_zero_expand_spt(QSharedPointer<SimpleQtCryptor::Key> k);
    bool test_key_zero_spt(QSharedPointer<SimpleQtCryptor::Key> k);
    bool test_serpent_encrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_serpent_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data, int expect);
    bool test_serpent_encrypt_decrypt_16b(QSharedPointer<SimpleQtCryptor::Key> k, const uchar* data);

};



} // namespace


#endif // SIMPLEQTCRYPTOR_TEST_H
