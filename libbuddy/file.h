#ifndef FILE_H
#define FILE_H

#include "libbuddy_global.h"
#include <QString>
#include <gpgme++/verificationresult.h>
#include <gpgme++/signingresult.h>
#include <QFileInfo>
#include <elf.h>

namespace buddy
{
class BUDDY_EXPORT File
{
public:
    enum Result
    {
        Success,
        CouldNotOpenFile,
        NotAnElfBinary,
        KeyNotFound,
        KeyCannotSign,
        MalformedFile,
        NoSignaturesFound,
        CouldNotWriteFile,
        BinaryIsNot64Bit,
        KeyIdAmbiguous,
        DuplicateSignature
    };

    File(const QString& filePath);
    bool exists();

    std::tuple<Result, GpgME::SigningResult> sign(const QString& keyId);
    std::tuple<Result, QString> removeSignature(const QString& keyId);
    std::tuple<Result, GpgME::VerificationResult> checkSignatures();
    Result clearAllSignatures();

private:
    QFileInfo m_file;

    std::tuple<Result, QList<QByteArray>> readSignatures(const char* data, const Elf64_Ehdr* header);
    std::tuple<Result, QByteArray> readSignableData(const char* data, const Elf64_Ehdr* header);
    std::tuple<Result, QList<QByteArray>, QByteArray> readSignaturesAndSignableData();
    std::tuple<Result, GpgME::Key> findSecretKey(const QString& keyId);
    std::tuple<Result, QByteArray> readFile();

    QString keyIdFromSignature(const QByteArray& signature);
    bool keyIdsEqual(const QString& a, const QString& b);
    Result writeSignatures(const QList<QByteArray>& signatures, bool isUpdating);
};
}

#endif // FILE_H
