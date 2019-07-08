#ifndef FILE_H
#define FILE_H

#include "libbuddy_global.h"
#include <QString>
#include <gpgme++/verificationresult.h>
#include <gpgme++/signingresult.h>
#include <QFileInfo>
#include <elf.h>
#include <QDebug>

namespace buddy
{
namespace detail
{
struct key_type
{
    key_type() {}

    key_type(const QString& key)
        : key(key.toUpper()),
          is_long_key(key.length() == 40)
    {
    }

    void lookupLongKey();

    QString key;
    bool is_long_key;
};

bool operator==(const key_type& a, const key_type& b)
{
    if (a.is_long_key && !b.is_long_key)
    {
        return a.key.endsWith(b.key);
    }
    else if (!a.is_long_key && b.is_long_key)
    {
        return b.key.endsWith(a.key);
    }

    return a.key == b.key;
}

QDataStream& operator<<(QDataStream& stream, const key_type& rhs)
{
    stream << rhs.key;
    return stream;
}

QDataStream& operator>>(QDataStream& stream, key_type& rhs)
{
    QString data;
    stream >> data;
    rhs = key_type(data);
    return stream;
}

uint qHash(const key_type& key, uint seed = 0)
{
    // Return the right-most 8 characters of the key.
    // This is designed to cause collisions between long keys and short keys,
    // in which case operator== determines equality.
    return qHash(key.key.right(8), seed);
}
}
class BUDDY_EXPORT File
{
public:
    using signature_container_t = QHash<detail::key_type, QByteArray>;

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

    std::tuple<Result, signature_container_t> readSignatures(const char* data, const Elf64_Ehdr* header);
    std::tuple<Result, QByteArray> readSignableData(const char* data, const Elf64_Ehdr* header);
    std::tuple<Result, signature_container_t, QByteArray> readSignaturesAndSignableData();
    std::tuple<Result, GpgME::Key> findSecretKey(const QString& keyId);
    std::tuple<Result, QByteArray> readFile();

    Result writeSignatures(const signature_container_t &signatures, bool isUpdating);
};
}

Q_DECLARE_METATYPE(buddy::detail::key_type);


#endif // FILE_H
