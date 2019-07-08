#include "file.h"
#include <QDataStream>
#include <QGpgME/Protocol>
#include <QProcess>
#include <QGpgME/VerifyDetachedJob>
#include <QGpgME/KeyListJob>
#include <QGpgME/SignJob>
#include <gpgme++/keylistresult.h>

buddy::File::File(const QString& filePath)
    : m_file(filePath)
{
}

bool buddy::File::exists()
{
    return m_file.exists();
}

std::tuple<buddy::File::Result, GpgME::SigningResult> buddy::File::sign(const QString& keyId)
{
    Result result;
    QByteArray fileData;
    std::tie(result, fileData) = readFile();

    if (result != Success)
    {
        return std::make_tuple(result, GpgME::SigningResult());
    }

    const char* data = fileData.data();
    const auto* header = reinterpret_cast<const Elf64_Ehdr*>(fileData.data());

    QList<QByteArray> signatures;
    std::tie(result, signatures) = readSignatures(data, header);
    bool isUpdating = (result == Success);

    QByteArray signableData;
    std::tie(result, signableData) = readSignableData(data, header);

    if (result != Success)
    {
        return std::make_tuple(result, GpgME::SigningResult());
    }

    GpgME::Key key;
    std::tie(result, key) = findSecretKey(keyId.toUpper());
    if (result != Success)
    {
        return std::make_tuple(result, GpgME::SigningResult());
    }

    auto* signJob = QGpgME::openpgp()->signJob();
    QByteArray signature;

    auto signingResult = signJob->exec({key}, signableData, GpgME::SignatureMode::Detached, signature);
    for (const auto& s : signatures)
    {
        if (keyIdsEqual(keyIdFromSignature(s), keyId.toUpper()))
        {
            return std::make_tuple(DuplicateSignature, GpgME::SigningResult());
        }
    }
    signatures << signature;

    return std::make_tuple(writeSignatures(signatures, isUpdating), signingResult);
}

std::tuple<buddy::File::Result, QString> buddy::File::removeSignature(const QString &keyId)
{
    Result result;
    QList<QByteArray> signatures;
    QByteArray signableData;
    std::tie(result, signatures, signableData) = readSignaturesAndSignableData();
    if (result != Success)
    {
        return std::make_tuple(result, QString());
    }

    for (int i = 0; i < signatures.size(); ++i)
    {
        auto signature = signatures[i];
        auto longKeyId = keyIdFromSignature(signature);
        if (keyIdsEqual(longKeyId, keyId))
        {
            signatures.removeAt(i);
            return std::make_tuple(writeSignatures(signatures, true), longKeyId);
        }
    }

    return std::make_tuple(KeyNotFound, QString());
}

std::tuple<buddy::File::Result, GpgME::VerificationResult> buddy::File::checkSignatures()
{
    Result result;
    QList<QByteArray> signatures;
    QByteArray signableData;
    std::tie(result, signatures, signableData) = readSignaturesAndSignableData();

    if (result != Success)
    {
        return {result, {}};
    }

    std::unique_ptr<QGpgME::VerifyDetachedJob> job{QGpgME::openpgp()->verifyDetachedJob()};
    auto signingResult = job->exec(signatures.join(), signableData);
    return {Success, signingResult};
}

buddy::File::Result buddy::File::clearAllSignatures()
{
    Result result;
    std::tie(result, std::ignore) = checkSignatures();
    if (result != Success)
    {
        return result;
    }

    return writeSignatures({}, true);
}

std::tuple<buddy::File::Result, QList<QByteArray>> buddy::File::readSignatures(const char* data, const Elf64_Ehdr* header)
{
    const auto* sectionHeaderList = reinterpret_cast<const Elf64_Shdr*>(data + header->e_shoff);
    const auto* sectionHeaderNameTable = &sectionHeaderList[header->e_shstrndx];

    // Find .signatures section
    for (uint16_t i = 0; i < header->e_shnum; ++i)
    {
        Elf64_Shdr sh = sectionHeaderList[i];
        const char* shName = (data + sectionHeaderNameTable->sh_offset) + sh.sh_name;
        if (strcmp(".signatures", shName) != 0)
        {
            continue;
        }
        const char* shData = (data + sh.sh_offset);
        auto byteArray = QByteArray::fromRawData(shData, static_cast<int>(sh.sh_size));
        QDataStream stream(byteArray);
        stream.setVersion(QDataStream::Qt_5_6);
        QList<QByteArray> signatures;
        stream >> signatures;

        return std::make_tuple(Success, signatures);
    }

    // No .signature section found
    return std::make_tuple(NoSignaturesFound, QList<QByteArray>());
}

std::tuple<buddy::File::Result, QByteArray> buddy::File::readSignableData(const char* data, const Elf64_Ehdr* header)
{
    QByteArray signableData;
    QDataStream stream(&signableData, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_5_6);

    const auto* sectionHeaderList = reinterpret_cast<const Elf64_Shdr*>(data + header->e_shoff);

    // Find .signature section
    for (uint16_t i = 0; i < header->e_shnum; ++i)
    {
        Elf64_Shdr sh = sectionHeaderList[i];
        if ((sh.sh_flags & SHF_ALLOC) == 0)
        {
            // Ignore non-allocated sections
            // These include .comment, .debug_*, .signatures, .symtab, .strtab, .shstrtab
            continue;
        }
        stream << QByteArray::fromRawData(data + sh.sh_offset, static_cast<int>(sh.sh_size));
    }

    return std::make_tuple(signableData.isEmpty() ? MalformedFile : Success, signableData);
}

std::tuple<buddy::File::Result, QList<QByteArray>, QByteArray> buddy::File::readSignaturesAndSignableData()
{
    Result result;

    QByteArray fileData;
    std::tie(result, fileData) = readFile();

    if (result != Success)
    {
        return std::make_tuple(result, QList<QByteArray>(), QByteArray());
    }

    const char* data = fileData.data();
    const auto* header = reinterpret_cast<const Elf64_Ehdr*>(fileData.data());

    QByteArray signableData;
    std::tie(result, signableData) = readSignableData(data, header);

    if (result != Success)
    {
        return std::make_tuple(result, QList<QByteArray>(), QByteArray());
    }

    QList<QByteArray> signatures;
    std::tie(result, signatures) = readSignatures(data, header);

    if (result != Success)
    {
        return std::make_tuple(result, QList<QByteArray>(), QByteArray());
    }

    return std::make_tuple(Success, signatures, signableData);
}

std::tuple<buddy::File::Result, GpgME::Key> buddy::File::findSecretKey(const QString& keyId)
{
    auto* keyListJob = QGpgME::openpgp()->keyListJob();
    std::vector<GpgME::Key> keys;
    auto keyListResult = keyListJob->exec({keyId}, true, keys);

    if (keys.empty())
    {
        return std::make_tuple(KeyNotFound, GpgME::Key::null);
    }
    else if (keys.size() > 1)
    {
        return std::make_tuple(KeyIdAmbiguous, GpgME::Key::null);
    }

    auto key = keys.front();

    if (!key.canSign())
    {
        return std::make_tuple(KeyCannotSign, GpgME::Key::null);
    }

    return std::make_tuple(Success, key);
}

std::tuple<buddy::File::Result, QByteArray> buddy::File::readFile()
{
    QFile f(m_file.absoluteFilePath());
    bool opened = f.open(QFile::ReadOnly);
    if (!opened)
    {
        return std::make_tuple(CouldNotOpenFile, QByteArray());
    }
    QByteArray fileData = f.readAll();
    f.close();

    // Ensure the data is at least as large as the ELF header
    if (static_cast<size_t>(fileData.length()) < sizeof(Elf64_Ehdr))
    {
        return std::make_tuple(NotAnElfBinary, QByteArray());
    }

    const auto* header = reinterpret_cast<const Elf64_Ehdr*>(fileData.data());

    // Check the magic number
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
    {
        // Invalid ELF file
        return std::make_tuple(NotAnElfBinary, QByteArray());
    }

    // Ensure the binary is 64 bit (32 bit support coming soon™)
    if (header->e_ident[EI_CLASS] != ELFCLASS64)
    {
        return std::make_tuple(BinaryIsNot64Bit, QByteArray());
    }

    return std::make_tuple(Success, fileData);
}

QString buddy::File::keyIdFromSignature(const QByteArray &signature)
{
    // Extract the 160-bit fingerprint from the signature
    return signature.mid(12, 20).toHex().toUpper();
}

bool buddy::File::keyIdsEqual(const QString &a, const QString &b)
{
    return a.toUpper() == b.toUpper()
           || a.toUpper().endsWith(b.toUpper())
           || b.toUpper().endsWith(a.toUpper());
}

buddy::File::Result buddy::File::writeSignatures(const QList<QByteArray> &signatures, bool isUpdating)
{
    if (signatures.isEmpty())
    {
        // Remove .signatures section
        QProcess proc;
        proc.setProgram("/usr/bin/objcopy");
        proc.setArguments({"--remove-section", ".signatures", m_file.absoluteFilePath()});
        proc.start();
        proc.waitForFinished();

        return (proc.exitCode() == 0) ? Success : CouldNotWriteFile;
    }

    // Creating an ELF binary programmatically is not gonna happen
    QByteArray signaturesData;
    QDataStream stream(&signaturesData, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_5_6);
    stream << signatures;

    QProcess proc;
    proc.setProgram("/usr/bin/objcopy");
    proc.setArguments({isUpdating ? "--update-section" : "--add-section", ".signatures=/dev/stdin",
                       "--set-section-flags", ".signatures=noload,readonly",
                       m_file.absoluteFilePath()});
    proc.start();
    proc.write(signaturesData);
    proc.closeWriteChannel();
    proc.waitForFinished();

    return (proc.exitCode() == 0) ? Success : CouldNotWriteFile;
}
