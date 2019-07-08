#include <QCoreApplication>
#include <QDebug>
#include <buddy/file>
#include <gpgme++/key.h>

int sign(const QStringList& args)
{
    if (args.count() != 2)
    {
        qDebug() << "Usage: ./buddy [-s|--sign] [file] [key]";
        return 1;
    }

    buddy::File f(args[0]);
    if (!f.exists())
    {
        qDebug() << "Error: No such file";
        return 1;
    }

    buddy::File::Result result;
    GpgME::SigningResult signingResult;

    std::tie(result, signingResult) = f.sign(args[1]);
    switch (result)
    {
    case buddy::File::Success:
        qDebug() << "Signed successfully using key"
                 << signingResult.createdSignature(0).fingerprint();
        return 0;
    case buddy::File::CouldNotOpenFile:
        qDebug() << "Error: Could not open file";
        break;
    case buddy::File::NotAnElfBinary:
        qDebug() << "Error: File is not an ELF binary";
        break;
    case buddy::File::KeyNotFound:
        qDebug() << "Error: Signing key not found";
        break;
    case buddy::File::KeyCannotSign:
        qDebug() << "Error: Key cannot be used to sign";
        break;
    case buddy::File::MalformedFile:
        qDebug() << "Error: Malformed file";
        break;
    case buddy::File::CouldNotWriteFile:
        qDebug() << "Error: Could not write signatures (check permissions)";
        break;
    case buddy::File::BinaryIsNot64Bit:
        qDebug() << "Error: Binary is not 64-bit";
        break;
    case buddy::File::DuplicateSignature:
        qDebug() << "Error: Duplicate signature";
        break;
    case buddy::File::NoSignaturesFound:
    case buddy::File::VerificationFailed:
    case buddy::File::OperationNotYetSupported:
    case buddy::File::KeyIdAmbiguous:
        qDebug() << "Error: (unknown error)";
    }
    return 1;
}

int check(const QStringList& args)
{
    if (args.count() != 1)
    {
        qDebug() << "Usage: ./buddy [-c|--check] [file]";
        return 1;
    }

    buddy::File f(args[0]);
    if (!f.exists())
    {
        qDebug() << "Error: No such file";
        return 1;
    }

    buddy::File::Result result;
    GpgME::VerificationResult verificationResult;

    std::tie(result, verificationResult) = f.checkSignatures();

    switch (result)
    {
    case buddy::File::Success:
        break;
    case buddy::File::NoSignaturesFound:
        qDebug() << "File does not have any signatures";
        return 0;
    case buddy::File::CouldNotOpenFile:
        qDebug() << "Error: Could not open file";
        break;
    case buddy::File::NotAnElfBinary:
        qDebug() << "Error: File is not an ELF binary";
        break;
    case buddy::File::MalformedFile:
        qDebug() << "Error: Malformed file";
        break;
    case buddy::File::BinaryIsNot64Bit:
        qDebug() << "Error: Binary is not 64-bit";
        break;
    case buddy::File::KeyNotFound:
    case buddy::File::KeyCannotSign:
    case buddy::File::CouldNotWriteFile:
    case buddy::File::VerificationFailed:
    case buddy::File::KeyIdAmbiguous:
    case buddy::File::DuplicateSignature:
    case buddy::File::OperationNotYetSupported:
        qDebug() << "Error: (unknown error)";
    }

    for (const auto& signature : verificationResult.signatures())
    {
        qDebug().noquote().nospace() << "[" << signature.status().asString() << "] "
                                     << signature.fingerprint();
    }

    return (result == buddy::File::Success) ? 0 : 1;
}

int remove(const QStringList& args)
{
    if (args.count() != 2)
    {
        qDebug() << "Usage: ./buddy [-r|--remove] [file] [key]";
        return 1;
    }

    buddy::File f(args[0]);
    if (!f.exists())
    {
        qDebug() << "Error: No such file";
        return 1;
    }

    buddy::File::Result result;
    QString longKeyId;
    std::tie(result, longKeyId) = f.removeSignature(args[1]);
    switch (result)
    {
    case buddy::File::Success:
        qDebug() << "Successfully removed signature with key" << longKeyId;
        return 0;
    case buddy::File::CouldNotOpenFile:
        qDebug() << "Error: Could not open file";
        break;
    case buddy::File::NotAnElfBinary:
        qDebug() << "Error: File is not an ELF binary";
        break;
    case buddy::File::MalformedFile:
        qDebug() << "Error: Malformed file";
        break;
    case buddy::File::BinaryIsNot64Bit:
        qDebug() << "Error: Binary is not 64-bit";
        break;
    case buddy::File::KeyNotFound:
        qDebug() << "Error: File is not signed with this key";
        break;
    case buddy::File::CouldNotWriteFile:
        qDebug() << "Error: Could not write signatures (check permissions)";
        break;
    case buddy::File::KeyIdAmbiguous:
        qDebug() << "Error: Key ID is ambiguous";
        break;
    case buddy::File::NoSignaturesFound:
    case buddy::File::KeyCannotSign:
    case buddy::File::VerificationFailed:
    case buddy::File::DuplicateSignature:
    case buddy::File::OperationNotYetSupported:
        qDebug() << "Error: (unknown error)";
    }

    return 1;
}

int clearAllSignatures(const QStringList& args)
{
    if (args.count() != 1)
    {
        qDebug() << "Usage: ./buddy --clear-all-signatures [file]";
        return 1;
    }

    buddy::File f(args[0]);
    if (!f.exists())
    {
        qDebug() << "Error: No such file";
        return 1;
    }

    auto result = f.clearAllSignatures();
    switch (result)
    {
    case buddy::File::Success:
        qDebug() << "Successfully removed all signatures";
        return 0;
    case buddy::File::NoSignaturesFound:
        qDebug() << "File does not have any signatures";
        return 0;
    case buddy::File::CouldNotOpenFile:
        qDebug() << "Error: Could not open file";
        break;
    case buddy::File::NotAnElfBinary:
        qDebug() << "Error: File is not an ELF binary";
        break;
    case buddy::File::MalformedFile:
        qDebug() << "Error: Malformed file";
        break;
    case buddy::File::BinaryIsNot64Bit:
        qDebug() << "Error: Binary is not 64-bit";
        break;
    case buddy::File::CouldNotWriteFile:
        qDebug() << "Error: Could not write signatures (check permissions)";
        break;
    case buddy::File::KeyNotFound:
    case buddy::File::KeyIdAmbiguous:
    case buddy::File::KeyCannotSign:
    case buddy::File::VerificationFailed:
    case buddy::File::DuplicateSignature:
    case buddy::File::OperationNotYetSupported:
        qDebug() << "Error: (unknown error)";
    }

    return 1;
}

void printUsage()
{
    qDebug() << "buddy [-s|--sign] [file] [key]         Add a signature to a file";
    qDebug() << "buddy [-c|--check] [file]              List signatures in a file and verify integrity";
    qDebug() << "buddy [-r|--remove] [file] [key]       Remove a signature from a file with specified key";
    qDebug() << "buddy --clear-all-signatures [file]    Remove all signatures from a file";
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QStringList args = a.arguments();
    if (args.count() < 2)
    {
        printUsage();
        return 1;
    }

    QHash<QString, int(*)(const QStringList&)> functions
    {
        {"--sign",   sign},
        {"-s",       sign},
        {"--check",  check},
        {"-c",       check},
        {"--remove", remove},
        {"-r",       remove},
        {"--clear-all-signatures", clearAllSignatures},
    };

    if (!functions.contains(args[1]))
    {
        printUsage();
        return 1;
    }

    return functions[args[1]](args.mid(2));
}
