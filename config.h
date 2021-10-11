#ifndef CONFIG_H
#define CONFIG_H
#include <QString>
#include <QRegularExpression>

struct PatternData
{
    int code;
    QString type;
    QString description;
    QRegularExpression pattern;
    QString patternString;
    QString flags;
    qsizetype line_number;
    QString matched_string;
};

#endif // CONFIG_H
