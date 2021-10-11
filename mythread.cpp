#include "mythread.h"
#include <QRegularExpressionMatch>
MyThread::MyThread(QObject *parent) : QThread(parent)
{
}

void MyThread::run()
{

    QVector<PatternData> matchedList;

    for (qsizetype i = startIndex; i <= endIndex; ++i)
    {

        for (PatternData pd : pdList)
        {

            QString matchLine = this->lines.at(i).size() > 1200 ? this->lines.at(i).left(1200) : this->lines.at(i);

            QRegularExpressionMatch match = pd.pattern.match(matchLine);
            if (match.hasMatch())
            {

                if (pd.flags.contains('f'))
                    pd.matched_string = this->lines.at(i);
                else
                    pd.matched_string = match.captured(0);
                pd.line_number = i + 1;
                matchedList.push_back(pd);
            }
        }

        emit emitProgress();
    }
    mutex.lock();
    emit emitComplete(matchedList);
    mutex.unlock();
}
