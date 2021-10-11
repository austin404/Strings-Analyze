#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QThread>
#include <QVector>
#include "config.h"
#include <QMutex>

class MyThread : public QThread
{
    Q_OBJECT
public:
    explicit MyThread(QObject *parent = nullptr);
    MyThread(QObject *parent, QStringList &l, qsizetype s, qsizetype e, QVector<PatternData> &pdL) : QThread{parent}, lines{l}, startIndex{s}, endIndex{e}, pdList{pdL}
    {
    }
    void run();

private:
    QStringList lines;
    bool isEmitting = false;
    qsizetype startIndex;
    qsizetype endIndex;
    QVector<PatternData> pdList;
    QMutex mutex;
    void doEmit(QVector<PatternData>);
signals:
    void emitProgress();
    void emitComplete(QVector<PatternData>);
};

#endif // MYTHREAD_H
