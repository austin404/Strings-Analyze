#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProgressBar>
#include "config.h"
#include "mythread.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    void FileDialog();
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QVector<PatternData> pattern_data;
    QStringList lines;
    QVector<PatternData> matchedPattern;
    qsizetype lineFinished;
    QString mimeType;
    int numberOfthreads = 4;
    QVector<MyThread *> threads;
    bool noPatterns = false;
    bool patternsPrinted = false;

    void resizeEvent(QResizeEvent *);
    QString removeNonPritables(QString str);
    QVector<PatternData> parsePattern(QString path);
    QPair<QString, QBrush> getType(int code);
    void initComponents();
    void readPatterns();
    void addDataToTable(PatternData);
    void addRowData(QString text, QBrush color, int col, bool isBold = false);
    void addRowData(int text, QBrush color, int col, bool isBold = false);
    void searchPatterns(QString path);
    void recursiveFileOpen(QString path);
    void noPatternFoundMsg();
    void threadParsePattern(qsizetype start, qsizetype end);

private slots:
    void onProgress();
    void onComplete(QVector<PatternData>);
};

#endif // MAINWINDOW_H
