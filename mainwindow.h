#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QRegExp>
#include <QProgressBar>

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
    struct PatternData
    {
        int code;
        QString type;
        QString description;
        QRegExp pattern;
        QString flags;
        qsizetype line_number;
        QString matched_string;
    };

    QVector<PatternData> pattern_data;
    QString removeNonPritables(QString str);
    QVector<PatternData> parsePattern(QString path);
    QPair<QString, QBrush> getType(int code);

    void resizeEvent(QResizeEvent *);
    void initComponents();
    void readPatterns();
    void addDataToTable(PatternData);
    void addRowData(QString text, QBrush color, int col, bool isBold = false);
    void searchPatterns(QString path);
    void recursiveFileOpen(QString path);
    void noPatternFoundMsg();
};

#endif // MAINWINDOW_H
