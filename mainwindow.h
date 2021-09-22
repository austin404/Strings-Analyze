#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QRegExp>
#include <QThread>
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

    void resizeEvent(QResizeEvent *);
    void initComponents();
    void readPatterns();
    QVector<PatternData> parsePattern(QString path);
    void addDataToTable(PatternData);
    void addRowData(QString text, QBrush color, int col, bool isBold = false);
    QPair<QString, QBrush> getType(int code);
    void searchPatterns(QString path);
    QString removeNonPritables(QString str);
};

#endif // MAINWINDOW_H
