#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDebug>
#include <QFileDialog>
#include <QFileInfo>
#include <QFileInfoList>
#include <QFile>
#include <QDir>
#include <QVector>
#include <QMessageBox>
#include <QMimeDatabase>
#include <iostream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Strings Analyze");
    initComponents();
    readPatterns();
}

void MainWindow::initComponents()
{
    // Progress Bar
    ui->progressBar->setValue(0);

    // Table Widget
    ui->tableWidget->setEditTriggers(QTableWidget ::NoEditTriggers);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView ::Stretch);
    ui->tableWidget->setSortingEnabled(true);
}

// Nothing fancy here
// File Dialog
void MainWindow ::FileDialog()
{
    QString filename = QFileDialog ::getOpenFileName(
        this,
        "Select strings dump file",
        QDir ::homePath(),
        "All files (*.*)");

    if (!filename.isNull())
    {
        searchPatterns(filename);
    }
    else
    {
        exit(1);
    }
}

// This guy over here read patterns from strings-analyze-patterns folder
void MainWindow ::readPatterns()
{
    QDir dir = QDir();

    if (dir.exists("strings-analyze-patterns/Patterns/"))
    {
        recursiveFileOpen(dir.currentPath() + "/strings-analyze-patterns/Patterns");
    }
    else
    {
        QMessageBox msg;
        msg.setWindowTitle("Patter Folder not found");
        msg.setText("<b>strings-analyze-patterns folder was not found<b>");
        msg.setTextFormat(Qt::TextFormat::RichText);
        msg.setInformativeText("Download the repo from<br> <a href='https://github.com/UnrealSecurity/strings-analyze-patterns'> https://github.com/UnrealSecurity/strings-analyze-patterns</a> and place it in the same directory as executable\
    <br>Current Directory:<br><small><i>" +
                               dir.currentPath() + "</i></small>");
        msg.setDetailedText("If \"strings-analyze-patterns\" folder is already present then try running the binary from same folder");
        msg.setIcon(QMessageBox ::Critical);
        msg.exec();
        exit(1);
    }
}

void MainWindow ::recursiveFileOpen(QString path)
{
    QDir dir = QDir(path);
    QFileInfoList fileList = dir.entryInfoList(QDir ::Filter ::NoDotAndDotDot | QDir::Filter ::AllEntries);
    for (QFileInfo &f : fileList)
    {
        if (f.isDir())
            recursiveFileOpen(f.absoluteFilePath());
        else if (f.isFile())
        {
            QVector<PatternData> pd_list = parsePattern(f.absoluteFilePath());
            this->pattern_data.append(pd_list);
        }
        else
        {
            // Why do you even exist ?
        }
    }
}

void MainWindow::noPatternFoundMsg()
{
    QMessageBox msg;
    msg.setWindowTitle("No Patterns Found");
    msg.setText("<b>No Patterns Found");
    msg.setTextFormat(Qt::TextFormat::RichText);
    msg.setIcon(QMessageBox ::Information);
    msg.exec();
}

// UwU pattern Parser
QVector<MainWindow::PatternData> MainWindow ::parsePattern(QString path)
{

    QVector<PatternData> pd_list;

    QFile f(path);
    f.open(QIODevice::ReadOnly);
    while (!f.atEnd())
    {

        bool is_quote = false;

        QString line = f.readLine().trimmed();
        QString temp = "";

        if (!line.isEmpty() && line.at(0) != '#')
        {
            QVector<QString> temp_list;
            for (unsigned int i = 0; i < line.size(); ++i)
            {
                if (!is_quote)
                {
                    if (line.at(i) == '"')
                        is_quote = true;
                    else
                    {
                        bool inside = false; // This is so that it doesn't add empty spaces
                        while (i < line.size() && line.at(i) != ' ')
                        {
                            inside = true;
                            temp += line.at(i);
                            ++i;
                        }
                        if (inside)
                            temp_list.push_back(temp);
                        temp = "";
                    }
                }
                else if (is_quote)
                {
                    while (true)
                    {
                        if (i >= line.size())
                            break;
                        if (line.at(i) != '"')
                            temp += line.at(i);
                        else if (line.at(i) == '"' && line.at(i - 1) == '\\' && line.at(i - 2) != '\\')
                        {
                            temp += line.at(i);
                        }
                        else if (line.at(i) == '"' && line.at(i - 1) == '\\' && line.at(i - 2) == '\\' && line.at(i - 3) == '\\')
                            temp += line.at(i);
                        else
                            break;
                        ++i;
                    }
                    temp_list.push_back(temp.trimmed());
                    temp = "";
                    is_quote = false;
                }
            }

            struct PatternData pd;

            if (temp_list.size() >= 4)
            {
                pd.code = temp_list.at(0).toInt();
                pd.type = temp_list.at(1);
                pd.description = temp_list.at(2);
                QRegExp reg;
                reg.setPattern(temp_list.at(3));
                pd.pattern = reg;
            }

            if (temp_list.size() == 5)
                pd.flags = temp_list.at(4);

            pd_list.push_back(pd);
            temp_list.clear();
        }
    }

    f.close();

    return pd_list;
}

// Adding data to table
void MainWindow::addDataToTable(PatternData pd)
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());

    QPair<QString, QBrush> pair = getType(pd.code); // This gets the keyword for the code and the corresponding color

    bool is_bold = pd.code == 1; // This is for bold text for "Interesting"

    addRowData(pair.first, pair.second, 0, is_bold);
    addRowData(QString::number(pd.line_number), pair.second, 1, is_bold);
    addRowData(pd.type, pair.second, 2, is_bold);
    addRowData(pd.description, pair.second, 3, is_bold);
    addRowData(pd.matched_string, pair.second, 4, is_bold);
}

// Adding data to a single row
void MainWindow ::addRowData(QString text, QBrush color, int col, bool is_bold)
{
    QTableWidgetItem *ti = new QTableWidgetItem();

    ti->setForeground(color);
    ti->setText(text);

    // Set Bold if necessary
    if (is_bold)
    {
        QFont font;
        font.setBold(true);
        ti->setFont(font);
    }

    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, col, ti);
}

// Set the keyword and color
QPair<QString, QBrush> MainWindow::getType(int code)
{
    QPair<QString, QBrush> pair;
    switch (code)
    {
    case 1:
        pair.first = "Interesting";
        pair.second = Qt::black;
        break;
    case 2:
        pair.first = "Miscellaneous";
        pair.second = Qt::darkBlue;
        break;
    case 3:
        pair.first = "Warning";
        pair.second = Qt::red;
        break;
    case 4:
        pair.first = "Suspicous";
        pair.second = Qt::darkYellow;
        break;
    default:
        pair.first = "Informative";
        pair.second = Qt::black;
    }
    return pair;
}

// Searching UwU patterns
void MainWindow::searchPatterns(QString path)
{
    QFile f(path);
    f.open(QIODevice::ReadOnly);
    QString mimeType = QMimeDatabase().mimeTypeForFile(path).name();

    QVector<QString> lines;

    while (!f.atEnd())
    {
        lines.push_back(f.readLine().trimmed().replace('\u0000', ""));
    }

    // For progress bar
    qsizetype total_lines = lines.size();
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(total_lines != 0 ? total_lines : 100);

    if (total_lines == 0)
        ui->progressBar->setValue(100);

    qsizetype i = 1;

    QVector<PatternData> matched_pattern;

    for (QString &line : lines)
    {
        for (PatternData &pd : pattern_data)
        {
            if (pd.flags.contains('i'))
                pd.pattern.setCaseSensitivity(Qt::CaseInsensitive);
            if (pd.pattern.indexIn(line) != -1)
            {
                if (pd.flags.contains('f'))
                    pd.matched_string = mimeType == "text/plain" ? line : removeNonPritables(line);
                else
                    pd.matched_string = pd.pattern.cap(0);
                pd.line_number = i;
                matched_pattern.push_back(pd);
            }
        }

        ui->progressBar->setValue(i);   // Increasing the progress bar
        QApplication ::processEvents(); // This is so that the screen doesn't freeze
        ++i;
    }

    if(matched_pattern.size() == 0)
        noPatternFoundMsg();


    for (PatternData &pd : matched_pattern)
    {
        addDataToTable(pd);
    }

    ui->tableWidget->resizeRowsToContents(); // For Word Wrap
    f.close();
}

QString MainWindow::removeNonPritables(QString str)
{

    QString temp;
    for (QChar &s : str)
    {
        if (s >= QChar(32) && s <= QChar(32 + 95))
            temp.push_back(s);
    }
    return temp.trimmed();
}

// Resizing progress bar and table when the MainWindow resizes
void MainWindow ::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    ui->progressBar->setGeometry(0, 0, width(), 10);
    ui->tableWidget->setGeometry(0, 10, width(), height() - 31);
}

MainWindow::~MainWindow()
{
    delete ui;
}
